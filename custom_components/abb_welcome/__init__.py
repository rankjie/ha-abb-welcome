"""ABB Welcome integration — LAN door unlock + cloud event history via SIP."""

import asyncio
import base64
import binascii
import json
import logging
import re
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests
import voluptuous as vol
from homeassistant.components.tts import generate_media_source_id
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.selector import MediaSelector
from homeassistant.helpers.start import async_at_start

from .const import (
    CONF_ALLOW_PICKUP,
    CONF_DEFAULT_UNLOCK_STATION_ID,
    CONF_LAN_RTSP_HOST,
    CONF_LAN_RTSP_PORT,
    CONF_RECORD_RING_CLIPS,
    CONF_RING_CLIP_CONTINUE_AFTER_HANGUP,
    CONF_RING_CLIP_DIR,
    CONF_TALKBACK_OUTPUT_GAIN_DB,
    CONF_UNLOCK_STRATEGY,
    DEFAULT_ALLOW_PICKUP,
    DEFAULT_LAN_RTSP_BIND_HOST,
    DEFAULT_LAN_RTSP_PORT,
    DEFAULT_LAN_RTSP_PORT_PICK_ATTEMPTS,
    DEFAULT_RECORD_RING_CLIPS,
    DEFAULT_RING_CLIP_CONTINUE_AFTER_HANGUP,
    DEFAULT_RING_CLIP_DIR,
    DOMAIN,
    EVENT_DISCOVERY_CHANGED,
    GATEWAY_PROFILE_APP_MANAGED,
    GO2RTC_RTSP_HOST,
    GO2RTC_RTSP_PORT,
    MAX_RING_CLIP_SECONDS,
    MIN_RING_CLIP_SECONDS,
    SIP_PORT_TLS,
    TOPOLOGY_REFRESH_ACTION_ERROR,
    TOPOLOGY_REFRESH_ACTION_REFRESH,
    TOPOLOGY_REFRESH_ACTION_SKIP,
    gateway_capabilities,
    gateway_profile,
    normalized_unlock_routing,
    ring_clip_seconds,
    topology_refresh_action,
    topology_refresh_error,
)
from .coordinator import ABBWelcomeCoordinator
from .redaction import get_redacting_logger
from .ring_clip import RingClipResult, RingClipWriter
from .rtsp_proxy import RtspTcpProxy
from .sip_client import SIPClient
from .sip_listener import IncomingCall, SipListener
from .streaming_state import (
    ARM_REASON_MANUAL,
    ARM_REASON_RING,
    MANUAL_ARM_SECONDS,
    RING_ARM_SECONDS,
    arm,
    disarm,
    is_pickup_allowed,
    set_pickup_allowed,
)
from .talkback_audio import async_prepare_talkback_audio
from .text import decode_gateway_text, repair_utf8_mojibake

_LOGGER = get_redacting_logger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _header_value(headers: dict, name: str) -> str:
    """Return a SIP header value from a case-insensitive mapping."""
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() != wanted:
            continue
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)
    return ""


def _station_id_from_sip_value(value: str) -> str:
    """Extract the SIP user/station id from a URI-bearing header value."""
    match = _SIP_URI_USER_RE.search(value or "")
    return match.group(1).strip() if match else ""


def _configured_hass_lan_host(hass: HomeAssistant) -> str:
    """Return an HA URL host that LAN clients can use, if one is configured."""
    for attr in ("internal_url", "external_url"):
        raw = getattr(hass.config, attr, None)
        host = urlparse(raw).hostname if raw else ""
        if host and host not in ("0.0.0.0", "::", "localhost", "127.0.0.1"):
            return host
    api = getattr(hass.config, "api", None)
    host = getattr(api, "host", None)
    if host and host not in ("0.0.0.0", "::", "localhost", "127.0.0.1"):
        return str(host)
    return ""


def _local_ip_for_peer(peer_host: str) -> str:
    """Infer the local source address HA uses to reach the ABB gateway."""
    if not peer_host:
        return ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((peer_host, 80))
        host = str(sock.getsockname()[0])
        if host and host not in ("0.0.0.0", "127.0.0.1"):
            return host
    except OSError:
        return ""
    finally:
        sock.close()
    return ""


def _coerce_lan_rtsp_port(value: object) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1024 <= port <= 65535 else None


def _candidate_lan_rtsp_ports(configured_port: int | None) -> list[int]:
    ports: list[int] = []
    if configured_port is not None:
        ports.append(configured_port)
    for port in range(
        DEFAULT_LAN_RTSP_PORT,
        min(
            65535,
            DEFAULT_LAN_RTSP_PORT + DEFAULT_LAN_RTSP_PORT_PICK_ATTEMPTS - 1,
        )
        + 1,
    ):
        if port not in ports:
            ports.append(port)
    return ports


for _name in (
    "custom_components.abb_welcome",
    "custom_components.abb_welcome.portal",
    "custom_components.abb_welcome.config_flow",
    "custom_components.abb_welcome.coordinator",
    "custom_components.abb_welcome.sip_client",
    "custom_components.abb_welcome.sip_listener",
    "custom_components.abb_welcome.button",
    "custom_components.abb_welcome.binary_sensor",
    "custom_components.abb_welcome.camera",
    "custom_components.abb_welcome.intercom_dialer",
    "custom_components.abb_welcome.media_pipeline",
    "custom_components.abb_welcome.rtsp_proxy",
    "custom_components.abb_welcome.rtsp_server",
    "custom_components.abb_welcome.streaming_state",
    "custom_components.abb_welcome.switch",
    "custom_components.abb_welcome.image",
    "custom_components.abb_welcome.event",
    "custom_components.abb_welcome.sensor",
):
    logging.getLogger(_name).setLevel(logging.INFO)

PLATFORMS = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.CAMERA,
    Platform.IMAGE,
    Platform.EVENT,
    Platform.SENSOR,
    Platform.SWITCH,
]

_RELOAD_OPTION_KEYS = (
    CONF_DEFAULT_UNLOCK_STATION_ID,
    CONF_LAN_RTSP_HOST,
    CONF_LAN_RTSP_PORT,
    CONF_TALKBACK_OUTPUT_GAIN_DB,
    CONF_UNLOCK_STRATEGY,
)

POLL_INTERVAL = timedelta(seconds=30)
PRESERVED_DOOR_METADATA_KEYS = ("type", "can_unlock")
_CAMERA_COUNT_MESSAGE_RE = re.compile(r"(?:^|[\s;,])c:(\d+)(?:$|[\s;,])")
_SIP_URI_USER_RE = re.compile(r"sip:([^@;>]+)")

# Bus event fired on every incoming SIP INVITE.  Carries the caller URI,
# extracted user portion (typically the outdoor station id), and call_id.
EVENT_RING = f"{DOMAIN}_ring"

# Bus event fired for every SIP frame the listener sends or receives.
# Useful for protocol investigation / debugging — subscribe in an
# automation or via the Developer Tools "Events" listener.
EVENT_SIP_FRAME = f"{DOMAIN}_sip_frame"

# Bus event fired whenever the SIP listener transitions state
# (stopped/connecting/registered/disconnected).
EVENT_LISTENER_STATE = f"{DOMAIN}_listener_state"

# Bus event fired once per native ring-clip capture attempt (automatic ring
# capture or the record_clip service), after the mp4 remux finishes.
EVENT_RING_CLIP = f"{DOMAIN}_ring_clip"

# Mandatory settle time before re-dialing for a continuation segment.
# Measured live: immediate re-dials return zero video and get BYE'd.
_RING_CLIP_REDIAL_DELAY_S = 2.5


def _fire_discovery_changed(
    hass: HomeAssistant,
    entry: ConfigEntry,
    *,
    reason: str,
    **extra: object,
) -> None:
    """Notify external bridges that ABB entity discovery should be refreshed."""
    payload = {
        "entry_id": entry.entry_id,
        "reason": reason,
        "gateway_ip": entry.data.get("gateway_ip", ""),
        "door_count": len(entry.data.get("doors", []) or []),
        **extra,
    }
    hass.bus.async_fire(EVENT_DISCOVERY_CHANGED, payload)


def _build_client(entry: ConfigEntry) -> SIPClient:
    strategy, default_station_id = normalized_unlock_routing(entry.data, entry.options)
    requested_strategy = entry.options.get(
        CONF_UNLOCK_STRATEGY,
        gateway_capabilities(entry.data).default_unlock_strategy,
    )
    if strategy != requested_strategy:
        _LOGGER.warning(
            "[abb] unsafe unlock strategy normalized to %s for this gateway profile",
            strategy,
        )
    is_app_managed = gateway_profile(entry.data) == GATEWAY_PROFILE_APP_MANAGED
    return SIPClient(
        host=entry.data["gateway_ip"],
        username=entry.data["sip_username"],
        password=entry.data["sip_password"],
        domain=entry.data["sip_domain"],
        doors=entry.data.get("doors", []),
        unlock_strategy=strategy,
        default_unlock_station_id=default_station_id,
        legacy_first_door_hybrid=not is_app_managed,
    )


def _reload_relevant_options(entry: ConfigEntry) -> dict[str, object]:
    return {key: entry.options.get(key) for key in _RELOAD_OPTION_KEYS}


async def _async_start_rtsp_proxy(
    hass: HomeAssistant,
    entry: ConfigEntry,
    entry_data: dict,
) -> RtspTcpProxy:
    """Start the LAN RTSP proxy, changing and persisting the port if needed."""
    configured_port = _coerce_lan_rtsp_port(entry.options.get(CONF_LAN_RTSP_PORT))
    candidate_ports = _candidate_lan_rtsp_ports(configured_port)

    last_proxy: RtspTcpProxy | None = None
    for port in candidate_ports:
        proxy = RtspTcpProxy(
            bind_host=DEFAULT_LAN_RTSP_BIND_HOST,
            bind_port=port,
            target_host=GO2RTC_RTSP_HOST,
            target_port=GO2RTC_RTSP_PORT,
        )
        last_proxy = proxy
        if not await proxy.start():
            await proxy.stop()
            continue

        entry_data["rtsp_proxy"] = proxy
        entry_data["lan_rtsp_port"] = port
        entry_data["lan_rtsp_proxy_running"] = True
        entry_data["lan_rtsp_port_changed"] = port != configured_port
        if port != configured_port:
            hass.config_entries.async_update_entry(
                entry,
                options={
                    **dict(entry.options),
                    CONF_LAN_RTSP_PORT: port,
                },
            )
            _LOGGER.info(
                "[abb] selected LAN RTSP proxy port %d and persisted it in "
                "options (previous=%s)",
                port,
                configured_port if configured_port is not None else "unset",
            )
        return proxy

    proxy = last_proxy or RtspTcpProxy(
        bind_host=DEFAULT_LAN_RTSP_BIND_HOST,
        bind_port=configured_port or DEFAULT_LAN_RTSP_PORT,
        target_host=GO2RTC_RTSP_HOST,
        target_port=GO2RTC_RTSP_PORT,
    )
    entry_data["rtsp_proxy"] = proxy
    entry_data["lan_rtsp_port"] = proxy.bind_port
    entry_data["lan_rtsp_proxy_running"] = False
    entry_data["lan_rtsp_port_changed"] = False
    port_detail = (f"{configured_port}, " if configured_port is not None else "") + (
        f"{DEFAULT_LAN_RTSP_PORT}-"
        f"{DEFAULT_LAN_RTSP_PORT + DEFAULT_LAN_RTSP_PORT_PICK_ATTEMPTS - 1}"
    )
    _LOGGER.error(
        "[abb] LAN RTSP proxy could not bind any candidate port (%s); "
        "Scrypted/HomeKit streaming will be unavailable until a free port is "
        "configured in ABB Welcome options. Last error: %s",
        port_detail,
        proxy.last_error or "unknown",
    )
    return proxy


async def _wait_for_first(timeout: float, *events: asyncio.Event) -> None:
    """Return as soon as ``timeout`` elapses or any event is set."""
    waiters = [asyncio.ensure_future(event.wait()) for event in events]
    try:
        await asyncio.wait(
            waiters, timeout=max(0.0, timeout), return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        for waiter in waiters:
            if not waiter.done():
                waiter.cancel()


async def _record_ring_segment(
    coordinator,
    writer: RingClipWriter,
    *,
    max_seconds: float,
    stop_events: tuple[asyncio.Event, ...],
) -> bool:
    """Record one segment onto ``writer``; return whether the call ended."""
    call_ended = asyncio.Event()

    def _on_call_ended(_call_id: str, _reason: str) -> None:
        call_ended.set()

    coordinator.add_packet_sink(writer)
    coordinator.add_call_ended_callback(_on_call_ended)
    try:
        await coordinator.async_open_for_ring()
        await _wait_for_first(max_seconds, call_ended, *stop_events)
    finally:
        coordinator.remove_call_ended_callback(_on_call_ended)
        coordinator.remove_packet_sink(writer)
    return call_ended.is_set()


def _ring_clip_public_url(hass: HomeAssistant, target_dir: Path, filename: str) -> str:
    """Return the /local/ URL for a file under HA's www directory, else ''."""
    try:
        relative = target_dir.resolve().relative_to(Path(hass.config.path("www")).resolve())
    except (OSError, ValueError):
        return ""
    suffix = "/".join(relative.parts)
    return f"/local/{suffix}/{filename}" if suffix else f"/local/{filename}"


def _ring_clip_event_payload(
    hass: HomeAssistant,
    station_id: str,
    reason: str,
    result,
    target_dir: Path,
) -> dict[str, object]:
    filename = result.output_path.name
    started_at = (
        datetime.fromtimestamp(result.started_at, tz=timezone.utc).isoformat()
        if result.started_at is not None
        else None
    )
    return {
        "station_id": station_id,
        "filename": filename,
        "path": str(result.output_path),
        "url": _ring_clip_public_url(hass, target_dir, filename),
        "duration_s": round(result.duration_s, 3),
        "frames": result.frames,
        "segments": result.segments,
        "started_at": started_at,
        "reason": reason,
        "ok": result.ok,
    }


async def _capture_ring_clip(
    hass: HomeAssistant,
    entry: ConfigEntry,
    station_id: str,
    *,
    reason: str = "ring",
    duration: float | None = None,
    filename: str | None = None,
) -> None:
    """Capture the ring-moment video natively and remux it to mp4.

    Must only ever run as a background task, never awaited inline from the
    SIP listener's read loop: opening a pending incoming call waits for
    that same loop to process the caller's ACK, so an inline await here
    would deadlock the listener.
    """
    # Deferred import: __init__.py otherwise never needs camera.py's
    # (heavier, go2rtc/WebRTC-dependent) module at import time — this
    # only runs after camera.py's platform setup has already completed.
    from .camera import _safe_key

    entry_data = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if entry_data is None:
        return

    # A visitor pressing the button twice in quick succession fires two
    # independent _on_ring calls against the same station; without this
    # guard both would race a capture against the station's single call.
    in_flight: set[str] = entry_data.setdefault("ring_clip_in_flight_stations", set())
    if station_id in in_flight:
        if reason == "service":
            raise HomeAssistantError(
                f"A ring clip capture is already running for station "
                f"{station_id!r}; wait for it to finish before retrying"
            )
        _LOGGER.info(
            "[abb] ring clip already capturing for station %s, ignoring re-ring",
            station_id,
        )
        return
    in_flight.add(station_id)
    try:
        coordinator = entry_data.get("stream_coordinators", {}).get(
            (_safe_key(station_id), 0)
        )
        if coordinator is None:
            raise HomeAssistantError(
                f"No ABB Welcome stream coordinator for station {station_id!r}"
            )

        seconds = (
            duration if duration is not None else ring_clip_seconds(entry.options)
        )
        target_dir = Path(
            hass.config.path(
                str(entry.options.get(CONF_RING_CLIP_DIR, "") or DEFAULT_RING_CLIP_DIR)
            )
        )
        base_name = filename or (
            # Intentionally local wall-clock time, matching the documented
            # abb_ringclip_<YYYYmmdd_HHMMSS local>_<station_id> filename scheme.
            f"abb_ringclip_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{station_id}"  # noqa: DTZ005
        )

        try:
            writer = RingClipWriter(hass, target_dir, base_name)
        except (PermissionError, OSError) as err:
            raise HomeAssistantError(
                f"Could not open ring clip capture file in {target_dir}: {err}"
            ) from err

        # A single unload Event, owned and set exactly once by
        # async_setup_entry, is shared by every capture against this
        # entry. The defensive fallback only matters if this ever runs
        # before that event is stored (should not happen in practice).
        unload_event = entry_data.get("ring_clip_unload_event")
        if unload_event is None:
            unload_event = asyncio.Event()

        extra_segments: list[RingClipWriter] = []
        try:
            call_ended = await _record_ring_segment(
                coordinator, writer, max_seconds=seconds, stop_events=(unload_event,)
            )

            continue_after_hangup = bool(
                entry.options.get(
                    CONF_RING_CLIP_CONTINUE_AFTER_HANGUP,
                    DEFAULT_RING_CLIP_CONTINUE_AFTER_HANGUP,
                )
            )
            if (
                reason == "ring"
                and continue_after_hangup
                and call_ended
                and not unload_event.is_set()
                and writer.elapsed_s < seconds
            ):
                remaining = seconds - writer.elapsed_s
                await asyncio.sleep(_RING_CLIP_REDIAL_DELAY_S)
                if not unload_event.is_set():
                    # Same clock as RingClipWriter.first_wall_time (wall
                    # time, not monotonic) — first_wall_time also anchors
                    # the fired event's started_at, so it cannot switch
                    # clocks without corrupting that timestamp too.
                    wait_started = time.time()
                    try:
                        writer2 = RingClipWriter(
                            hass, target_dir, f"{base_name}.part2"
                        )
                    except (PermissionError, OSError) as err:
                        _LOGGER.error(
                            "[abb] ring clip: could not open continuation segment "
                            "for station=%s: %s",
                            station_id,
                            err,
                        )
                    else:
                        await _record_ring_segment(
                            coordinator,
                            writer2,
                            max_seconds=remaining,
                            stop_events=(unload_event,),
                        )
                        if writer2.first_wall_time is not None:
                            _LOGGER.info(
                                "[abb] ring clip: continuation wait->first-frame "
                                "delta=%.3fs station=%s",
                                writer2.first_wall_time - wait_started,
                                station_id,
                            )
                        extra_segments.append(writer2)
        except Exception:  # the clip must still be finalized below
            _LOGGER.exception(
                "[abb] ring clip: capture failed unexpectedly station=%s",
                station_id,
            )
        finally:
            # Idempotent: on the normal path finalize() below re-closes (a
            # no-op) each writer; this only matters if something above
            # raised or the task was cancelled, so no writer is left
            # accepting packets after this point.
            writer.close()
            for segment in extra_segments:
                segment.close()

        try:
            result = await writer.finalize(extra_segments=extra_segments)
        except Exception as err:  # the event must still fire
            _LOGGER.exception(
                "[abb] ring clip: finalize failed unexpectedly station=%s",
                station_id,
            )
            result = RingClipResult(
                ok=False,
                output_path=writer.path,
                frames=writer.frames,
                nals=writer.nals,
                bytes_written=writer.bytes_written,
                duration_s=writer.elapsed_s,
                started_at=writer.first_wall_time,
                segments=1 + len(extra_segments),
                fps=0,
                error=str(err),
            )
        payload = _ring_clip_event_payload(hass, station_id, reason, result, target_dir)
        hass.bus.async_fire(EVENT_RING_CLIP, payload)
        _LOGGER.info(
            "[abb] ring clip: %s station=%s file=%s duration=%.1fs frames=%d "
            "segments=%d",
            "captured" if result.ok else "failed",
            station_id,
            payload["filename"],
            result.duration_s,
            result.frames,
            result.segments,
        )
    finally:
        in_flight.discard(station_id)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up ABB Welcome from a config entry."""
    # Repair names persisted by older versions before entities are created.
    _repair_entry_door_names(hass, entry)

    # Refresh the door topology before entities are created.  This makes a
    # normal config-entry reload pick up outdoor stations added/removed via
    # the gateway admin UI, without re-running the pairing/config flow.
    if topology_refresh_action(entry.data) == TOPOLOGY_REFRESH_ACTION_REFRESH:
        await _async_refresh_doors_for_entry(hass, entry, reload_on_change=False)

    coordinator = ABBWelcomeCoordinator(hass, entry)

    entry_data: dict = {
        "sip_client": _build_client(entry),
        "coordinator": coordinator,
    }
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = entry_data

    # One unload Event per entry, shared by every ring-clip capture that
    # runs against it (see _capture_ring_clip). Registering it here, once,
    # avoids leaking one entry.async_on_unload listener per ring capture
    # and — since ConfigEntry.async_on_unload returns None, not an
    # unsubscribe callable — avoids calling that None at capture teardown.
    ring_clip_unload_event = asyncio.Event()
    entry.async_on_unload(ring_clip_unload_event.set)
    entry_data["ring_clip_unload_event"] = ring_clip_unload_event

    set_pickup_allowed(
        hass,
        entry.entry_id,
        entry.options.get(CONF_ALLOW_PICKUP, DEFAULT_ALLOW_PICKUP),
    )

    lan_rtsp_host = str(entry.options.get(CONF_LAN_RTSP_HOST, "") or "").strip()
    if not lan_rtsp_host:
        lan_rtsp_host = _configured_hass_lan_host(hass)
    if not lan_rtsp_host:
        lan_rtsp_host = await hass.async_add_executor_job(
            _local_ip_for_peer, entry.data.get("gateway_ip", "")
        )
    if not lan_rtsp_host:
        lan_rtsp_host = "<home-assistant-lan-ip>"

    entry_data["lan_rtsp_host"] = lan_rtsp_host

    rtsp_proxy = await _async_start_rtsp_proxy(hass, entry, entry_data)

    async def _stop_rtsp_proxy(*_args) -> None:
        await rtsp_proxy.stop()

    entry.async_on_unload(_stop_rtsp_proxy)

    # Initial poll
    if coordinator.has_certs:
        await coordinator.async_request_refresh()

        # Schedule periodic polling
        async def _poll_events(_now=None):
            await coordinator.async_request_refresh()

        entry.async_on_unload(
            async_track_time_interval(hass, _poll_events, POLL_INTERVAL)
        )

    # Realtime SIP listener for ring detection.  Set up only when SIP
    # credentials are present (config entries from older flows may not have
    # them; in that case we silently skip the listener and the integration
    # still works for outbound unlocks).
    sip_user = entry.data.get("sip_username")
    sip_pass = entry.data.get("sip_password")
    sip_domain = entry.data.get("sip_domain")
    gw_ip = entry.data.get("gateway_ip")
    if sip_user and sip_pass and sip_domain and gw_ip:
        door_names = {
            str(door.get("station_id", "")).strip(): str(
                door.get("name") or door.get("station_id") or ""
            )
            for door in entry.data.get("doors", []) or []
            if str(door.get("station_id", "")).strip()
        }

        def _on_ring(call: IncomingCall) -> None:
            station_id = call.caller_user
            station = door_names.get(station_id, "")
            payload = {
                "caller_uri": call.caller_uri,
                "caller_user": call.caller_user,
                "station_id": station_id,
                "station": station,
                "station_name": station,
                "call_id": call.call_id,
                "received_at": call.received_at,
            }
            if (
                entry.options.get(CONF_RECORD_RING_CLIPS, DEFAULT_RECORD_RING_CLIPS)
                and is_pickup_allowed(hass, entry.entry_id)
            ):
                # Background task only — see _capture_ring_clip's docstring.
                # _on_ring itself stays synchronous and is never awaited by
                # _handle_invite, so this cannot deadlock the SIP read loop.
                hass.async_create_background_task(
                    _capture_ring_clip(hass, entry, station_id),
                    name=f"abb_ring_clip_{station_id or 'unknown'}",
                )
            hass.bus.async_fire(EVENT_RING, payload)
            sensor = entry_data.get("ringing_sensor")
            if sensor is not None:
                sensor.trigger_ring(payload)
            if is_pickup_allowed(hass, entry.entry_id):
                # Auto-arm streaming so the user can answer the ring within
                # the next minute (clicking the camera or accepting a HomeKit
                # doorbell notification triggers a stream straight away).
                arm(
                    hass,
                    entry.entry_id,
                    reason=ARM_REASON_RING,
                    duration=RING_ARM_SECONDS,
                    station_id=station_id,
                )
            else:
                _LOGGER.info(
                    "[abb] incoming ring from station=%s call_id=%s while "
                    "pickup is disabled; disarming streaming",
                    station_id,
                    call.call_id,
                )
                disarm(hass, entry.entry_id)

        def _on_frame(payload: dict) -> None:
            hass.bus.async_fire(EVENT_SIP_FRAME, payload)
            sensor = entry_data.get("listener_state_sensor")
            if sensor is not None:
                is_invite = (
                    payload.get("direction") == "in"
                    and payload.get("method") == "INVITE"
                )
                sensor.record_frame(payload.get("direction", ""), is_invite)

        def _on_message(frame) -> None:
            """Handle private MESSAGE content without putting it on the HA bus."""
            body = frame.body.decode("utf-8", errors="replace").strip()
            match = _CAMERA_COUNT_MESSAGE_RE.search(body)
            if match is None:
                return
            headers: dict[str, str | list[str]] = {}
            seen_case: dict[str, str] = {}
            for key, value in frame.headers:
                canonical = seen_case.setdefault(key.lower(), key)
                if canonical not in headers:
                    headers[canonical] = value
                elif isinstance(headers[canonical], list):
                    headers[canonical].append(value)
                else:
                    headers[canonical] = [headers[canonical], value]
            count = int(match.group(1))
            call_id = _header_value(headers, "Call-ID")
            from_station_id = _station_id_from_sip_value(_header_value(headers, "From"))

            # ABB Camera Interface units can send the `c:N` notification via
            # a fixed gateway/root sender (often station 100000001), not the
            # actual station being viewed.  Prefer the active/pending
            # surveillance target owned by IntercomDialer; fall back to
            # From/request URI only when there is no call context available.
            dialer = entry_data.get("intercom_dialer")
            call_target = getattr(dialer, "camera_count_target", None)
            door_handler = entry_data.get("camera_count_door_handler")
            if call_target is not None and callable(door_handler):
                target_door = call_target.door
                if call_id and call_id != call_target.call_id:
                    _LOGGER.info(
                        "[abb] sip_listener: camera count MESSAGE call_id=%s "
                        "does not match target_call_id=%s; using target "
                        "door=%s station=%s instead of sender=%s",
                        call_id,
                        call_target.call_id,
                        target_door.name,
                        target_door.station_id,
                        from_station_id or "unknown",
                    )
                _LOGGER.info(
                    "[abb] sip_listener: detected camera count=%d for target "
                    "door=%s station=%s sender=%s call_id=%s body=%r",
                    count,
                    target_door.name,
                    target_door.station_id,
                    from_station_id or "unknown",
                    call_id or "unknown",
                    body[:200],
                )
                door_handler(target_door, count, body, "sip_listener_call_target")
                return

            station_id = from_station_id
            if not station_id:
                request_uri = (
                    frame.start_line.split(" ", 2)[1] if " " in frame.start_line else ""
                )
                station_id = _station_id_from_sip_value(request_uri)
            if not station_id:
                _LOGGER.info(
                    "[abb] sip_listener: camera count MESSAGE body=%r has no "
                    "station id and no active call (from=%r request_uri=%r)",
                    body[:200],
                    _header_value(headers, "From"),
                    request_uri,
                )
                return
            handler = entry_data.get("camera_count_handler")
            if not callable(handler):
                _LOGGER.info(
                    "[abb] sip_listener: camera count=%d for station=%s but "
                    "camera handler is not ready",
                    count,
                    station_id,
                )
                return
            _LOGGER.info(
                "[abb] sip_listener: detected camera count=%d for station=%s "
                "from MESSAGE body=%r using sender fallback",
                count,
                station_id,
                body[:200],
            )
            handler(station_id, count, body, "sip_listener_sender_fallback")

        def _on_state_change(new_state: str) -> None:
            hass.bus.async_fire(
                EVENT_LISTENER_STATE,
                {"state": new_state, "at": _now_iso()},
            )
            sensor = entry_data.get("listener_state_sensor")
            if sensor is not None:
                sensor.update_state(new_state)

        listener = SipListener(
            host=gw_ip,
            username=sip_user,
            password=sip_pass,
            domain=sip_domain,
            port=SIP_PORT_TLS,
            transport="tls",
            on_ring=_on_ring,
            on_frame=_on_frame,
            on_message=_on_message,
            on_state_change=_on_state_change,
            custom_media_crypto=(
                gateway_profile(entry.data) == GATEWAY_PROFILE_APP_MANAGED
            ),
        )
        entry_data["sip_listener"] = listener

        # Defer start until HA finishes booting.  Before EVENT_HOMEASSISTANT_
        # STARTED the network stack and other integrations may not be ready,
        # which on some setups leaves the listener task starved or its first
        # connect failing in ways that show up as a stuck "stopped" state.
        # async_at_start fires immediately if HA is already running (i.e. on
        # integration reload), so the path is the same in both cases.
        @callback
        def _start_listener(_hass: HomeAssistant) -> None:
            listener.start(_hass)

        entry.async_on_unload(async_at_start(hass, _start_listener))

        async def _stop_listener(*_args) -> None:
            await listener.stop()

        entry.async_on_unload(_stop_listener)

    entry_data["reload_options"] = _reload_relevant_options(entry)
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    _fire_discovery_changed(
        hass,
        entry,
        reason=(
            "rtsp_proxy_started"
            if entry_data.get("lan_rtsp_proxy_running")
            else "rtsp_proxy_failed"
        ),
        lan_rtsp_host=entry_data.get("lan_rtsp_host", ""),
        lan_rtsp_port=entry_data.get("lan_rtsp_port"),
        lan_rtsp_proxy_running=bool(entry_data.get("lan_rtsp_proxy_running")),
        port_changed=bool(entry_data.get("lan_rtsp_port_changed")),
    )
    _async_register_services(hass)
    return True


SERVICE_EXPORT_CREDENTIALS = "export_credentials"
SERVICE_REFRESH_DOORS = "refresh_doors"
SERVICE_ARM_STREAMING = "arm_streaming"
SERVICE_TALK_START = "talk_start"
SERVICE_TALK_STOP = "talk_stop"
SERVICE_TALK_PCM16LE = "talk_pcm16le"
SERVICE_TALK_TONE = "talk_tone"
SERVICE_PLAY_AUDIO = "play_audio"
SERVICE_ANNOUNCE = "announce"
SERVICE_RECORD_CLIP = "record_clip"
EXPORT_FIELDS = (
    "gateway_ip",
    "sip_username",
    "sip_password",
    "sip_domain",
    "doors",
    "certificate_pem",
    "private_key_pem",
    "gateway_admin_password",
    "gateway_uuid",
    "abb_username",
)

_GATEWAY_ADMIN_TIMEOUT = 8
_GATEWAY_LOGIN_OK_RESPONSES = {"1", "2"}


def _fetch_gateway_device_list(gateway_ip: str, admin_password: str) -> str:
    """Read the gateway admin device-list CGI response."""
    errors: list[str] = []
    for scheme in ("http", "https"):
        base = f"{scheme}://{gateway_ip}"
        try:
            with requests.Session() as session:
                login = session.get(
                    f"{base}/cgi-bin/checklogin.cgi",
                    params={"name": "admin", "pwd": admin_password},
                    timeout=_GATEWAY_ADMIN_TIMEOUT,
                    verify=False,
                )
                body = decode_gateway_text(login.content).strip()
                if login.status_code != 200 or body not in _GATEWAY_LOGIN_OK_RESPONSES:
                    errors.append(
                        f"{scheme}: login returned HTTP {login.status_code} "
                        f"body={body!r}"
                    )
                    continue

                response = session.get(
                    f"{base}/cgi-bin/adduser.cgi",
                    params={"type": "getdevicelist"},
                    headers={"Referer": f"{base}/config.html"},
                    timeout=_GATEWAY_ADMIN_TIMEOUT,
                    verify=False,
                )
                if response.status_code != 200:
                    errors.append(
                        f"{scheme}: getdevicelist returned HTTP {response.status_code}"
                    )
                    continue
                return decode_gateway_text(response.content).strip()
        except requests.RequestException as err:
            errors.append(f"{scheme}: {err}")

    raise RuntimeError("; ".join(errors) or "gateway returned no device list")


def _parse_gateway_doors(raw: str, sip_domain: str) -> list[dict]:
    """Parse adduser.cgi?type=getdevicelist into entry.data['doors']."""
    doors: list[dict] = []
    for item in filter(None, raw.split(";")):
        parts = item.split("+")
        if len(parts) < 3 or not parts[0].startswith("outdoorstation_"):
            continue

        device_id = parts[1].strip()
        name = repair_utf8_mojibake(unquote(parts[2].strip()))
        if not device_id or not name:
            continue

        station_id = f"10000000{device_id}"
        doors.append(
            {
                "name": name,
                "address": f"sip:{station_id}@{sip_domain}",
                "station_id": station_id,
                "body": "1",
                "index": len(doors),
            }
        )
    return doors


def _fetch_doors_from_gateway(
    gateway_ip: str, admin_password: str, sip_domain: str
) -> list[dict] | None:
    """Pull the current outdoor-station list from the gateway admin CGI."""
    try:
        raw = _fetch_gateway_device_list(gateway_ip, admin_password)
    except RuntimeError as err:
        _LOGGER.error("[abb] refresh_doors: gateway HTTP error: %s", err)
        return None

    doors = _parse_gateway_doors(raw, sip_domain)
    if not doors:
        _LOGGER.warning(
            "[abb] refresh_doors: gateway returned no outdoorstation entries (raw=%r)",
            raw,
        )
        return None
    return doors


def _doors_equal(a: list[dict], b: list[dict]) -> bool:
    """Compare door lists ignoring persisted index metadata."""
    keys = ("name", "address", "station_id", "body", "type", "can_unlock")
    return [tuple(door.get(key) for key in keys) for door in a] == [
        tuple(door.get(key) for key in keys) for door in b
    ]


def _repair_entry_door_names(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Repair mojibake in door names stored by older config-flow versions."""
    current = entry.data.get("doors", []) or []
    repaired: list[dict] = []
    changed = False
    for door in current:
        name = door.get("name")
        if isinstance(name, str):
            repaired_name = repair_utf8_mojibake(name)
            if repaired_name != name:
                door = {**door, "name": repaired_name}
                changed = True
        repaired.append(door)

    if changed:
        _LOGGER.info("[abb] repaired UTF-8 mojibake in stored door names")
        hass.config_entries.async_update_entry(
            entry, data={**entry.data, "doors": repaired}
        )
    return changed


async def _async_refresh_doors_for_entry(
    hass: HomeAssistant, entry: ConfigEntry, *, reload_on_change: bool
) -> bool:
    """Refresh one config entry's stored door topology from the gateway."""
    if topology_refresh_action(entry.data) != TOPOLOGY_REFRESH_ACTION_REFRESH:
        return False
    gateway_ip = entry.data.get("gateway_ip")
    admin_password = entry.data.get("gateway_admin_password")
    sip_domain = entry.data.get("sip_domain")
    if not (gateway_ip and admin_password and sip_domain):
        _LOGGER.warning(
            "[abb] refresh_doors: entry %s missing gateway_ip, "
            "gateway_admin_password, or sip_domain; skipping",
            entry.entry_id,
        )
        return False

    new_doors = await hass.async_add_executor_job(
        _fetch_doors_from_gateway,
        gateway_ip,
        admin_password,
        sip_domain,
    )
    if new_doors is None:
        return False

    current = entry.data.get("doors", []) or []
    current_by_station = {
        str(door.get("station_id", "")).strip(): door
        for door in current
        if str(door.get("station_id", "")).strip()
    }
    for door in new_doors:
        old = current_by_station.get(str(door.get("station_id", "")).strip())
        if old is None:
            continue
        for key in PRESERVED_DOOR_METADATA_KEYS:
            if key in old and key not in door:
                door[key] = old[key]

    if _doors_equal(current, new_doors):
        _LOGGER.info(
            "[abb] refresh_doors: entry %s already up to date (%d door(s))",
            entry.entry_id,
            len(current),
        )
        return False

    _LOGGER.warning(
        "[abb] refresh_doors: entry %s — updating doors %d -> %d",
        entry.entry_id,
        len(current),
        len(new_doors),
    )
    hass.config_entries.async_update_entry(
        entry, data={**entry.data, "doors": new_doors}
    )
    _fire_discovery_changed(
        hass,
        entry,
        reason="doors_changed",
        door_count=len(new_doors),
    )
    if reload_on_change:
        await hass.config_entries.async_reload(entry.entry_id)
    return True


def _normalise_entity_ids(raw: object) -> list[str]:
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, (list, tuple, set)):
        return [str(item) for item in raw if item]
    return [str(raw)]


def _camera_sort_key(camera: object) -> tuple[int, int, int]:
    scorer = getattr(camera, "talkback_target_score", None)
    if callable(scorer):
        return scorer()
    ready = bool(getattr(camera, "talkback_ready", False))
    session = getattr(camera, "_session", None)
    active = bool(getattr(session, "active", False))
    camera_index = getattr(camera, "_camera_index", None)
    return (0 if ready else 1, 0 if active else 1, 0 if camera_index is None else 1)


def _cameras_for_talk_service(hass: HomeAssistant, call: ServiceCall) -> list[object]:
    entries = hass.data.get(DOMAIN, {})
    if not entries:
        raise HomeAssistantError("No ABB Welcome config entries are loaded")

    target_entry_id = call.data.get("entry_id")
    if target_entry_id:
        if target_entry_id not in entries:
            raise HomeAssistantError(
                f"No ABB Welcome config entry id={target_entry_id!r}"
            )
        entry_items = [(target_entry_id, entries[target_entry_id])]
    else:
        entry_items = list(entries.items())

    requested_entity_ids = _normalise_entity_ids(call.data.get("entity_id"))
    station_id = str(call.data.get("station_id") or "").strip()

    cameras: list[object] = []
    missing_entities: set[str] = set(requested_entity_ids)
    for _entry_id, entry_data in entry_items:
        by_entity = entry_data.get("camera_entities_by_entity_id", {})
        if not isinstance(by_entity, dict):
            by_entity = {}

        if requested_entity_ids:
            for entity_id in requested_entity_ids:
                camera = by_entity.get(entity_id)
                if camera is not None:
                    cameras.append(camera)
                    missing_entities.discard(entity_id)
            continue

        if station_id:
            by_station = entry_data.get("camera_entities_by_station", {})
            if isinstance(by_station, dict):
                cameras.extend(by_station.get(station_id, []))
            if not cameras:
                for camera in by_entity.values():
                    door = getattr(camera, "_door", None)
                    if str(getattr(door, "station_id", "") or "").strip() == station_id:
                        cameras.append(camera)
            continue

        cameras.extend(by_entity.values())

    if missing_entities:
        missing = ", ".join(sorted(missing_entities))
        raise HomeAssistantError(f"No loaded ABB Welcome camera entity: {missing}")

    deduped: list[object] = []
    seen: set[int] = set()
    for camera in cameras:
        marker = id(camera)
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(camera)
    if not deduped:
        raise HomeAssistantError("No ABB Welcome camera target is loaded")

    deduped.sort(key=_camera_sort_key)
    if requested_entity_ids:
        return deduped
    return [deduped[0]]


@callback
def _async_register_services(hass: HomeAssistant) -> None:
    """Register integration-wide services.

    Registration is idempotent and safe on every entry setup.
    """
    if not hass.services.has_service(DOMAIN, SERVICE_EXPORT_CREDENTIALS):

        async def _export_creds(call: ServiceCall) -> None:
            target_entry_id = call.data.get("entry_id")
            path = call.data.get("path") or "/config/abb_welcome_creds.json"

            entries = hass.data.get(DOMAIN, {})
            if not entries:
                raise ValueError("No ABB Welcome config entries are loaded")

            if target_entry_id:
                if target_entry_id not in entries:
                    raise ValueError(f"No config entry with id={target_entry_id!r}")
                entry_ids = [target_entry_id]
            else:
                entry_ids = list(entries.keys())

            payload: dict = {"exported_at": _now_iso(), "entries": []}
            for eid in entry_ids:
                entry = hass.config_entries.async_get_entry(eid)
                if entry is None:
                    continue
                data = entry.data
                payload["entries"].append(
                    {
                        "entry_id": eid,
                        "title": entry.title,
                        **{k: data.get(k) for k in EXPORT_FIELDS if k in data},
                        "options": dict(entry.options),
                    }
                )

            target = Path(path)
            await hass.async_add_executor_job(
                target.write_text, json.dumps(payload, indent=2)
            )
            _LOGGER.warning(
                "[abb] Credentials exported to %s — file contains the SIP password, "
                "private key, and gateway admin password. Treat as sensitive.",
                target,
            )

        hass.services.async_register(
            DOMAIN,
            SERVICE_EXPORT_CREDENTIALS,
            _export_creds,
            schema=vol.Schema(
                {
                    vol.Optional("entry_id"): str,
                    vol.Optional("path"): str,
                }
            ),
        )

    if not hass.services.has_service(DOMAIN, SERVICE_REFRESH_DOORS):

        async def _refresh_doors(call: ServiceCall) -> None:
            target_entry_id = call.data.get("entry_id")
            entries = hass.data.get(DOMAIN, {})
            if not entries:
                raise ValueError("No ABB Welcome config entries are loaded")

            if target_entry_id:
                if target_entry_id not in entries:
                    raise ValueError(f"No config entry with id={target_entry_id!r}")
                entry_ids = [target_entry_id]
            else:
                entry_ids = list(entries.keys())

            refresh_entries: list[ConfigEntry] = []
            skipped_entries = 0
            skipped_error = ""
            explicitly_targeted = bool(target_entry_id)
            for eid in entry_ids:
                entry = hass.config_entries.async_get_entry(eid)
                if entry is None:
                    continue
                action = topology_refresh_action(
                    entry.data, explicitly_targeted=explicitly_targeted
                )
                if action == TOPOLOGY_REFRESH_ACTION_ERROR:
                    raise HomeAssistantError(topology_refresh_error(entry.data))
                if action == TOPOLOGY_REFRESH_ACTION_SKIP:
                    skipped_entries += 1
                    skipped_error = topology_refresh_error(entry.data) or ""
                    continue
                refresh_entries.append(entry)

            if not refresh_entries and skipped_entries:
                raise HomeAssistantError(skipped_error)

            for entry in refresh_entries:
                await _async_refresh_doors_for_entry(hass, entry, reload_on_change=True)
            if skipped_entries:
                _LOGGER.warning(
                    "[abb] refresh_doors skipped %d app-managed entry or entries; "
                    "their topology requires re-pairing",
                    skipped_entries,
                )

        hass.services.async_register(
            DOMAIN,
            SERVICE_REFRESH_DOORS,
            _refresh_doors,
            schema=vol.Schema({vol.Optional("entry_id"): str}),
        )

    if not hass.services.has_service(DOMAIN, SERVICE_ARM_STREAMING):

        async def _arm_streaming(call: ServiceCall) -> None:
            target_entry_id = call.data.get("entry_id")
            station_id = str(call.data.get("station_id") or "").strip()
            duration = float(call.data.get("duration") or MANUAL_ARM_SECONDS)
            entries = hass.data.get(DOMAIN, {})
            if not entries:
                raise ValueError("No ABB Welcome config entries are loaded")
            if target_entry_id:
                if target_entry_id not in entries:
                    raise ValueError(f"No config entry with id={target_entry_id!r}")
                entry_ids = [target_entry_id]
            else:
                entry_ids = list(entries.keys())
            for eid in entry_ids:
                arm(
                    hass,
                    eid,
                    reason=ARM_REASON_MANUAL,
                    duration=duration,
                    station_id=station_id,
                )

        hass.services.async_register(
            DOMAIN,
            SERVICE_ARM_STREAMING,
            _arm_streaming,
            schema=vol.Schema(
                {
                    vol.Optional("entry_id"): str,
                    vol.Optional("station_id"): str,
                    vol.Optional("duration"): vol.All(
                        vol.Coerce(float), vol.Range(min=5, max=600)
                    ),
                }
            ),
        )

    talk_target_schema = {
        vol.Optional("entry_id"): str,
        vol.Optional("entity_id"): vol.Any(str, [str]),
        vol.Optional("station_id"): str,
        vol.Optional("talkback_session_id"): str,
        vol.Optional("session_id"): str,
    }

    if not hass.services.has_service(DOMAIN, SERVICE_TALK_START):

        async def _talk_start(call: ServiceCall) -> None:
            talkback_session_id = str(
                call.data.get("talkback_session_id")
                or call.data.get("session_id")
                or ""
            ).strip()
            for camera in _cameras_for_talk_service(hass, call):
                start = getattr(camera, "async_talkback_start", None)
                if not callable(start):
                    raise HomeAssistantError(
                        "Selected camera does not support talkback"
                    )
                stats = await start(talkback_session_id)
                _LOGGER.info(
                    "[abb] talk_start target=%s stats=%s",
                    getattr(camera, "entity_id", "unknown"),
                    stats,
                )

        hass.services.async_register(
            DOMAIN,
            SERVICE_TALK_START,
            _talk_start,
            schema=vol.Schema(talk_target_schema),
        )

    if not hass.services.has_service(DOMAIN, SERVICE_TALK_STOP):

        async def _talk_stop(call: ServiceCall) -> None:
            talkback_session_id = str(
                call.data.get("talkback_session_id")
                or call.data.get("session_id")
                or ""
            ).strip()
            for camera in _cameras_for_talk_service(hass, call):
                stop = getattr(camera, "async_talkback_stop", None)
                if not callable(stop):
                    raise HomeAssistantError(
                        "Selected camera does not support talkback"
                    )
                stats = await stop(talkback_session_id)
                _LOGGER.info(
                    "[abb] talk_stop target=%s stats=%s",
                    getattr(camera, "entity_id", "unknown"),
                    stats,
                )

        hass.services.async_register(
            DOMAIN,
            SERVICE_TALK_STOP,
            _talk_stop,
            schema=vol.Schema(talk_target_schema),
        )

    if not hass.services.has_service(DOMAIN, SERVICE_TALK_PCM16LE):

        async def _talk_pcm16le(call: ServiceCall) -> None:
            talkback_session_id = str(
                call.data.get("talkback_session_id")
                or call.data.get("session_id")
                or ""
            ).strip()
            encoded = str(call.data["pcm16le"])
            try:
                pcm = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as err:
                raise HomeAssistantError(
                    "pcm16le must be base64-encoded bytes"
                ) from err
            if len(pcm) % 2:
                raise HomeAssistantError("pcm16le must contain whole 16-bit samples")
            if len(pcm) > 160000:
                raise HomeAssistantError("pcm16le payload is too large")
            for camera in _cameras_for_talk_service(hass, call):
                feed = getattr(camera, "async_talkback_pcm16le", None)
                if not callable(feed):
                    raise HomeAssistantError(
                        "Selected camera does not support talkback"
                    )
                stats = await feed(pcm, talkback_session_id)
                # PCM is normally fed several times per second. INFO logging
                # every block can stall Home Assistant's event loop long
                # enough to disturb the 20 ms RTP talkback clock.
                _LOGGER.debug(
                    "[abb] talk_pcm16le target=%s bytes=%d stats=%s",
                    getattr(camera, "entity_id", "unknown"),
                    len(pcm),
                    stats,
                )

        hass.services.async_register(
            DOMAIN,
            SERVICE_TALK_PCM16LE,
            _talk_pcm16le,
            schema=vol.Schema(
                {
                    **talk_target_schema,
                    vol.Required("pcm16le"): str,
                }
            ),
        )

    if not hass.services.has_service(DOMAIN, SERVICE_TALK_TONE):

        async def _talk_tone(call: ServiceCall) -> None:
            talkback_session_id = str(
                call.data.get("talkback_session_id")
                or call.data.get("session_id")
                or ""
            ).strip()
            for camera in _cameras_for_talk_service(hass, call):
                tone = getattr(camera, "async_talkback_tone", None)
                if not callable(tone):
                    raise HomeAssistantError(
                        "Selected camera does not support talkback"
                    )
                stats = await tone(
                    duration_ms=call.data["duration_ms"],
                    frequency_hz=call.data["frequency_hz"],
                    amplitude=call.data["amplitude"],
                    talkback_session_id=talkback_session_id,
                )
                _LOGGER.info(
                    "[abb] talk_tone target=%s stats=%s",
                    getattr(camera, "entity_id", "unknown"),
                    stats,
                )

        hass.services.async_register(
            DOMAIN,
            SERVICE_TALK_TONE,
            _talk_tone,
            schema=vol.Schema(
                {
                    **talk_target_schema,
                    vol.Optional("duration_ms", default=1200): vol.All(
                        vol.Coerce(int), vol.Range(min=100, max=5000)
                    ),
                    vol.Optional("frequency_hz", default=880): vol.All(
                        vol.Coerce(int), vol.Range(min=100, max=3000)
                    ),
                    vol.Optional("amplitude", default=0.35): vol.All(
                        vol.Coerce(float), vol.Range(min=0.0, max=1.0)
                    ),
                }
            ),
        )

    if not hass.services.has_service(DOMAIN, SERVICE_PLAY_AUDIO):

        async def _play_audio(call: ServiceCall) -> None:
            talkback_session_id = str(
                call.data.get("talkback_session_id")
                or call.data.get("session_id")
                or ""
            ).strip()
            media = call.data["media"]
            camera = _cameras_for_talk_service(hass, call)[0]
            play = getattr(camera, "async_talkback_play_audio", None)
            if not callable(play):
                raise HomeAssistantError(
                    "Selected camera does not support talkback audio"
                )
            if not bool(getattr(camera, "talkback_ready", False)):
                raise HomeAssistantError(
                    "Talkback is not ready; open the selected camera stream first"
                )
            pcm = await async_prepare_talkback_audio(
                hass, media["media_content_id"]
            )
            try:
                await play(pcm, talkback_session_id)
            except HomeAssistantError:
                raise
            except (OSError, RuntimeError, ValueError) as err:
                raise HomeAssistantError(
                    "Unable to play audio through the selected camera"
                ) from err

        hass.services.async_register(
            DOMAIN,
            SERVICE_PLAY_AUDIO,
            _play_audio,
            schema=vol.Schema(
                {
                    **talk_target_schema,
                    vol.Required("media"): MediaSelector(
                        {"accept": ["audio/*"]}
                    ),
                }
            ),
        )

    if not hass.services.has_service(DOMAIN, SERVICE_ANNOUNCE):

        async def _announce(call: ServiceCall) -> None:
            talkback_session_id = str(
                call.data.get("talkback_session_id")
                or call.data.get("session_id")
                or ""
            ).strip()
            camera = _cameras_for_talk_service(hass, call)[0]
            announce = getattr(camera, "async_temporary_talkback_audio", None)
            if not callable(announce):
                raise HomeAssistantError(
                    "Selected camera does not support unattended announcements"
                )

            try:
                media_content_id = generate_media_source_id(
                    hass,
                    call.data["message"],
                    engine=call.data.get("tts_entity_id") or None,
                    language=call.data.get("language") or None,
                    cache=True,
                )
                pcm = await async_prepare_talkback_audio(hass, media_content_id)
            except HomeAssistantError:
                raise
            except (OSError, RuntimeError, TypeError, ValueError) as err:
                raise HomeAssistantError(
                    "Unable to prepare the unattended announcement"
                ) from err

            try:
                await announce(pcm, talkback_session_id)
            except HomeAssistantError:
                raise
            except (OSError, RuntimeError, ValueError) as err:
                raise HomeAssistantError(
                    "Unable to play the unattended announcement; the selected "
                    "station may already be in use"
                ) from err

        hass.services.async_register(
            DOMAIN,
            SERVICE_ANNOUNCE,
            _announce,
            schema=vol.Schema(
                {
                    **talk_target_schema,
                    vol.Required("message"): vol.All(
                        str,
                        lambda value: value.strip(),
                        vol.Length(min=1, max=500),
                    ),
                    vol.Optional("tts_entity_id"): str,
                    vol.Optional("language"): str,
                }
            ),
        )

    if not hass.services.has_service(DOMAIN, SERVICE_RECORD_CLIP):

        async def _record_clip(call: ServiceCall) -> None:
            camera = _cameras_for_talk_service(hass, call)[0]
            entry_id = getattr(camera, "_entry_id", None)
            door = getattr(camera, "_door", None)
            station_id = str(getattr(door, "station_id", "") or "").strip()
            target_entry = (
                hass.config_entries.async_get_entry(entry_id) if entry_id else None
            )
            if target_entry is None or not station_id:
                raise HomeAssistantError(
                    "Selected camera has no ABB Welcome station to record"
                )
            filename = str(call.data.get("filename") or "").strip() or None
            await _capture_ring_clip(
                hass,
                target_entry,
                station_id,
                reason="service",
                duration=call.data.get("duration"),
                filename=filename,
            )

        hass.services.async_register(
            DOMAIN,
            SERVICE_RECORD_CLIP,
            _record_clip,
            schema=vol.Schema(
                {
                    **talk_target_schema,
                    vol.Optional("duration"): vol.All(
                        vol.Coerce(float),
                        vol.Range(
                            min=MIN_RING_CLIP_SECONDS, max=MAX_RING_CLIP_SECONDS
                        ),
                    ),
                    vol.Optional("filename"): str,
                }
            ),
        )


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload only for options that affect connection topology."""
    entry_data = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if entry_data is not None:
        set_pickup_allowed(
            hass,
            entry.entry_id,
            entry.options.get(CONF_ALLOW_PICKUP, DEFAULT_ALLOW_PICKUP),
        )
        current_reload_options = _reload_relevant_options(entry)
        previous_reload_options = entry_data.get("reload_options")
        entry_data["reload_options"] = current_reload_options
        if previous_reload_options == current_reload_options:
            return
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload ABB Welcome config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
