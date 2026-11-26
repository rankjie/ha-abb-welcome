"""ABB Welcome integration — LAN door unlock + cloud event history via SIP."""

import base64
import binascii
import json
import logging
import re
import socket
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, urlparse

import requests
import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.event import async_call_later, async_track_time_interval
from homeassistant.helpers.service import async_register_admin_service
from homeassistant.helpers.start import async_at_start
from homeassistant.helpers.storage import Store

from .const import (
    CONF_ALLOW_PICKUP,
    CONF_CAMERA_STILL_IMAGE,
    CONF_PREVIEW_BEFORE_ANSWER,
    CONF_RING_VIDEO_SIZE,
    CONF_DEFAULT_UNLOCK_STATION_ID,
    CONF_DTMF_SECOND_LOCK_CODE,
    CONF_DTMF_UNLOCK_CODE,
    CONF_LAN_RTSP_HOST,
    CONF_LAN_RTSP_PORT,
    CONF_LAN_RTSP_PROXY,
    CONF_UNLOCK_STRATEGY,
    DEFAULT_ALLOW_PICKUP,
    DEFAULT_CAMERA_STILL_IMAGE,
    DEFAULT_PREVIEW_BEFORE_ANSWER,
    DEFAULT_RING_VIDEO_SIZE,
    DEFAULT_LAN_RTSP_BIND_HOST,
    DEFAULT_LAN_RTSP_PORT,
    DEFAULT_LAN_RTSP_PORT_PICK_ATTEMPTS,
    DEFAULT_LAN_RTSP_PROXY,
    DOMAIN,
    EVENT_DISCOVERY_CHANGED,
    GATEWAY_PROFILE_APP_MANAGED,
    GO2RTC_RTSP_HOST,
    GO2RTC_RTSP_PORT,
    SIP_PORT_TLS,
    TOPOLOGY_REFRESH_ACTION_ERROR,
    TOPOLOGY_REFRESH_ACTION_REFRESH,
    TOPOLOGY_REFRESH_ACTION_SKIP,
    gateway_capabilities,
    gateway_profile,
    normalized_unlock_routing,
    topology_refresh_action,
    topology_refresh_error,
)
from .coordinator import (
    STATION_SCREENSHOT_STORAGE_VERSION,
    ABBWelcomeCoordinator,
    station_screenshot_storage_key,
)
from .frontend import async_register_frontend, async_unregister_frontend
from .message_diagnostics import (
    DEFAULT_MESSAGE_DIAGNOSTICS_SECONDS,
    MAX_MESSAGE_DIAGNOSTICS_SECONDS,
)
from .credential_export import (
    ExportPathError,
    resolve_export_path,
    write_private_file,
)
from .portal import GatewayAdminError, _gateway_login
from .redaction import get_redacting_logger
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
    set_preview_before_answer,
)
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


# Only the package logger is pinned: the module loggers inherit from it, so
# Home Assistant's "Enable debug logging" (which raises this logger) reaches
# every module.
logging.getLogger("custom_components.abb_welcome").setLevel(logging.INFO)

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
    CONF_DTMF_SECOND_LOCK_CODE,
    CONF_DTMF_UNLOCK_CODE,
    CONF_LAN_RTSP_HOST,
    CONF_LAN_RTSP_PORT,
    CONF_LAN_RTSP_PROXY,
    CONF_UNLOCK_STRATEGY,
)

POLL_INTERVAL = timedelta(seconds=30)
PRESERVED_DOOR_METADATA_KEYS = ("type", "can_unlock", "second_lock")
_CAMERA_COUNT_MESSAGE_RE = re.compile(r"(?:^|[\s;,])c:(\d+)(?:$|[\s;,])")
_SIP_URI_USER_RE = re.compile(r"sip:([^@;>]+)")

# Bus event fired on every incoming SIP INVITE.  Carries the caller URI,
# extracted user portion (typically the outdoor station id), and call_id.
EVENT_RING = f"{DOMAIN}_ring"

# Bus event fired for every SIP frame the listener sends or receives.
# Useful for protocol investigation / debugging — subscribe in an
# automation or via the Developer Tools "Events" listener.
EVENT_SIP_FRAME = f"{DOMAIN}_sip_frame"
EVENT_SIP_MESSAGE = f"{DOMAIN}_sip_message"

# Bus event fired whenever the SIP listener transitions state
# (stopped/connecting/registered/disconnected).
EVENT_LISTENER_STATE = f"{DOMAIN}_listener_state"


def _is_level_push_message(body: str) -> bool:
    """Return whether a MESSAGE reports a press of the floor-call button.

    The official app treats a body of ``8`` (MRANGE) or a JSON ``levelpush``
    command (GlobalIP) as a floor call (LinphoneService.onMessageReceive).
    """
    if body == "8":
        return True
    if not body.startswith("{"):
        return False
    try:
        message = json.loads(body)
    except ValueError:
        return False
    return isinstance(message, dict) and message.get("cmd") == "levelpush"


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
        dtmf_unlock_code=str(entry.options.get(CONF_DTMF_UNLOCK_CODE) or ""),
        dtmf_second_lock_code=str(
            entry.options.get(CONF_DTMF_SECOND_LOCK_CODE) or ""
        ),
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


async def async_setup(hass: HomeAssistant, _config: dict) -> bool:
    """Register the history view and live command once, not per entry reload."""
    from homeassistant.components import websocket_api

    from .call_history import ABBCallHistoryView
    from .live_window import ws_live

    hass.http.register_view(ABBCallHistoryView())
    websocket_api.async_register_command(hass, ws_live)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up ABB Welcome from a config entry."""
    try:
        gateway_capabilities(entry.data)
    except ValueError:
        _LOGGER.error("[abb] refusing config entry with an unsupported gateway profile")
        return False

    # Repair names persisted by older versions before entities are created.
    _repair_entry_door_names(hass, entry)

    # Refresh the door topology before entities are created.  This makes a
    # normal config-entry reload pick up outdoor stations added/removed via
    # the gateway admin UI, without re-running the pairing/config flow.
    if topology_refresh_action(entry.data) == TOPOLOGY_REFRESH_ACTION_REFRESH:
        if await _async_refresh_doors_for_entry(hass, entry, reload_on_change=False) is None:
            _schedule_topology_retry(hass, entry)

    coordinator = ABBWelcomeCoordinator(hass, entry)
    await coordinator.async_restore_station_screenshots()

    entry_data: dict = {
        "sip_client": _build_client(entry),
        "coordinator": coordinator,
    }
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = entry_data
    set_pickup_allowed(
        hass,
        entry.entry_id,
        entry.options.get(CONF_ALLOW_PICKUP, DEFAULT_ALLOW_PICKUP),
    )
    set_preview_before_answer(
        hass,
        entry.entry_id,
        entry.options.get(CONF_PREVIEW_BEFORE_ANSWER, DEFAULT_PREVIEW_BEFORE_ANSWER),
    )
    entry_data["camera_still_image"] = entry.options.get(
        CONF_CAMERA_STILL_IMAGE, DEFAULT_CAMERA_STILL_IMAGE
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

    lan_rtsp_proxy_enabled = bool(
        entry.options.get(CONF_LAN_RTSP_PROXY, DEFAULT_LAN_RTSP_PROXY)
    )
    if lan_rtsp_proxy_enabled:
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

    entry.async_on_unload(coordinator.async_stop_ring_poll)

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
            hass.bus.async_fire(EVENT_RING, payload)
            sensor = entry_data.get("ringing_sensor")
            if sensor is not None:
                sensor.trigger_ring(payload)
            coordinator.async_schedule_ring_poll()
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

        def _on_message_diagnostic(payload: dict) -> None:
            hass.bus.async_fire(EVENT_SIP_MESSAGE, {"entry_id": entry.entry_id, **payload})

        def _on_message(frame) -> None:
            """Handle private MESSAGE content without putting it on the HA bus."""
            body = frame.body.decode("utf-8", errors="replace").strip()
            if _is_level_push_message(body):
                handler = entry_data.get("level_push_handler")
                if callable(handler):
                    handler()
                else:
                    _LOGGER.info("[abb] floor call received before its entity is ready")
                return
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
            on_message_diagnostic=_on_message_diagnostic,
            on_state_change=_on_state_change,
            custom_media_crypto=(
                gateway_profile(entry.data) == GATEWAY_PROFILE_APP_MANAGED
            ),
            ring_video_size=entry.options.get(
                CONF_RING_VIDEO_SIZE, DEFAULT_RING_VIDEO_SIZE
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
            "rtsp_proxy_disabled"
            if not lan_rtsp_proxy_enabled
            else "rtsp_proxy_started"
            if entry_data.get("lan_rtsp_proxy_running")
            else "rtsp_proxy_failed"
        ),
        lan_rtsp_host=entry_data.get("lan_rtsp_host", ""),
        lan_rtsp_port=entry_data.get("lan_rtsp_port"),
        lan_rtsp_proxy_running=bool(entry_data.get("lan_rtsp_proxy_running")),
        port_changed=bool(entry_data.get("lan_rtsp_port_changed")),
    )
    _async_register_services(hass)
    await async_register_frontend(hass, entry.entry_id)
    return True


SERVICE_EXPORT_CREDENTIALS = "export_credentials"
SERVICE_REFRESH_DOORS = "refresh_doors"
SERVICE_ARM_STREAMING = "arm_streaming"
SERVICE_TALK_START = "talk_start"
SERVICE_TALK_STOP = "talk_stop"
SERVICE_TALK_PCM16LE = "talk_pcm16le"
SERVICE_TALK_TONE = "talk_tone"
SERVICE_TALK_AUDIO_FILE = "talk_audio_file"
SERVICE_DIAGNOSE_MESSAGES = "diagnose_messages"
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
_GATEWAY_ERROR_CODE_RE = re.compile(r"-?\d+")


def _fetch_gateway_device_list(gateway_ip: str, admin_password: str) -> str:
    """Read the gateway admin device-list CGI response."""
    try:
        session = _gateway_login(gateway_ip, "admin", admin_password)
        with session:
            # Must carry the origin _gateway_login gave the gateway.
            response = session.get(
                f"https://{gateway_ip}/cgi-bin/adduser.cgi",
                params={"type": "getdevicelist"},
                headers={"Referer": f"https://{gateway_ip}/config.html"},
                timeout=_GATEWAY_ADMIN_TIMEOUT,
                verify=False,
            )
    except (GatewayAdminError, requests.RequestException) as err:
        raise RuntimeError(str(err)) from err
    if response.status_code != 200:
        raise RuntimeError(f"getdevicelist returned HTTP {response.status_code}")
    listing = decode_gateway_text(response.content).strip()
    if _GATEWAY_ERROR_CODE_RE.fullmatch(listing):
        raise RuntimeError(f"getdevicelist answered {listing}")
    return listing


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
        if len(parts) >= 4 and parts[3].strip():
            second_unlock = parts[3].strip()
            if second_unlock not in ("0", "1"):
                raise ValueError("Invalid second-lock capability in gateway device list")
            doors[-1]["second_lock"] = second_unlock == "1"
    return doors


def _parse_gateway_relays(raw: str) -> list[dict]:
    """Parse the relay actuators from adduser.cgi?type=getdevicelist."""
    relays: list[dict] = []
    for item in filter(None, raw.split(";")):
        parts = item.split("+")
        if len(parts) < 3 or not parts[0].startswith("relay_"):
            continue
        address = parts[1].strip()
        if not address.isdigit():
            raise ValueError("Invalid relay address in gateway device list")
        name = repair_utf8_mojibake(unquote(parts[2].strip())) or f"Relay {address}"
        relays.append({"name": name, "address": address})
    return relays


def _fetch_topology_from_gateway(
    gateway_ip: str, admin_password: str, sip_domain: str
) -> tuple[list[dict], list[dict]] | None:
    """Pull the outdoor stations and relays from the gateway admin CGI."""
    try:
        raw = _fetch_gateway_device_list(gateway_ip, admin_password)
    except RuntimeError as err:
        _LOGGER.error("[abb] refresh_doors: device list request failed: %s", err)
        return None

    doors = _parse_gateway_doors(raw, sip_domain)
    if not doors:
        # Item kinds are fixed type labels; the names after them are private.
        kinds = sorted({item.split("+", 1)[0].split("_", 1)[0][:32] for item in raw.split(";")})
        _LOGGER.warning(
            "[abb] device list has no outdoorstation entries "
            "(%d characters, item kinds: %s)",
            len(raw),
            ", ".join(kinds[:10]),
        )
        return None
    return doors, _parse_gateway_relays(raw)


def _doors_equal(a: list[dict], b: list[dict]) -> bool:
    """Compare door lists ignoring persisted index metadata."""
    keys = ("name", "address", "station_id", "body", "type", "can_unlock", "second_lock")
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
) -> bool | None:
    """Refresh one config entry's stored door topology from the gateway.

    Returns whether the topology changed, or None when the gateway could not
    be read; the stored topology is then left as it was.
    """
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

    topology = await hass.async_add_executor_job(
        _fetch_topology_from_gateway,
        gateway_ip,
        admin_password,
        sip_domain,
    )
    if topology is None:
        return None
    new_doors, new_relays = topology

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

    current_relays = entry.data.get("relays", []) or []
    if _doors_equal(current, new_doors) and current_relays == new_relays:
        _LOGGER.info(
            "[abb] refresh_doors: entry %s already up to date "
            "(%d door(s), %d relay(s))",
            entry.entry_id,
            len(current),
            len(current_relays),
        )
        return False

    _LOGGER.warning(
        "[abb] refresh_doors: entry %s — updating doors %d -> %d, relays %d -> %d",
        entry.entry_id,
        len(current),
        len(new_doors),
        len(current_relays),
        len(new_relays),
    )
    hass.config_entries.async_update_entry(
        entry, data={**entry.data, "doors": new_doors, "relays": new_relays}
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


# Seconds between retries of a failed startup refresh; the last one repeats.
_TOPOLOGY_RETRY_DELAYS = (60, 300, 900, 3600)


def _schedule_topology_retry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Retry the device list until the gateway answers or the entry unloads."""
    attempts = 0
    cancel = None

    def schedule() -> None:
        nonlocal cancel
        delay = _TOPOLOGY_RETRY_DELAYS[min(attempts, len(_TOPOLOGY_RETRY_DELAYS) - 1)]
        _LOGGER.warning("[abb] refresh_doors: retrying the device list in %d s", delay)
        cancel = async_call_later(hass, delay, retry)

    async def retry(_now) -> None:
        nonlocal attempts, cancel
        cancel = None
        attempts += 1
        if await _async_refresh_doors_for_entry(hass, entry, reload_on_change=True) is None:
            schedule()

    def stop() -> None:
        if cancel is not None:
            cancel()

    entry.async_on_unload(stop)
    schedule()


def _normalise_entity_ids(raw: object) -> list[str]:
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, (list, tuple, set)):
        return [str(item) for item in raw if item]
    return [str(raw)]


def _camera_sort_key(camera: object) -> tuple[int, int, int, int]:
    scorer = getattr(camera, "talkback_target_score", None)
    if callable(scorer):
        return scorer()
    ready = bool(getattr(camera, "talkback_ready", False))
    session = getattr(camera, "_session", None)
    active = bool(getattr(session, "active", False))
    pending = bool(getattr(camera, "has_pending_call", False))
    camera_index = getattr(camera, "_camera_index", None)
    return (
        0 if ready else 1,
        0 if active else 1,
        0 if pending else 1,
        0 if camera_index is None else 1,
    )


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
    if not hass.services.has_service(DOMAIN, SERVICE_DIAGNOSE_MESSAGES):

        async def _diagnose_messages(call: ServiceCall) -> None:
            entries = hass.data.get(DOMAIN, {})
            target = call.data.get("entry_id")
            if not entries:
                raise HomeAssistantError("No ABB Welcome config entries are loaded")
            if target and target not in entries:
                raise HomeAssistantError("ABB Welcome config entry is not loaded")
            selected = [entries[target]] if target else list(entries.values())
            listeners = [data.get("sip_listener") for data in selected]
            if any(listener is None for listener in listeners):
                raise HomeAssistantError("Selected ABB Welcome entry has no SIP listener")
            duration = call.data.get("duration", DEFAULT_MESSAGE_DIAGNOSTICS_SECONDS)
            for listener in listeners:
                listener.enable_message_diagnostics(duration)

        hass.services.async_register(
            DOMAIN,
            SERVICE_DIAGNOSE_MESSAGES,
            _diagnose_messages,
            schema=vol.Schema({
                vol.Optional("entry_id"): str,
                vol.Optional("duration", default=DEFAULT_MESSAGE_DIAGNOSTICS_SECONDS): vol.All(
                    vol.Coerce(int), vol.Range(min=0, max=MAX_MESSAGE_DIAGNOSTICS_SECONDS)
                ),
            }),
        )

    if not hass.services.has_service(DOMAIN, SERVICE_EXPORT_CREDENTIALS):

        async def _export_creds(call: ServiceCall) -> None:
            target_entry_id = call.data.get("entry_id")
            try:
                target = await hass.async_add_executor_job(
                    resolve_export_path, hass.config.path(), call.data.get("path")
                )
            except ExportPathError as err:
                raise HomeAssistantError(str(err)) from err

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

            await hass.async_add_executor_job(
                write_private_file, target, json.dumps(payload, indent=2)
            )
            _LOGGER.warning(
                "[abb] Credentials exported to %s — file contains the SIP password, "
                "private key, and gateway admin password. Treat as sensitive.",
                target,
            )

        # Admin only: the file contains every secret this integration holds.
        async_register_admin_service(
            hass,
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

    if not hass.services.has_service(DOMAIN, SERVICE_TALK_AUDIO_FILE):

        async def _talk_audio_file(call: ServiceCall) -> None:
            file_path = str(call.data["file_path"]).strip()
            if not hass.config.is_allowed_path(file_path):
                raise HomeAssistantError(f"Path is not allowed: {file_path}")
            talkback_session_id = str(
                call.data.get("talkback_session_id")
                or call.data.get("session_id")
                or ""
            ).strip()
            for camera in _cameras_for_talk_service(hass, call):
                talk_file = getattr(camera, "async_talkback_audio_file", None)
                if not callable(talk_file):
                    raise HomeAssistantError(
                        "Selected camera does not support talkback"
                    )
                try:
                    stats = await talk_file(
                        file_path=file_path,
                        talkback_session_id=talkback_session_id,
                    )
                except (OSError, RuntimeError, ValueError) as err:
                    raise HomeAssistantError(str(err)) from err
                _LOGGER.info(
                    "[abb] talk_audio_file target=%s stats=%s",
                    getattr(camera, "entity_id", "unknown"),
                    stats,
                )

        hass.services.async_register(
            DOMAIN,
            SERVICE_TALK_AUDIO_FILE,
            _talk_audio_file,
            schema=vol.Schema(
                {
                    **talk_target_schema,
                    vol.Required("file_path"): str,
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
        set_preview_before_answer(
            hass,
            entry.entry_id,
            entry.options.get(
                CONF_PREVIEW_BEFORE_ANSWER, DEFAULT_PREVIEW_BEFORE_ANSWER
            ),
        )
        entry_data["camera_still_image"] = entry.options.get(
            CONF_CAMERA_STILL_IMAGE, DEFAULT_CAMERA_STILL_IMAGE
        )
        listener = entry_data.get("sip_listener")
        if listener is not None:
            listener.ring_video_size = entry.options.get(
                CONF_RING_VIDEO_SIZE, DEFAULT_RING_VIDEO_SIZE
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
        await async_unregister_frontend(hass, entry.entry_id)
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Delete per-entry storage when the ABB Welcome entry is removed."""
    await Store(
        hass,
        STATION_SCREENSHOT_STORAGE_VERSION,
        station_screenshot_storage_key(entry.entry_id),
        private=True,
    ).async_remove()
