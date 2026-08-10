"""ABB Welcome integration — LAN door unlock + cloud event history via SIP."""

import base64
import binascii
import json
import logging
import re
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests
import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.start import async_at_start

from .const import (
    CONF_ALLOW_PICKUP,
    CONF_DEVICE_TYPE,
    CONF_LAN_RTSP_HOST,
    CONF_LAN_RTSP_PORT,
    CONF_UNLOCK_STRATEGY,
    DEFAULT_ALLOW_PICKUP,
    DEFAULT_LAN_RTSP_BIND_HOST,
    DEFAULT_LAN_RTSP_PORT,
    DEFAULT_LAN_RTSP_PORT_PICK_ATTEMPTS,
    DEFAULT_UNLOCK_STRATEGY,
    DEVICE_TYPE_WIFI_PANEL,
    DOMAIN,
    EVENT_DISCOVERY_CHANGED,
    GO2RTC_RTSP_HOST,
    GO2RTC_RTSP_PORT,
    SIP_PORT_TLS,
)
from .coordinator import ABBWelcomeCoordinator
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
from .text import decode_gateway_text, repair_utf8_mojibake

_LOGGER = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _header_value(headers: dict, name: str) -> str:
    """Return a SIP header value from sip_listener's JSON-safe summary."""
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
    CONF_LAN_RTSP_HOST,
    CONF_LAN_RTSP_PORT,
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
    wifi_panel = entry.data.get(CONF_DEVICE_TYPE) == DEVICE_TYPE_WIFI_PANEL
    # WiFi panels: the fast TCP MESSAGE path works (the panel processes
    # the MESSAGE and opens the door, even though it responds with an
    # INVITE instead of 200 OK).  The standard TLS invite path gets
    # 407/403 from the panel, so force fast for WiFi.
    if wifi_panel:
        unlock_strategy = "fast"
    else:
        unlock_strategy = entry.options.get(
            CONF_UNLOCK_STRATEGY, DEFAULT_UNLOCK_STRATEGY
        )
    return SIPClient(
        host=entry.data["gateway_ip"],
        username=entry.data["sip_username"],
        password=entry.data["sip_password"],
        domain=entry.data["sip_domain"],
        doors=entry.data.get("doors", []),
        unlock_strategy=unlock_strategy,
        wifi_panel=wifi_panel,
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
    port_detail = (
        f"{configured_port}, " if configured_port is not None else ""
    ) + (
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


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up ABB Welcome from a config entry."""
    # Repair names persisted by older versions before entities are created.
    _repair_entry_door_names(hass, entry)

    # Refresh the door topology before entities are created.  This makes a
    # normal config-entry reload pick up outdoor stations added/removed via
    # the gateway admin UI, without re-running the pairing/config flow.
    await _async_refresh_doors_for_entry(hass, entry, reload_on_change=False)

    coordinator = ABBWelcomeCoordinator(hass, entry)

    entry_data: dict = {
        "sip_client": _build_client(entry),
        "coordinator": coordinator,
    }
    wifi_panel = entry.data.get(CONF_DEVICE_TYPE) == DEVICE_TYPE_WIFI_PANEL
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = entry_data
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
            hass.bus.async_fire(EVENT_RING, payload)
            sensor = entry_data.get("ringing_sensor")
            if sensor is not None:
                sensor.trigger_ring(payload)

            # WiFi panel auto-discovery: when the panel has no doors
            # (no outdoorstation_* in the ACL-update), capture the
            # outdoor station's SIP URI from the incoming call and
            # persist it so a door-open button can be created.
            device_type = entry.data.get(CONF_DEVICE_TYPE, "ip_gateway")
            if (
                device_type == DEVICE_TYPE_WIFI_PANEL
                and not entry.data.get("doors")
                and not entry.data.get("discovered_outdoor_station")
                and call.caller_uri
                and call.caller_user
            ):
                sip_domain = entry.data.get("sip_domain", "")
                # Build a clean SIP address without ;transport=tls to
                # avoid duplication when sip_client appends it later.
                clean_address = f"sip:{call.caller_user}@{sip_domain}" if sip_domain else call.caller_uri
                _LOGGER.warning(
                    "[abb] WiFi panel: discovered outdoor station from "
                    "incoming call: uri=%s user=%s clean_address=%s",
                    call.caller_uri,
                    call.caller_user,
                    clean_address,
                )
                discovered = {
                    "address": clean_address,
                    "station_id": call.caller_user,
                    "name": f"Puerta ({call.caller_user})",
                }
                hass.config_entries.async_update_entry(
                    entry,
                    data={**entry.data, "discovered_outdoor_station": discovered},
                )
                # Delayed reload so the current ring/camera flow is
                # not interrupted by unloading the integration immediately.
                async def _reload_after_discovery() -> None:
                    import asyncio
                    await asyncio.sleep(5)
                    await hass.config_entries.async_reload(entry.entry_id)

                hass.async_create_task(_reload_after_discovery())

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

            if payload.get("direction") != "in" or payload.get("method") != "MESSAGE":
                return
            body = str(payload.get("body") or "").strip()
            match = _CAMERA_COUNT_MESSAGE_RE.search(body)
            if match is None:
                return
            headers = (
                payload.get("headers")
                if isinstance(payload.get("headers"), dict)
                else {}
            )
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
                station_id = _station_id_from_sip_value(str(payload.get("request_uri") or ""))
            if not station_id:
                _LOGGER.info(
                    "[abb] sip_listener: camera count MESSAGE body=%r has no "
                    "station id and no active call (from=%r request_uri=%r)",
                    body[:200],
                    _header_value(headers, "From"),
                    payload.get("request_uri"),
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
            on_state_change=_on_state_change,
            wifi_panel=wifi_panel,
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
                if (
                    login.status_code != 200
                    or body not in _GATEWAY_LOGIN_OK_RESPONSES
                ):
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
                        f"{scheme}: getdevicelist returned HTTP "
                        f"{response.status_code}"
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
            "[abb] refresh_doors: gateway returned no outdoorstation entries "
            "(raw=%r)",
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
    # WiFi panels have no web admin CGI, so door refresh is not possible.
    device_type = entry.data.get(CONF_DEVICE_TYPE, "ip_gateway")
    if device_type == DEVICE_TYPE_WIFI_PANEL:
        _LOGGER.info(
            "[abb] refresh_doors: entry %s is a WiFi panel — door refresh "
            "via gateway admin CGI is not available. Doors come from the "
            "ACL-update payload during pairing.",
            entry.entry_id,
        )
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
            raise HomeAssistantError(f"No ABB Welcome config entry id={target_entry_id!r}")
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
    """Register integration-wide services. Idempotent — safe to call on every entry setup."""
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

            for eid in entry_ids:
                entry = hass.config_entries.async_get_entry(eid)
                if entry is None:
                    continue
                await _async_refresh_doors_for_entry(
                    hass, entry, reload_on_change=True
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
                    raise HomeAssistantError("Selected camera does not support talkback")
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
                    raise HomeAssistantError("Selected camera does not support talkback")
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
                raise HomeAssistantError("pcm16le must be base64-encoded bytes") from err
            if len(pcm) % 2:
                raise HomeAssistantError("pcm16le must contain whole 16-bit samples")
            if len(pcm) > 160000:
                raise HomeAssistantError("pcm16le payload is too large")
            for camera in _cameras_for_talk_service(hass, call):
                feed = getattr(camera, "async_talkback_pcm16le", None)
                if not callable(feed):
                    raise HomeAssistantError("Selected camera does not support talkback")
                stats = await feed(pcm, talkback_session_id)
                _LOGGER.info(
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
                    raise HomeAssistantError("Selected camera does not support talkback")
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
