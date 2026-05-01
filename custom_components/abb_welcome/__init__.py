"""ABB Welcome integration — LAN door unlock + cloud event history via SIP."""

import logging
from datetime import datetime, timedelta, timezone


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.start import async_at_start

from .const import CONF_UNLOCK_STRATEGY, DEFAULT_UNLOCK_STRATEGY, DOMAIN, SIP_PORT_TLS
from .coordinator import ABBWelcomeCoordinator
from .sip_client import SIPClient
from .sip_listener import IncomingCall, SipListener

_LOGGER = logging.getLogger(__name__)

for _name in (
    "custom_components.abb_welcome",
    "custom_components.abb_welcome.portal",
    "custom_components.abb_welcome.config_flow",
    "custom_components.abb_welcome.coordinator",
    "custom_components.abb_welcome.sip_client",
    "custom_components.abb_welcome.sip_listener",
    "custom_components.abb_welcome.button",
    "custom_components.abb_welcome.binary_sensor",
    "custom_components.abb_welcome.image",
    "custom_components.abb_welcome.event",
    "custom_components.abb_welcome.sensor",
):
    logging.getLogger(_name).setLevel(logging.INFO)

PLATFORMS = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.IMAGE,
    Platform.EVENT,
    Platform.SENSOR,
]

POLL_INTERVAL = timedelta(seconds=30)

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


def _build_client(entry: ConfigEntry) -> SIPClient:
    return SIPClient(
        host=entry.data["gateway_ip"],
        username=entry.data["sip_username"],
        password=entry.data["sip_password"],
        domain=entry.data["sip_domain"],
        doors=entry.data.get("doors", []),
        unlock_strategy=entry.options.get(
            CONF_UNLOCK_STRATEGY, DEFAULT_UNLOCK_STRATEGY
        ),
    )


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up ABB Welcome from a config entry."""
    coordinator = ABBWelcomeCoordinator(hass, entry)

    entry_data: dict = {
        "sip_client": _build_client(entry),
        "coordinator": coordinator,
    }
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = entry_data

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
        def _on_ring(call: IncomingCall) -> None:
            payload = {
                "caller_uri": call.caller_uri,
                "caller_user": call.caller_user,
                "call_id": call.call_id,
                "received_at": call.received_at,
            }
            hass.bus.async_fire(EVENT_RING, payload)
            sensor = entry_data.get("ringing_sensor")
            if sensor is not None:
                sensor.trigger_ring(payload)

        def _on_frame(payload: dict) -> None:
            hass.bus.async_fire(EVENT_SIP_FRAME, payload)
            sensor = entry_data.get("listener_state_sensor")
            if sensor is not None:
                is_invite = (
                    payload.get("direction") == "in"
                    and payload.get("method") == "INVITE"
                )
                sensor.record_frame(payload.get("direction", ""), is_invite)

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

    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Rebuild the SIP client when the user changes options."""
    hass.data[DOMAIN][entry.entry_id]["sip_client"] = _build_client(entry)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload ABB Welcome config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
