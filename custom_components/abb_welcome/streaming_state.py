"""Per-gateway armed-state machine for camera streaming.

Streaming the ABB intercom is **building-wide exclusive** — opening it
locks the rest of the building's intercom out for the duration of the
call.  We never want a stream to start by accident (HA frontend prefetch,
HomeKit health probe, idle webrtc consumer, etc.), so streaming is
gated on an explicit *armed* boolean per gateway.

Two paths flip armed True:

* the user toggles ``switch.<gateway>_streaming_enabled`` on
  (manual arm; auto-disarms after ``MANUAL_ARM_SECONDS``)
* the SIP listener observes an inbound INVITE for an outdoor station
  while pickup is allowed (auto arm; auto-disarms after
  ``RING_ARM_SECONDS``)

The switch entity, the SIP listener handler, and the camera entity all
read/write through this small helper so the timer, dispatcher signal,
and "reason" string stay coherent.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import DEFAULT_ALLOW_PICKUP, DOMAIN
from .redaction import get_redacting_logger

_LOGGER = get_redacting_logger(__name__)

MANUAL_ARM_SECONDS = 180
RING_ARM_SECONDS = 120

ARM_REASON_MANUAL = "manual"
ARM_REASON_RING = "ring"


def signal_armed_changed(entry_id: str) -> str:
    """Dispatcher signal raised when the armed flag flips for one entry."""
    return f"{DOMAIN}_armed_changed_{entry_id}"


def signal_pickup_allowed_changed(entry_id: str) -> str:
    """Dispatcher signal raised when the pickup gate changes for one entry."""
    return f"{DOMAIN}_pickup_allowed_changed_{entry_id}"


@dataclass
class ArmedState:
    """Mutable armed-state for a single gateway/entry."""

    armed: bool = False
    reason: str = ""
    target_station_id: str = ""
    until_monotonic: float = 0.0
    auto_disarm_task: asyncio.Task | None = None

    def remaining_seconds(self) -> float:
        if not self.armed:
            return 0.0
        return max(0.0, self.until_monotonic - time.monotonic())


def _entry_bucket(hass: HomeAssistant, entry_id: str) -> dict:
    return hass.data.setdefault(DOMAIN, {}).setdefault(entry_id, {})


def get_state(hass: HomeAssistant, entry_id: str) -> ArmedState:
    """Return (creating if missing) the armed state for an integration entry."""
    bucket = _entry_bucket(hass, entry_id)
    state = bucket.get("armed_state")
    if state is None:
        state = ArmedState()
        bucket["armed_state"] = state
    return state


def is_pickup_allowed(hass: HomeAssistant, entry_id: str) -> bool:
    """Return whether incoming doorbell calls may be accepted by streams."""
    return bool(_entry_bucket(hass, entry_id).get("allow_pickup", DEFAULT_ALLOW_PICKUP))


def is_stream_allowed(
    hass: HomeAssistant,
    entry_id: str,
    station_id: str | None = None,
) -> bool:
    """Return whether this station may open media under the current arm."""
    state = get_state(hass, entry_id)
    if not state.armed:
        return False
    target = state.target_station_id
    station_id = str(station_id or "").strip()
    return not target or (station_id and target == station_id)


@callback
def set_pickup_allowed(
    hass: HomeAssistant,
    entry_id: str,
    allowed: bool,
) -> None:
    """Set the independent incoming-call pickup gate for this entry."""
    bucket = _entry_bucket(hass, entry_id)
    allowed = bool(allowed)
    previous = bucket.get("allow_pickup")
    bucket["allow_pickup"] = allowed
    if not allowed:
        state = get_state(hass, entry_id)
        if state.armed and state.reason == ARM_REASON_RING:
            disarm(hass, entry_id)
    if previous == allowed:
        return
    async_dispatcher_send(hass, signal_pickup_allowed_changed(entry_id))
    _LOGGER.info(
        "[abb] incoming call pickup %s for entry %s",
        "allowed" if allowed else "disabled",
        entry_id,
    )


@callback
def arm(
    hass: HomeAssistant,
    entry_id: str,
    *,
    reason: str,
    duration: float,
    station_id: str | None = None,
) -> None:
    """Arm streaming for ``duration`` seconds; cancels any existing timer."""
    state = get_state(hass, entry_id)
    if state.auto_disarm_task is not None and not state.auto_disarm_task.done():
        state.auto_disarm_task.cancel()
        state.auto_disarm_task = None

    state.armed = True
    state.reason = reason
    state.target_station_id = str(station_id or "").strip()
    state.until_monotonic = time.monotonic() + duration

    async def _auto_off() -> None:
        try:
            await asyncio.sleep(duration)
        except asyncio.CancelledError:
            return
        # Only disarm if we're still the active timer (a newer arm() may have
        # taken over with a different until time).
        cur = get_state(hass, entry_id)
        if cur.auto_disarm_task is not asyncio.current_task():
            return
        cur.armed = False
        cur.reason = ""
        cur.target_station_id = ""
        cur.until_monotonic = 0.0
        cur.auto_disarm_task = None
        async_dispatcher_send(hass, signal_armed_changed(entry_id))
        _LOGGER.info(
            "[abb] streaming auto-disarmed for entry %s after %ss",
            entry_id, duration,
        )

    state.auto_disarm_task = hass.async_create_background_task(
        _auto_off(), name=f"abb_streaming_auto_disarm_{entry_id}"
    )

    async_dispatcher_send(hass, signal_armed_changed(entry_id))
    _LOGGER.info(
        "[abb] streaming armed for entry %s (reason=%s, target_station=%s, %ss)",
        entry_id, reason, state.target_station_id or "any", int(duration),
    )


@callback
def disarm(hass: HomeAssistant, entry_id: str) -> None:
    """Force-disarm streaming."""
    state = get_state(hass, entry_id)
    if state.auto_disarm_task is not None and not state.auto_disarm_task.done():
        state.auto_disarm_task.cancel()
        state.auto_disarm_task = None
    if not state.armed:
        return
    state.armed = False
    state.reason = ""
    state.target_station_id = ""
    state.until_monotonic = 0.0
    async_dispatcher_send(hass, signal_armed_changed(entry_id))
    _LOGGER.info("[abb] streaming disarmed for entry %s", entry_id)


def is_armed(hass: HomeAssistant, entry_id: str) -> bool:
    return get_state(hass, entry_id).armed
