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
  (auto arm; auto-disarms after ``RING_ARM_SECONDS``)

The switch entity, the SIP listener handler, and the camera entity all
read/write through this small helper so the timer, dispatcher signal,
and "reason" string stay coherent.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

MANUAL_ARM_SECONDS = 30
RING_ARM_SECONDS = 60

ARM_REASON_MANUAL = "manual"
ARM_REASON_RING = "ring"


def signal_armed_changed(entry_id: str) -> str:
    """Dispatcher signal raised when the armed flag flips for one entry."""
    return f"{DOMAIN}_armed_changed_{entry_id}"


@dataclass
class ArmedState:
    """Mutable armed-state for a single gateway/entry."""

    armed: bool = False
    reason: str = ""
    until_monotonic: float = 0.0
    auto_disarm_task: asyncio.Task | None = None

    def remaining_seconds(self) -> float:
        if not self.armed:
            return 0.0
        return max(0.0, self.until_monotonic - time.monotonic())


def get_state(hass: HomeAssistant, entry_id: str) -> ArmedState:
    """Return (creating if missing) the armed state for an integration entry."""
    bucket = hass.data.setdefault(DOMAIN, {}).setdefault(entry_id, {})
    state = bucket.get("armed_state")
    if state is None:
        state = ArmedState()
        bucket["armed_state"] = state
    return state


@callback
def arm(
    hass: HomeAssistant,
    entry_id: str,
    *,
    reason: str,
    duration: float,
) -> None:
    """Arm streaming for ``duration`` seconds; cancels any existing timer."""
    state = get_state(hass, entry_id)
    if state.auto_disarm_task is not None and not state.auto_disarm_task.done():
        state.auto_disarm_task.cancel()
        state.auto_disarm_task = None

    state.armed = True
    state.reason = reason
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
        "[abb] streaming armed for entry %s (reason=%s, %ss)",
        entry_id, reason, int(duration),
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
    state.until_monotonic = 0.0
    async_dispatcher_send(hass, signal_armed_changed(entry_id))
    _LOGGER.info("[abb] streaming disarmed for entry %s", entry_id)


def is_armed(hass: HomeAssistant, entry_id: str) -> bool:
    return get_state(hass, entry_id).armed
