"""Per-gateway armed-state machine for camera streaming.

Streaming the ABB intercom is **building-wide exclusive** — opening it
locks the rest of the building's intercom out for the duration of the
call.  We never want a stream to start by accident (HA frontend prefetch,
HomeKit health probe, idle webrtc consumer, etc.), so streaming is
gated on an explicit *armed* boolean per gateway.

Three paths flip armed True:

* the user toggles ``switch.<gateway>_streaming_enabled`` on
  (manual arm; auto-disarms after ``MANUAL_ARM_SECONDS``)
* the SIP listener observes an inbound INVITE for an outdoor station
  while pickup is allowed (auto arm; auto-disarms after
  ``RING_ARM_SECONDS``)
* a live view holds the station open (live arm; no timer). Each holder is
  a frontend websocket subscription, so a closed or disconnected browser
  releases it, and the window ends when the station hangs up.

The switch entity, the SIP listener handler, and the camera entity all
read/write through this small helper so the timer, dispatcher signal,
and "reason" string stay coherent.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import (
    DEFAULT_ALLOW_PICKUP,
    DEFAULT_CAMERA_STILL_IMAGE,
    DEFAULT_PREVIEW_BEFORE_ANSWER,
    DOMAIN,
)
from .redaction import get_redacting_logger

_LOGGER = get_redacting_logger(__name__)

MANUAL_ARM_SECONDS = 180
RING_ARM_SECONDS = 120

ARM_REASON_MANUAL = "manual"
ARM_REASON_RING = "ring"
ARM_REASON_LIVE = "live"


def signal_armed_changed(entry_id: str) -> str:
    """Dispatcher signal raised when the armed flag flips for one entry."""
    return f"{DOMAIN}_armed_changed_{entry_id}"


def signal_pickup_allowed_changed(entry_id: str) -> str:
    """Dispatcher signal raised when the pickup gate changes for one entry."""
    return f"{DOMAIN}_pickup_allowed_changed_{entry_id}"


def signal_preview_before_answer_changed(entry_id: str) -> str:
    """Dispatcher signal raised when the preview option changes for one entry."""
    return f"{DOMAIN}_preview_before_answer_changed_{entry_id}"


@dataclass
class ArmedState:
    """Mutable armed-state for a single gateway/entry."""

    armed: bool = False
    reason: str = ""
    target_station_id: str = ""
    until_monotonic: float = 0.0
    auto_disarm_task: asyncio.Task | None = None
    live_owners: set[str] = field(default_factory=set)

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


def is_preview_before_answer(hass: HomeAssistant, entry_id: str) -> bool:
    """Return whether a stream opened during a ring only previews the call."""
    return bool(
        _entry_bucket(hass, entry_id).get(
            "preview_before_answer", DEFAULT_PREVIEW_BEFORE_ANSWER
        )
    )


@callback
def set_preview_before_answer(
    hass: HomeAssistant,
    entry_id: str,
    enabled: bool,
) -> None:
    """Set whether a stream opened during a ring only previews the call."""
    bucket = _entry_bucket(hass, entry_id)
    enabled = bool(enabled)
    previous = bucket.get("preview_before_answer")
    bucket["preview_before_answer"] = enabled
    if previous == enabled:
        return
    async_dispatcher_send(hass, signal_preview_before_answer_changed(entry_id))


def is_camera_still_image_enabled(hass: HomeAssistant, entry_id: str) -> bool:
    """Return whether cameras serve the last station screenshot as their still."""
    return bool(
        _entry_bucket(hass, entry_id).get(
            "camera_still_image", DEFAULT_CAMERA_STILL_IMAGE
        )
    )


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
    """Arm streaming for ``duration`` seconds; cancels any existing timer.

    A timed arm takes over a live window: its holders keep streaming until
    this window ends.
    """
    state = get_state(hass, entry_id)
    state.live_owners.clear()
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
    state.live_owners.clear()
    async_dispatcher_send(hass, signal_armed_changed(entry_id))
    _LOGGER.info("[abb] streaming disarmed for entry %s", entry_id)


def is_armed(hass: HomeAssistant, entry_id: str) -> bool:
    return get_state(hass, entry_id).armed


@callback
def acquire_live(
    hass: HomeAssistant, entry_id: str, station_id: str, owner: str
) -> None:
    """Hold streaming open for one station until released or disarmed.

    A ring or switch window that already allows the station is used as it
    is: the live view neither extends nor ends it. Raises ValueError while
    another station is armed.
    """
    state = get_state(hass, entry_id)
    if state.armed and state.target_station_id not in ("", station_id):
        raise ValueError("Another station is already armed")
    if state.armed and not state.live_owners:
        return
    state.live_owners.add(owner)
    if state.armed:
        return
    state.armed = True
    state.reason = ARM_REASON_LIVE
    state.target_station_id = station_id
    state.until_monotonic = 0.0
    async_dispatcher_send(hass, signal_armed_changed(entry_id))
    _LOGGER.info(
        "[abb] streaming armed for entry %s (reason=live, target_station=%s)",
        entry_id, station_id,
    )


@callback
def release_live(hass: HomeAssistant, entry_id: str, owner: str) -> None:
    """Drop one live holder; the last one disarms its window."""
    state = hass.data.get(DOMAIN, {}).get(entry_id, {}).get("armed_state")
    if state is None or owner not in state.live_owners:
        return
    state.live_owners.discard(owner)
    if not state.live_owners:
        disarm(hass, entry_id)


@callback
def end_live(hass: HomeAssistant, entry_id: str, station_id: str) -> None:
    """End a live window after its station hung up the call.

    Stream clients reconnect on their own; leaving the window open would
    call the station again for a viewer that never asked for it.
    """
    state = get_state(hass, entry_id)
    if state.live_owners and state.target_station_id == station_id:
        disarm(hass, entry_id)
