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
    owner_leases: dict[str, float] = field(default_factory=dict)

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
    owner_token: str | None = None,
    renew: bool = False,
) -> None:
    """Arm streaming or extend an existing, unexpired owner lease."""
    station_id = str(station_id or "").strip()
    owner_token = str(owner_token or "").strip()
    if owner_token and (not entry_id or not station_id or reason != ARM_REASON_MANUAL):
        raise ValueError("An owned arm requires an entry, station and manual reason")
    if renew and not owner_token:
        raise ValueError("A renewal requires an owner token")
    state = get_state(hass, entry_id)
    now = time.monotonic()
    if owner_token:
        active_window = state.armed and state.until_monotonic > now
        if renew and not active_window:
            raise ValueError("Streaming lease expired")
        if active_window and state.target_station_id not in ("", station_id):
            raise ValueError("Another station is already armed")
        if active_window and not state.owner_leases:
            # Borrow an existing ring/switch arm; never take over its lifetime.
            return
        if renew and state.owner_leases.get(owner_token, 0.0) <= now:
            raise ValueError("Streaming lease expired")
        state.owner_leases = {
            token: expiry for token, expiry in state.owner_leases.items() if expiry > now
        }
        state.owner_leases[owner_token] = now + duration
    else:
        state.owner_leases.clear()
    if state.auto_disarm_task is not None and not state.auto_disarm_task.done():
        state.auto_disarm_task.cancel()
        state.auto_disarm_task = None

    state.armed = True
    state.reason = reason
    state.target_station_id = station_id
    state.until_monotonic = (
        max(state.owner_leases.values())
        if state.owner_leases
        else now + duration
    )

    async def _auto_off() -> None:
        try:
            while state.owner_leases:
                await asyncio.sleep(
                    max(0, min(state.owner_leases.values()) - time.monotonic())
                )
                now = time.monotonic()
                state.owner_leases = {
                    token: expiry
                    for token, expiry in state.owner_leases.items()
                    if expiry > now
                }
                if state.owner_leases:
                    state.until_monotonic = max(state.owner_leases.values())
            if not owner_token:
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
        cur.owner_leases.clear()
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
    state.owner_leases.clear()
    async_dispatcher_send(hass, signal_armed_changed(entry_id))
    _LOGGER.info("[abb] streaming disarmed for entry %s", entry_id)


def is_armed(hass: HomeAssistant, entry_id: str) -> bool:
    return get_state(hass, entry_id).armed


@callback
def release_manual_arm(
    hass: HomeAssistant,
    entry_id: str,
    *,
    station_id: str,
    owner_token: str,
) -> bool:
    """Release only this card's lease, preserving other cards and ring arms."""
    if not entry_id or not station_id or not owner_token:
        return False
    state = hass.data.get(DOMAIN, {}).get(entry_id, {}).get("armed_state")
    if (
        state is None
        or not state.armed
        or state.reason != ARM_REASON_MANUAL
        or state.target_station_id != station_id
        or owner_token not in state.owner_leases
    ):
        return False
    del state.owner_leases[owner_token]
    if not state.owner_leases:
        disarm(hass, entry_id)
    else:
        state.until_monotonic = max(state.owner_leases.values())
    return True
