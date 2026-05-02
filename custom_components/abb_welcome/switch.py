"""Streaming-armed switch.

Streaming the ABB intercom is building-wide exclusive (see
:mod:`streaming_state`).  This switch gives the user explicit, visible
control over whether the camera stream is allowed to start.

* ``on``  → arm streaming for :data:`MANUAL_ARM_SECONDS` (auto-disarms)
* ``off`` → force-disarm; any active stream is torn down

The switch state also reflects auto-arm by the SIP listener (when an
inbound INVITE arrives), so the user always sees "is streaming
permitted right now?" at a glance.
"""

from __future__ import annotations

import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .streaming_state import (
    ARM_REASON_MANUAL,
    MANUAL_ARM_SECONDS,
    arm,
    disarm,
    get_state,
    signal_armed_changed,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    if not entry.data.get("doors"):
        return
    async_add_entities([ABBStreamingArmedSwitch(hass, entry)])


class ABBStreamingArmedSwitch(SwitchEntity):
    """Per-gateway switch gating camera streaming."""

    _attr_has_entity_name = True
    _attr_name = "Streaming enabled"
    _attr_icon = "mdi:cctv"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self._entry = entry
        gateway_uuid = entry.data.get("gateway_uuid", "unknown")
        self._attr_unique_id = f"{gateway_uuid}_streaming_enabled"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, gateway_uuid)},
            name="ABB Welcome Gateway",
            manufacturer="ABB / Busch-Jaeger",
            model="IP Gateway (MRANGE)",
        )
        self._unsub: callable | None = None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._unsub = async_dispatcher_connect(
            self.hass,
            signal_armed_changed(self._entry.entry_id),
            self._on_changed,
        )

    async def async_will_remove_from_hass(self) -> None:
        if self._unsub is not None:
            self._unsub()
            self._unsub = None

    @callback
    def _on_changed(self) -> None:
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool:
        return get_state(self.hass, self._entry.entry_id).armed

    @property
    def extra_state_attributes(self) -> dict[str, str | int | float]:
        state = get_state(self.hass, self._entry.entry_id)
        return {
            "reason": state.reason,
            "remaining_seconds": int(state.remaining_seconds()),
        }

    async def async_turn_on(self, **kwargs) -> None:
        arm(
            self.hass,
            self._entry.entry_id,
            reason=ARM_REASON_MANUAL,
            duration=MANUAL_ARM_SECONDS,
        )

    async def async_turn_off(self, **kwargs) -> None:
        disarm(self.hass, self._entry.entry_id)
