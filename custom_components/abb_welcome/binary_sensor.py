"""Binary sensor platform for ABB Welcome — realtime ring detection."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# How long the binary_sensor stays ON after a ring (the SIP leg only lasts
# a few hundred ms; users want a visible ring for at least this long so
# automations and notifications can react).
RING_HOLD_SECONDS = 5.0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the realtime ring binary_sensor."""
    data = hass.data[DOMAIN][entry.entry_id]
    if "sip_listener" not in data:
        return
    gateway_uuid = entry.data.get("gateway_uuid", "unknown")
    sensor = ABBWelcomeRingingSensor(gateway_uuid)
    data["ringing_sensor"] = sensor
    async_add_entities([sensor])


class ABBWelcomeRingingSensor(BinarySensorEntity):
    """Momentary ON state when an INVITE arrives from the gateway.

    Stays on for :data:`RING_HOLD_SECONDS` after each ring so HomeKit /
    Lovelace cards have time to render the change.  Re-rings while still
    ON simply restart the timer.
    """

    _attr_has_entity_name = True
    _attr_name = "Intercom Ringing"
    _attr_icon = "mdi:bell-ring"
    _attr_device_class = BinarySensorDeviceClass.OCCUPANCY

    def __init__(self, gateway_uuid: str) -> None:
        self._attr_unique_id = f"{gateway_uuid}_ringing"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, gateway_uuid)},
            name="ABB Welcome Gateway",
            manufacturer="ABB / Busch-Jaeger",
            model="IP Gateway (MRANGE)",
        )
        self._attr_is_on = False
        self._caller: dict[str, Any] = {}
        self._cancel_off: Any = None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return dict(self._caller)

    @callback
    def trigger_ring(self, caller: dict[str, Any]) -> None:
        """Mark the sensor ON for RING_HOLD_SECONDS, then return to OFF."""
        self._caller = caller
        self._attr_is_on = True
        self.async_write_ha_state()

        if self._cancel_off is not None:
            self._cancel_off()
            self._cancel_off = None

        @callback
        def _turn_off(_now: Any) -> None:
            self._attr_is_on = False
            self._cancel_off = None
            self.async_write_ha_state()

        if self.hass is not None:
            self._cancel_off = async_call_later(
                self.hass, RING_HOLD_SECONDS, _turn_off
            )
