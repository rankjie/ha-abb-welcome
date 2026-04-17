"""Sensor entity showing the last intercom event."""

from __future__ import annotations

import logging

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ABBWelcomeCoordinator

_LOGGER = logging.getLogger(__name__)

STATION_NAMES = {
    "100000001": "Outdoor 1",
    "100000002": "Inner",
    "100000003": "Parking Garage",
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up ABB Welcome sensor from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: ABBWelcomeCoordinator = data.get("coordinator")
    if not coordinator or not coordinator.has_certs:
        return
    gateway_uuid = entry.data.get("gateway_uuid", "unknown")
    async_add_entities([ABBWelcomeLastEventSensor(coordinator, gateway_uuid)])


class ABBWelcomeLastEventSensor(SensorEntity):
    """Sensor showing the most recent intercom event."""

    _attr_has_entity_name = True
    _attr_name = "Last Event"
    _attr_icon = "mdi:bell-ring-outline"

    def __init__(
        self,
        coordinator: ABBWelcomeCoordinator,
        gateway_uuid: str,
    ) -> None:
        self._coordinator = coordinator
        self._attr_unique_id = f"{gateway_uuid}_last_event"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, gateway_uuid)},
            name="ABB Welcome Gateway",
            manufacturer="ABB / Busch-Jaeger",
            model="IP Gateway (MRANGE)",
        )

    async def async_added_to_hass(self) -> None:
        self._coordinator.async_add_listener(self._handle_update)

    @callback
    def _handle_update(self) -> None:
        data = self._coordinator.data
        if data and data.last_event:
            self.async_write_ha_state()

    @property
    def native_value(self) -> str | None:
        data = self._coordinator.data
        if not data or not data.last_event:
            return None
        evt = data.last_event
        station = STATION_NAMES.get(evt.station_id, evt.station_id)
        label = evt.event_type.replace("-", " ").title()
        return f"{label} — {station}" if station else label

    @property
    def extra_state_attributes(self) -> dict | None:
        data = self._coordinator.data
        if not data or not data.last_event:
            return None
        evt = data.last_event
        return {
            "event_type": evt.event_type,
            "station_id": evt.station_id,
            "station_name": STATION_NAMES.get(evt.station_id, ""),
            "timestamp": evt.timestamp,
            "event_id": evt.event_id,
            "total_events_cached": len(data.events),
        }
