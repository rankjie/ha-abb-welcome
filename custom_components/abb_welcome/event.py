"""Event entity for ABB Welcome intercom events.

Fires HA events when the gateway reports rings, door opens, calls, etc.
These show up in the HA logbook and can trigger automations.
"""

from __future__ import annotations

import logging

from homeassistant.components.event import EventEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ABBWelcomeCoordinator

_LOGGER = logging.getLogger(__name__)

EVENT_TYPES = [
    "ring",
    "door-open",
    "call-answered",
    "call-terminated",
    "call-missed",
    "light",
    "screenshot",
]

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
    """Set up ABB Welcome event entity from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: ABBWelcomeCoordinator = data.get("coordinator")
    if not coordinator or not coordinator.has_certs:
        return
    gateway_uuid = entry.data.get("gateway_uuid", "unknown")
    async_add_entities([ABBWelcomeEventEntity(coordinator, gateway_uuid)])


class ABBWelcomeEventEntity(EventEntity):
    """Event entity that fires on intercom activity."""

    _attr_has_entity_name = True
    _attr_name = "Intercom"
    _attr_icon = "mdi:bell-ring"
    _attr_event_types = EVENT_TYPES

    def __init__(
        self,
        coordinator: ABBWelcomeCoordinator,
        gateway_uuid: str,
    ) -> None:
        self._coordinator = coordinator
        self._attr_unique_id = f"{gateway_uuid}_intercom_events"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, gateway_uuid)},
            name="ABB Welcome Gateway",
            manufacturer="ABB / Busch-Jaeger",
            model="IP Gateway (MRANGE)",
        )
        self._last_seen_id = ""

    async def async_added_to_hass(self) -> None:
        self._coordinator.async_add_listener(self._handle_update)

    @callback
    def _handle_update(self) -> None:
        data = self._coordinator.data
        if not data or not data.events:
            return

        for evt in data.events:
            if evt.event_id == self._last_seen_id:
                break
            if evt.event_type == "screenshot":
                continue

            station = ""
            if evt.station_id:
                station = STATION_NAMES.get(evt.station_id, f"Station {evt.station_id}")

            self._trigger_event(
                evt.event_type,
                {
                    "station": station,
                    "station_id": evt.station_id,
                    "timestamp": evt.timestamp,
                    "event_id": evt.event_id,
                },
            )

        if data.events:
            self._last_seen_id = data.events[0].event_id
