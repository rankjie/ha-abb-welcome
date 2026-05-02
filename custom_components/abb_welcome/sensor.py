"""Sensor entities for ABB Welcome — last cloud event and SIP listener state."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ABBWelcomeCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up ABB Welcome sensors from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    gateway_uuid = entry.data.get("gateway_uuid", "unknown")

    sensors: list[SensorEntity] = []

    coordinator: ABBWelcomeCoordinator = data.get("coordinator")
    if coordinator is not None and coordinator.has_certs:
        sensors.append(
            ABBWelcomeLastEventSensor(
                coordinator,
                gateway_uuid,
                entry.data.get("doors", []) or [],
            )
        )

    if "sip_listener" in data:
        listener_sensor = ABBWelcomeListenerStateSensor(gateway_uuid)
        data["listener_state_sensor"] = listener_sensor
        sensors.append(listener_sensor)

    if sensors:
        async_add_entities(sensors)


class ABBWelcomeLastEventSensor(SensorEntity):
    """Sensor showing the most recent intercom event."""

    _attr_has_entity_name = True
    _attr_name = "Last Event"
    _attr_icon = "mdi:bell-ring-outline"

    def __init__(
        self,
        coordinator: ABBWelcomeCoordinator,
        gateway_uuid: str,
        doors: list[dict[str, Any]],
    ) -> None:
        self._coordinator = coordinator
        self._station_names = {
            str(door.get("station_id", "")).strip(): str(
                door.get("name") or door.get("station_id") or ""
            )
            for door in doors
            if str(door.get("station_id", "")).strip()
        }
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
        station = evt.local_name or self._station_names.get(evt.station_id, evt.station_id)
        label = evt.event_type.replace("-", " ").title()
        return f"{label} — {station}" if station else label

    @property
    def extra_state_attributes(self) -> dict | None:
        data = self._coordinator.data
        if not data or not data.last_event:
            return None
        evt = data.last_event
        station_name = evt.local_name or self._station_names.get(evt.station_id, "")
        attrs = {
            "event_type": evt.event_type,
            "event_label": evt.event_type.replace("-", " ").title(),
            "station_id": evt.station_id,
            "station": station_name,
            "station_name": station_name,
            "local_id": evt.local_id,
            "local_name": evt.local_name,
            "sender": evt.sender,
            "belongs_to": evt.belongs_to,
            "timestamp": evt.timestamp,
            "event_id": evt.event_id,
            "has_image": evt.image_data is not None,
            "image_bytes": len(evt.image_data) if evt.image_data else 0,
            "total_events_cached": len(data.events),
        }
        if evt.payload_text:
            attrs["payload_text"] = evt.payload_text
        return attrs


class ABBWelcomeListenerStateSensor(SensorEntity):
    """Reports the SIP listener's connection / registration state.

    Values mirror :class:`SipListener.state`:
    ``stopped`` → not running, ``connecting`` → opening socket / sending
    REGISTER, ``registered`` → REGISTER 200 OK received and the listener
    is reading frames, ``disconnected`` → socket dropped, waiting for
    backoff before reconnect.

    The ``last_change`` attribute stamps each transition so it's obvious
    when the listener last reconnected without scrubbing logs.  Frame
    counters are also exposed for at-a-glance liveness.
    """

    _attr_has_entity_name = True
    _attr_name = "SIP Listener"
    _attr_icon = "mdi:phone-incoming"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = ["stopped", "connecting", "registered", "disconnected"]

    def __init__(self, gateway_uuid: str) -> None:
        self._attr_unique_id = f"{gateway_uuid}_sip_listener_state"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, gateway_uuid)},
            name="ABB Welcome Gateway",
            manufacturer="ABB / Busch-Jaeger",
            model="IP Gateway (MRANGE)",
        )
        self._state = "stopped"
        self._last_change = datetime.now(timezone.utc)
        self._frames_in = 0
        self._frames_out = 0
        self._invites_received = 0
        self._last_invite_at: datetime | None = None
        self._last_register_at: datetime | None = None

    @property
    def native_value(self) -> str:
        return self._state

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "last_change": self._last_change.isoformat(),
            "frames_in": self._frames_in,
            "frames_out": self._frames_out,
            "invites_received": self._invites_received,
            "last_invite_at": self._last_invite_at.isoformat() if self._last_invite_at else None,
            "last_register_at": self._last_register_at.isoformat() if self._last_register_at else None,
        }

    @callback
    def update_state(self, new_state: str) -> None:
        if new_state != self._state:
            self._state = new_state
            self._last_change = datetime.now(timezone.utc)
            if new_state == "registered":
                self._last_register_at = self._last_change
        if self.hass is not None:
            self.async_write_ha_state()

    @callback
    def record_frame(self, direction: str, is_invite: bool) -> None:
        if direction == "in":
            self._frames_in += 1
        elif direction == "out":
            self._frames_out += 1
        if is_invite:
            self._invites_received += 1
            self._last_invite_at = datetime.now(timezone.utc)
        if self.hass is not None:
            self.async_write_ha_state()
