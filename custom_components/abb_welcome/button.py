"""Button platform for ABB Welcome door unlock."""

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


def _door_station_key(door: dict) -> str:
    station_id = str(door.get("station_id", "")).strip()
    if station_id:
        return station_id

    body = str(door.get("body", "")).strip()
    if body.startswith("b:"):
        return body.split(":", 1)[1].strip()

    address = str(door.get("address", "")).strip()
    if address.startswith("sip:") and "@" in address:
        return address.split(":", 1)[1].split("@", 1)[0]

    return door.get("name", "door")


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up ABB Welcome door buttons from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    sip_client = data["sip_client"]
    gateway_uuid = entry.data.get("gateway_uuid", "unknown")
    doors = entry.data.get("doors", [])

    entities = [
        ABBWelcomeDoorButton(sip_client, door, gateway_uuid, entry.entry_id)
        for door in doors
    ]
    async_add_entities(entities)


class ABBWelcomeDoorButton(ButtonEntity):
    """Button to unlock an ABB Welcome door station."""

    _attr_icon = "mdi:door-open"
    _attr_has_entity_name = True

    def __init__(self, sip_client, door: dict, gateway_uuid: str, entry_id: str) -> None:
        self._sip_client = sip_client
        self._door = door
        self._attr_name = door["name"]
        self._attr_unique_id = f"{gateway_uuid}_{_door_station_key(door)}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, gateway_uuid)},
            name="ABB Welcome Gateway",
            manufacturer="ABB / Busch-Jaeger",
            model="IP Gateway (MRANGE)",
        )

    async def async_press(self) -> None:
        """Unlock the door."""
        _LOGGER.debug("Unlocking door: %s", self._attr_name)
        success = await self.hass.async_add_executor_job(
            self._sip_client.unlock_door, self._door
        )
        if not success:
            raise HomeAssistantError(
                f"Failed to unlock door: {self._attr_name}"
            )
