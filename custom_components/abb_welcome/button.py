"""Button platform for ABB Welcome door unlock."""

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ABBWelcomeCoordinator
from .device import gateway_device_info
from .gateway_profile import GatewayProfile
from .gateway_runtime import GatewayRuntime

_LOGGER = logging.getLogger(__name__)


def _door_can_unlock(door: dict) -> bool:
    """Return whether this station should expose a door-open button."""
    if door.get("can_unlock") is False:
        return False
    station_type = str(door.get("type", "")).strip()
    return not station_type or station_type == "1"


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
    runtime: GatewayRuntime = data["runtime"]
    coordinator: ABBWelcomeCoordinator | None = data.get("coordinator")
    gateway_uuid = entry.data.get("gateway_uuid", "unknown")
    profile: GatewayProfile = data["gateway_profile"]
    doors = entry.data.get("doors", [])

    entities: list[ButtonEntity] = [
        ABBWelcomeDoorButton(
            runtime, door, gateway_uuid, entry.entry_id, profile
        )
        for door in doors
        if _door_can_unlock(door)
    ]
    if coordinator is not None and coordinator.has_certs:
        entities.append(
            ABBWelcomeRefreshButton(coordinator, gateway_uuid, profile)
        )
    async_add_entities(entities)


class ABBWelcomeDoorButton(ButtonEntity):
    """Button to unlock an ABB Welcome door station."""

    _attr_icon = "mdi:door-open"
    _attr_has_entity_name = True

    def __init__(
        self,
        runtime: GatewayRuntime,
        door: dict,
        gateway_uuid: str,
        entry_id: str,
        profile: GatewayProfile,
    ) -> None:
        self._runtime = runtime
        self._door = door
        self._attr_name = door["name"]
        self._attr_unique_id = f"{gateway_uuid}_{_door_station_key(door)}"
        self._attr_device_info = gateway_device_info(gateway_uuid, profile)

    async def async_press(self) -> None:
        """Unlock the door."""
        _LOGGER.debug("Unlocking door: %s", self._attr_name)
        success = await self._runtime.async_unlock(self.hass, self._door)
        if not success:
            raise HomeAssistantError(
                f"Failed to unlock door: {self._attr_name}"
            )


class ABBWelcomeRefreshButton(ButtonEntity):
    """Force a portal poll for new events / screenshots.

    The gateway only generates a new screenshot when the doorbell rings, so
    this button cannot make a *fresher* screenshot appear — it just shortens
    the wait between a ring and the entity reflecting it (otherwise the
    coordinator polls every 30 seconds).
    """

    _attr_icon = "mdi:refresh"
    _attr_has_entity_name = True
    _attr_name = "Refresh Events"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: ABBWelcomeCoordinator,
        gateway_uuid: str,
        profile: GatewayProfile,
    ) -> None:
        self._coordinator = coordinator
        self._attr_unique_id = f"{gateway_uuid}_refresh_events"
        self._attr_device_info = gateway_device_info(gateway_uuid, profile)

    async def async_press(self) -> None:
        await self._coordinator.async_request_refresh()
