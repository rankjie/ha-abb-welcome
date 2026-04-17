"""Camera entity showing the latest intercom screenshot."""

from __future__ import annotations

import logging

from homeassistant.components.camera import Camera
from homeassistant.config_entries import ConfigEntry
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
    """Set up ABB Welcome camera from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: ABBWelcomeCoordinator = data.get("coordinator")
    if not coordinator or not coordinator.has_certs:
        return
    gateway_uuid = entry.data.get("gateway_uuid", "unknown")
    async_add_entities([ABBWelcomeCamera(coordinator, gateway_uuid, entry.entry_id)])


class ABBWelcomeCamera(Camera):
    """Camera showing the latest intercom screenshot from the portal."""

    _attr_has_entity_name = True
    _attr_name = "Latest Screenshot"
    _attr_icon = "mdi:doorbell-video"

    def __init__(
        self,
        coordinator: ABBWelcomeCoordinator,
        gateway_uuid: str,
        entry_id: str,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._attr_unique_id = f"{gateway_uuid}_latest_screenshot"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, gateway_uuid)},
            name="ABB Welcome Gateway",
            manufacturer="ABB / Busch-Jaeger",
            model="IP Gateway (MRANGE)",
        )
        self._image: bytes | None = None
        self._last_event_id = ""

    async def async_added_to_hass(self) -> None:
        self._coordinator.async_add_listener(self._handle_update)

    @callback
    def _handle_update(self) -> None:
        data = self._coordinator.data
        if data and data.latest_screenshot and data.latest_screenshot_event_id != self._last_event_id:
            self._image = data.latest_screenshot
            self._last_event_id = data.latest_screenshot_event_id
            self.async_write_ha_state()

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        return self._image
