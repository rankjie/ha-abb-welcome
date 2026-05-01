"""Image entity exposing the latest intercom screenshot."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from homeassistant.components.image import ImageEntity
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
    """Set up the screenshot image entity."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: ABBWelcomeCoordinator = data.get("coordinator")
    if not coordinator or not coordinator.has_certs:
        return
    gateway_uuid = entry.data.get("gateway_uuid", "unknown")
    async_add_entities(
        [ABBWelcomeScreenshotImage(hass, coordinator, gateway_uuid)]
    )


def _parse_event_timestamp(value: str) -> datetime | None:
    """Parse the ISO-8601 timestamp the portal puts on each event."""
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


class ABBWelcomeScreenshotImage(ImageEntity):
    """Last screenshot pushed by the gateway when someone rang the bell.

    The gateway only generates screenshots in response to ring events — this
    entity does not poll for new images on its own.  The
    ``image_last_updated`` timestamp is taken from the originating event so
    the user can see exactly when the frame was captured.
    """

    _attr_has_entity_name = True
    _attr_name = "Latest Screenshot"
    _attr_icon = "mdi:doorbell-video"
    _attr_content_type = "image/jpeg"

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: ABBWelcomeCoordinator,
        gateway_uuid: str,
    ) -> None:
        super().__init__(hass)
        self._coordinator = coordinator
        self._image: bytes | None = None
        self._last_event_id = ""
        self._attr_unique_id = f"{gateway_uuid}_latest_screenshot"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, gateway_uuid)},
            name="ABB Welcome Gateway",
            manufacturer="ABB / Busch-Jaeger",
            model="IP Gateway (MRANGE)",
        )

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._sync_from_coordinator()
        self.async_on_remove(
            self._coordinator.async_add_listener(self._handle_update)
        )

    def _sync_from_coordinator(self) -> None:
        data = self._coordinator.data
        if not data or not data.latest_screenshot:
            return
        if data.latest_screenshot_event_id == self._last_event_id:
            return
        self._image = data.latest_screenshot
        self._last_event_id = data.latest_screenshot_event_id
        ts: datetime | None = None
        for evt in data.events:
            if evt.event_id == self._last_event_id:
                ts = _parse_event_timestamp(evt.timestamp)
                break
        self._attr_image_last_updated = ts or datetime.now(timezone.utc)

    @callback
    def _handle_update(self) -> None:
        self._sync_from_coordinator()
        self.async_write_ha_state()

    async def async_image(self) -> bytes | None:
        return self._image
