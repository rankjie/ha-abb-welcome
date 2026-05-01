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


def _parse_event_timestamp(value: str | int | float | None) -> datetime | None:
    """Parse a portal event's timestamp, accepting ISO-8601 or Unix epoch."""
    if value in (None, ""):
        return None
    # Some endpoints emit numeric epoch seconds — handle both str digits and int.
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
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

        raw_ts = ""
        ts: datetime | None = None
        for evt in data.events:
            if evt.event_id == self._last_event_id:
                raw_ts = evt.timestamp
                ts = _parse_event_timestamp(evt.timestamp)
                break

        if ts is not None:
            self._attr_image_last_updated = ts
            _LOGGER.info(
                "[abb] Screenshot event %s captured at %s (raw=%r)",
                self._last_event_id, ts.isoformat(), raw_ts,
            )
        else:
            # No parseable event timestamp — fall back to ``now`` so the
            # frontend cache-buster still fires.  Without this the browser
            # would keep showing the previous image.
            self._attr_image_last_updated = datetime.now(timezone.utc)
            _LOGGER.warning(
                "[abb] Screenshot event %s has no parseable timestamp "
                "(raw=%r) — using current time. Please report this with a "
                "DEBUG log so the parser can be extended.",
                self._last_event_id, raw_ts,
            )

    @callback
    def _handle_update(self) -> None:
        self._sync_from_coordinator()
        self.async_write_ha_state()

    async def async_image(self) -> bytes | None:
        return self._image

    @property
    def extra_state_attributes(self) -> dict[str, str | None]:
        """Expose the actual capture time as a clearly named attribute.

        ``image_last_updated`` is also the entity's state value, but HA's
        Lovelace cards often surface ``last_changed`` (when HA wrote the
        state) rather than the image's own timestamp.  This attribute makes
        the real capture time visible regardless of which timestamp the UI
        chooses to display.
        """
        ts = self._attr_image_last_updated
        return {
            "captured_at": ts.isoformat() if ts else None,
            "event_id": self._last_event_id or None,
        }
