"""Button platform for ABB Welcome door unlock."""

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_DEVICE_TYPE, DEVICE_TYPE_WIFI_PANEL, DOMAIN
from .coordinator import ABBWelcomeCoordinator

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
    sip_client = data["sip_client"]
    coordinator: ABBWelcomeCoordinator | None = data.get("coordinator")
    gateway_uuid = entry.data.get("gateway_uuid", "unknown")
    doors = entry.data.get("doors", [])
    device_type = entry.data.get(CONF_DEVICE_TYPE, "ip_gateway")

    entities: list[ButtonEntity] = [
        ABBWelcomeDoorButton(sip_client, door, gateway_uuid, entry.entry_id)
        for door in doors
        if _door_can_unlock(door)
    ]

    # WiFi panels without outdoorstation_* sections get a generic
    # door-open button.  The outdoor station SIP URI is discovered
    # dynamically from the first incoming call (see __init__.py).
    if device_type == DEVICE_TYPE_WIFI_PANEL and not entities:
        discovered_station = entry.data.get("discovered_outdoor_station")
        if discovered_station and discovered_station.get("address"):
            # Reconstruct a clean SIP address without ;user=phone or
            # ;transport=tls parameters that may have come from the
            # incoming INVITE From header.
            station_id = discovered_station.get("station_id", "")
            sip_domain = entry.data.get("sip_domain", "")
            if station_id and sip_domain:
                clean_address = f"sip:{station_id}@{sip_domain}"
            else:
                clean_address = discovered_station["address"]
            door = {
                "name": discovered_station.get("name", "Abrir puerta"),
                "address": clean_address,
                "station_id": station_id,
                "body": "1",
                # No index: let hybrid strategy use the invite/standard
                # flow (TLS) instead of fast TCP MESSAGE, which is safer
                # for WiFi panels.
            }
            entities.append(
                ABBWelcomeDoorButton(sip_client, door, gateway_uuid, entry.entry_id)
            )
        else:
            # Show a placeholder button that will work once a call is received
            entities.append(
                ABBWelcomeWifiDoorButton(sip_client, gateway_uuid, entry.entry_id)
            )

    if coordinator is not None and coordinator.has_certs:
        entities.append(ABBWelcomeRefreshButton(coordinator, gateway_uuid))
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


class ABBWelcomeWifiDoorButton(ButtonEntity):
    """Generic door-open button for WiFi panels.

    Shown when no outdoor station has been discovered yet.  Once a call
    is received from the outdoor station, the config entry is updated
    with the discovered SIP URI and this button is replaced by a
    standard ABBWelcomeDoorButton.
    """

    _attr_icon = "mdi:door-open"
    _attr_has_entity_name = True
    _attr_name = "Abrir puerta"

    def __init__(self, sip_client, gateway_uuid: str, entry_id: str) -> None:
        self._sip_client = sip_client
        self._entry_id = entry_id
        self._attr_unique_id = f"{gateway_uuid}_wifi_door_open"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, gateway_uuid)},
            name="ABB Welcome Gateway",
            manufacturer="ABB / Busch-Jaeger",
            model="WiFi Panel 4.3\"",
        )

    async def async_press(self) -> None:
        """Try to unlock the door using any discovered station."""
        _LOGGER.warning(
            "[abb] WiFi door button pressed but no outdoor station discovered "
            "yet. Ring the doorbell first so the panel can learn the outdoor "
            "station SIP address, then press this button again."
        )
        raise HomeAssistantError(
            "Aún no se ha descubierto la estación exterior. Toca el timbre "
            "primero para que el panel aprenda la dirección SIP del portero, "
            "luego vuelve a pulsar este botón."
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

    def __init__(self, coordinator: ABBWelcomeCoordinator, gateway_uuid: str) -> None:
        self._coordinator = coordinator
        self._attr_unique_id = f"{gateway_uuid}_refresh_events"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, gateway_uuid)},
            name="ABB Welcome Gateway",
            manufacturer="ABB / Busch-Jaeger",
            model="IP Gateway (MRANGE)",
        )

    async def async_press(self) -> None:
        await self._coordinator.async_request_refresh()
