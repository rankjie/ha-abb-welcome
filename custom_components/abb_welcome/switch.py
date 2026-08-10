"""Streaming and incoming-call pickup switches.

Streaming the ABB intercom is building-wide exclusive (see
:mod:`streaming_state`).  This switch gives the user explicit, visible
control over whether the camera stream is allowed to start.

* ``on``  → arm streaming for :data:`MANUAL_ARM_SECONDS` (auto-disarms)
* ``off`` → force-disarm; any active stream is torn down

``Streaming enabled`` also reflects auto-arm by the SIP listener (when
an inbound INVITE arrives and pickup is allowed), so the user always
sees "is streaming permitted right now?" at a glance.

``Allow pickup`` is independent.  Turning it off keeps ordinary manual
stream arming available, but incoming doorbell INVITEs will not auto-arm
or be accepted by a stream consumer.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_ALLOW_PICKUP, DEFAULT_ALLOW_PICKUP, DOMAIN
from .device import gateway_device_info
from .gateway_profile import GatewayProfile
from .streaming_state import (
    ARM_REASON_MANUAL,
    MANUAL_ARM_SECONDS,
    arm,
    disarm,
    get_state,
    is_pickup_allowed,
    signal_armed_changed,
    signal_pickup_allowed_changed,
    set_pickup_allowed,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    if not entry.data.get("doors"):
        return
    profile: GatewayProfile = hass.data[DOMAIN][entry.entry_id]["gateway_profile"]
    async_add_entities(
        [
            ABBStreamingArmedSwitch(hass, entry, profile),
            ABBAllowPickupSwitch(hass, entry, profile),
        ]
    )


class ABBStreamingArmedSwitch(SwitchEntity):
    """Per-gateway switch gating camera streaming."""

    _attr_has_entity_name = True
    _attr_name = "Streaming enabled"
    _attr_icon = "mdi:cctv"

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        profile: GatewayProfile,
    ) -> None:
        self.hass = hass
        self._entry = entry
        gateway_uuid = entry.data.get("gateway_uuid", "unknown")
        self._attr_unique_id = f"{gateway_uuid}_streaming_enabled"
        self._attr_device_info = gateway_device_info(gateway_uuid, profile)
        self._unsub: Callable[[], None] | None = None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._unsub = async_dispatcher_connect(
            self.hass,
            signal_armed_changed(self._entry.entry_id),
            self._on_changed,
        )

    async def async_will_remove_from_hass(self) -> None:
        if self._unsub is not None:
            self._unsub()
            self._unsub = None

    @callback
    def _on_changed(self) -> None:
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool:
        return get_state(self.hass, self._entry.entry_id).armed

    @property
    def extra_state_attributes(self) -> dict[str, str | int | float]:
        state = get_state(self.hass, self._entry.entry_id)
        return {
            "reason": state.reason,
            "target_station_id": state.target_station_id,
            "remaining_seconds": int(state.remaining_seconds()),
        }

    async def async_turn_on(self, **kwargs) -> None:
        arm(
            self.hass,
            self._entry.entry_id,
            reason=ARM_REASON_MANUAL,
            duration=MANUAL_ARM_SECONDS,
        )

    async def async_turn_off(self, **kwargs) -> None:
        disarm(self.hass, self._entry.entry_id)


class ABBAllowPickupSwitch(SwitchEntity):
    """Per-gateway switch allowing HA streams to accept incoming calls."""

    _attr_has_entity_name = True
    _attr_name = "Allow pickup"
    _attr_icon = "mdi:phone-incoming"

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        profile: GatewayProfile,
    ) -> None:
        self.hass = hass
        self._entry = entry
        gateway_uuid = entry.data.get("gateway_uuid", "unknown")
        self._attr_unique_id = f"{gateway_uuid}_allow_pickup"
        self._attr_device_info = gateway_device_info(gateway_uuid, profile)
        self._unsub: Callable[[], None] | None = None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        set_pickup_allowed(
            self.hass,
            self._entry.entry_id,
            self._entry.options.get(CONF_ALLOW_PICKUP, DEFAULT_ALLOW_PICKUP),
        )
        self._unsub = async_dispatcher_connect(
            self.hass,
            signal_pickup_allowed_changed(self._entry.entry_id),
            self._on_changed,
        )

    async def async_will_remove_from_hass(self) -> None:
        if self._unsub is not None:
            self._unsub()
            self._unsub = None

    @callback
    def _on_changed(self) -> None:
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool:
        return is_pickup_allowed(self.hass, self._entry.entry_id)

    async def async_turn_on(self, **kwargs) -> None:
        self._set_allowed(True)

    async def async_turn_off(self, **kwargs) -> None:
        self._set_allowed(False)

    def _set_allowed(self, allowed: bool) -> None:
        set_pickup_allowed(self.hass, self._entry.entry_id, allowed)
        if self._entry.options.get(CONF_ALLOW_PICKUP, DEFAULT_ALLOW_PICKUP) != allowed:
            self.hass.config_entries.async_update_entry(
                self._entry,
                options={
                    **dict(self._entry.options),
                    CONF_ALLOW_PICKUP: allowed,
                },
            )
        self.async_write_ha_state()
