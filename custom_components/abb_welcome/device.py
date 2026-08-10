"""Shared device metadata for all entities of a config entry."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo

from .const import DOMAIN
from .gateway_profile import GatewayProfile


def gateway_device_info(gateway_uuid: str, profile: GatewayProfile) -> DeviceInfo:
    """Build the single DeviceInfo shared by every gateway platform."""
    return DeviceInfo(
        identifiers={(DOMAIN, gateway_uuid)},
        name=profile.name,
        manufacturer=profile.manufacturer,
        model=profile.model,
    )
