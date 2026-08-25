"""Shared Home Assistant device metadata for ABB Welcome entities."""

from __future__ import annotations

from collections.abc import Mapping

from homeassistant.helpers.device_registry import DeviceInfo

from .const import DOMAIN, gateway_capabilities


def gateway_device_info(data: Mapping[str, object]) -> DeviceInfo:
    """Build profile-aware metadata for the configured ABB device."""
    gateway_uuid = str(data.get("gateway_uuid", "unknown"))
    return DeviceInfo(
        identifiers={(DOMAIN, gateway_uuid)},
        name="ABB Welcome Gateway",
        manufacturer="ABB / Busch-Jaeger",
        model=gateway_capabilities(data).model,
    )
