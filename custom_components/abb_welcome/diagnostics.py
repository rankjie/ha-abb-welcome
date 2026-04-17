"""Diagnostics support for ABB Welcome."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN

REDACT = "**REDACTED**"

SENSITIVE_KEYS = {
    "sip_password",
    "gateway_admin_password",
    "private_key_pem",
    "abb_password",
}


def _redact(data: dict, depth: int = 0) -> dict:
    out = {}
    for k, v in data.items():
        if k in SENSITIVE_KEYS:
            out[k] = REDACT
        elif isinstance(v, dict) and depth < 3:
            out[k] = _redact(v, depth + 1)
        elif isinstance(v, list):
            out[k] = v
        else:
            out[k] = v
    return out


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    data = dict(entry.data)
    options = dict(entry.options)

    # Certificate summary (not the full PEM)
    cert_pem = data.get("certificate_pem", "")
    cert_info = ""
    if cert_pem:
        lines = cert_pem.strip().splitlines()
        cert_info = f"{len(lines)} lines, {len(cert_pem)} bytes"

    coordinator = hass.data.get(DOMAIN, {}).get(entry.entry_id, {}).get("coordinator")
    coordinator_info = {}
    if coordinator:
        coordinator_info = {
            "has_certs": coordinator.has_certs,
            "events_cached": len(coordinator.data.events) if coordinator.data else 0,
            "latest_screenshot": bool(
                coordinator.data and coordinator.data.latest_screenshot
            ),
            "last_event_type": (
                coordinator.data.last_event.event_type
                if coordinator.data and coordinator.data.last_event
                else None
            ),
            "last_event_time": (
                coordinator.data.last_event.timestamp
                if coordinator.data and coordinator.data.last_event
                else None
            ),
        }

    return {
        "config_entry": {
            **_redact(data),
            "certificate_pem": cert_info,
        },
        "options": options,
        "coordinator": coordinator_info,
    }
