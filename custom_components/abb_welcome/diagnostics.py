"""Diagnostics support for ABB Welcome."""

from __future__ import annotations

import re
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN

REDACT = "**REDACTED**"

SENSITIVE_KEYS = {
    "abb_password",
    "abb_username",
    "address",
    "authorization",
    "belongs_to",
    "body",
    "certificate",
    "certificate_pem",
    "client-certificate",
    "client-csr",
    "client_name",
    "cookie",
    "destination",
    "default_unlock_station_id",
    "door_id",
    "event_id",
    "gateway_admin_password",
    "gateway_ip",
    "gateway_password",
    "gateway_uuid",
    "local_id",
    "local_name",
    "name",
    "own_portal_uuid",
    "payload",
    "private_key_pem",
    "sender",
    "set-cookie",
    "sip_domain",
    "sip_password",
    "sip_username",
    "source",
    "station",
    "station_id",
    "station_name",
}

_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(
    r"\[(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\]"
    r"|(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)
_PEM_RE = re.compile(
    r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL
)


def _redact(data: Any, key: str | None = None) -> Any:
    """Recursively redact secrets and private installation identifiers."""
    if key is not None and key.lower() in SENSITIVE_KEYS:
        return REDACT
    if isinstance(data, dict):
        return {str(k): _redact(v, str(k)) for k, v in data.items()}
    if isinstance(data, list):
        return [_redact(value) for value in data]
    if isinstance(data, tuple):
        return tuple(_redact(value) for value in data)
    if isinstance(data, str):
        value = _PEM_RE.sub(REDACT, data)
        value = _UUID_RE.sub(REDACT, value)
        value = _IPV4_RE.sub(REDACT, value)
        return _IPV6_RE.sub(REDACT, value)
    return data


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
        "options": _redact(options),
        "coordinator": coordinator_info,
    }
