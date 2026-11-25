"""Serve and register the Lovelace card bundled with the integration.

The static route is process-wide and Home Assistant does not expose an API to
remove it.  The Lovelace module URL is owned by the loaded ABB Welcome config
entries and is removed when the last owner unloads on cores that expose the
dynamic removal API.  Older supported cores keep the inert registration until
restart.

Registration is deliberately best-effort: frontend failures must never make
the intercom backend unavailable.  Failed steps keep enough state to be
retried without repeating steps that already completed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from homeassistant.components import frontend as ha_frontend

try:
    from homeassistant.components.http import StaticPathConfig
except ImportError:  # Home Assistant 2024.1-2024.6 compatibility
    StaticPathConfig = None  # type: ignore[assignment,misc]

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

DATA_FRONTEND = "abb_welcome_frontend"
FRONTEND_URL_BASE = "/abb_welcome/frontend"
CARD_FILENAME = "abb-welcome-intercom-card.js"

_FRONTEND_DIR = Path(__file__).parent / "frontend"


@dataclass
class _FrontendState:
    """Process-wide registration state shared by all config entries."""

    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    entry_ids: set[str] = field(default_factory=set)
    route_registered: bool = False
    url: str | None = None


def _state_for(hass: HomeAssistant) -> _FrontendState:
    """Return the frontend state without polluting ``hass.data[DOMAIN]``."""
    state = hass.data.get(DATA_FRONTEND)
    if isinstance(state, _FrontendState):
        return state

    state = _FrontendState()
    hass.data[DATA_FRONTEND] = state
    return state


def _manifest_version() -> str:
    """Read the integration version used to invalidate browser caches."""
    manifest = json.loads(
        (Path(__file__).parent / "manifest.json").read_text(encoding="utf-8")
    )
    return str(manifest.get("version", "0"))


def _frontend_version() -> str:
    """Return a human-readable content fingerprint for cache invalidation."""
    digest = hashlib.sha256((_FRONTEND_DIR / CARD_FILENAME).read_bytes())
    return f"{_manifest_version()}-{digest.hexdigest()[:8]}"


def card_url(version: str) -> str:
    """Return the versioned Lovelace module URL."""
    return f"{FRONTEND_URL_BASE}/{CARD_FILENAME}?v={version}"


async def _async_register_static_path(hass: HomeAssistant) -> None:
    """Register the asset directory on both modern and legacy HA cores."""
    modern_register = getattr(hass.http, "async_register_static_paths", None)
    if StaticPathConfig is not None and callable(modern_register):
        await modern_register(
            [StaticPathConfig(FRONTEND_URL_BASE, str(_FRONTEND_DIR), True)]
        )
        return

    legacy_register = getattr(hass.http, "register_static_path", None)
    if not callable(legacy_register):
        raise RuntimeError("Home Assistant HTTP static-path API is unavailable")  # noqa: TRY004 - unavailable runtime API, not a caller type error
    legacy_register(FRONTEND_URL_BASE, str(_FRONTEND_DIR), True)


async def async_register_frontend(hass: HomeAssistant, entry_id: str) -> bool:
    """Register one config entry as an owner of the bundled card.

    ``False`` reports a frontend-only failure to callers that want diagnostics;
    exceptions are contained so backend setup can continue.  A later setup of
    either the same or another entry retries the incomplete step.
    """
    state = _state_for(hass)

    async with state.lock:
        state.entry_ids.add(entry_id)
        if state.url is not None:
            return True

        try:
            version = await hass.async_add_executor_job(_frontend_version)
            url = card_url(version)

            if not state.route_registered:
                await _async_register_static_path(hass)
                state.route_registered = True

            ha_frontend.add_extra_js_url(hass, url)
        # Unreadable card or manifest (OSError, ValueError), a missing asset
        # directory (ValueError) or an unavailable static-path API
        # (RuntimeError). Anything else is a bug and fails the setup.
        except (OSError, ValueError, RuntimeError):
            _LOGGER.warning(
                "Unable to register the ABB Welcome Lovelace card; "
                "the backend integration will remain available",
                exc_info=True,
            )
            return False

        state.url = url
        _LOGGER.debug("Registered ABB Welcome Lovelace module at %s", url)
        return True


async def async_unregister_frontend(hass: HomeAssistant, entry_id: str) -> bool:
    """Release one config entry's ownership of the bundled card.

    The module URL is removed only after the final owner unloads.  The static
    route remains registered because Home Assistant has no route-unregister
    API.  Removal failures are best-effort and remain retryable.
    """
    state = hass.data.get(DATA_FRONTEND)
    if not isinstance(state, _FrontendState):
        return True

    async with state.lock:
        state.entry_ids.discard(entry_id)
        if state.entry_ids or state.url is None:
            return True

        remove_extra_js_url = getattr(ha_frontend, "remove_extra_js_url", None)
        if not callable(remove_extra_js_url):
            # HA 2024.1-2024.6 cannot dynamically remove an extra module URL.
            # Keep the process-wide registration so a later entry reload stays
            # idempotent; the inert asset route disappears on HA restart.
            _LOGGER.debug(
                "Home Assistant cannot dynamically unregister the ABB Welcome "
                "Lovelace module on this core version"
            )
            return True

        try:
            remove_extra_js_url(hass, state.url)
        except ValueError:  # the URL was already removed
            _LOGGER.warning(
                "Unable to unregister the ABB Welcome Lovelace card; "
                "backend unload will continue",
                exc_info=True,
            )
            return False

        _LOGGER.debug("Unregistered ABB Welcome Lovelace module at %s", state.url)
        state.url = None
        return True
