"""ABB Welcome integration — LAN door unlock via SIP."""

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import CONF_UNLOCK_STRATEGY, DEFAULT_UNLOCK_STRATEGY, DOMAIN
from .sip_client import SIPClient

_LOGGER = logging.getLogger(__name__)

# Force INFO-level logging for everything in this integration so users get a
# verbose pairing trace by default — no need to add a logger: block to
# configuration.yaml.  Users who want to silence it can override via the
# normal Home Assistant logger configuration.
for _name in (
    "custom_components.abb_welcome",
    "custom_components.abb_welcome.portal",
    "custom_components.abb_welcome.config_flow",
    "custom_components.abb_welcome.sip_client",
    "custom_components.abb_welcome.button",
):
    logging.getLogger(_name).setLevel(logging.INFO)

PLATFORMS = [Platform.BUTTON]


def _build_client(entry: ConfigEntry) -> SIPClient:
    return SIPClient(
        host=entry.data["gateway_ip"],
        username=entry.data["sip_username"],
        password=entry.data["sip_password"],
        domain=entry.data["sip_domain"],
        doors=entry.data.get("doors", []),
        unlock_strategy=entry.options.get(
            CONF_UNLOCK_STRATEGY, DEFAULT_UNLOCK_STRATEGY
        ),
    )


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up ABB Welcome from a config entry."""
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "sip_client": _build_client(entry),
    }
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Rebuild the SIP client when the user changes options."""
    hass.data[DOMAIN][entry.entry_id]["sip_client"] = _build_client(entry)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload ABB Welcome config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
