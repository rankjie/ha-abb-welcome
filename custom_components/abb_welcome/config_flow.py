"""Config flow for ABB Welcome integration."""

from __future__ import annotations

import logging
import socket

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback
from homeassistant.helpers import selector

from .const import (
    CONF_ABB_PASSWORD,
    CONF_ABB_USERNAME,
    CONF_GATEWAY_IP,
    CONF_UNLOCK_STRATEGY,
    DEFAULT_UNLOCK_STRATEGY,
    DOMAIN,
    SIP_PORT,
    UNLOCK_STRATEGIES,
)
from .portal import (
    GatewayAdminError,
    PortalError,
    compute_integrity_code,
    default_client_name,
    derive_identity,
    gateway_authorize,
    gateway_local_info,
    generate_keypair_and_csr,
    parse_acl_update,
    poll_acl_update,
    request_certificate,
    resolve_portal_url,
    send_connect_event,
)

_LOGGER = logging.getLogger(__name__)

CONF_GATEWAY_PASSWORD = "gateway_password"  # noqa: S105 (config-flow field name)

POLL_ATTEMPTS = 60
POLL_INTERVAL = 3.0

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_ABB_USERNAME): str,
        vol.Required(CONF_ABB_PASSWORD): selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
        ),
        vol.Required(CONF_GATEWAY_IP): str,
        vol.Required(CONF_GATEWAY_PASSWORD): selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
        ),
    }
)


def _gateway_reachable(host: str, port: int = SIP_PORT, timeout: float = 5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class ABBWelcomeConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the config flow for ABB Welcome."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> "ABBWelcomeOptionsFlow":
        return ABBWelcomeOptionsFlow(config_entry)

    def __init__(self) -> None:
        self._username = ""
        self._password = ""
        self._gateway_ip = ""
        self._gateway_password = ""
        self._portal_url = ""
        self._private_key_pem = b""
        self._cert_pem = b""
        self._client_name = ""
        self._sip_username = ""
        self._sip_password = ""
        self._sip_domain = ""
        self._own_uuid = ""
        self._gateway_uuid = ""
        self._gateway_name = ""
        self._gateway_sid = ""
        self._fingerprint = ""
        self._integrity_eight = ""
        self._integrity_display = ""
        self._doors: list[dict] = []

    async def _check_unique(self, gateway_uuid: str) -> ConfigFlowResult | None:
        await self.async_set_unique_id(gateway_uuid)
        self._abort_if_unique_id_configured()
        for entry in self._async_current_entries():
            if entry.data.get(CONF_GATEWAY_IP) == self._gateway_ip:
                return self.async_abort(reason="already_configured")
        return None

    async def async_step_user(
        self, user_input: dict | None = None
    ) -> ConfigFlowResult:
        """Single-step setup: collect credentials and run pairing end-to-end."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._username = user_input[CONF_ABB_USERNAME].strip()
            self._password = user_input[CONF_ABB_PASSWORD]
            self._gateway_ip = user_input[CONF_GATEWAY_IP].strip()
            self._gateway_password = user_input[CONF_GATEWAY_PASSWORD]

            reachable = await self.hass.async_add_executor_job(
                _gateway_reachable, self._gateway_ip, SIP_PORT
            )
            if not reachable:
                errors["base"] = "cannot_connect"
            else:
                try:
                    await self.hass.async_add_executor_job(self._do_pairing_setup)
                    await self.hass.async_add_executor_job(self._do_gateway_authorize)
                    return await self.async_step_poll_acl()
                except GatewayAdminError as err:
                    msg = str(err).lower()
                    if "login failed" in msg:
                        errors["base"] = "gateway_admin_auth_failed"
                    elif "no pending app" in msg:
                        errors["base"] = "no_pending_app"
                    elif "integrity code" in msg:
                        errors["base"] = "integrity_code_rejected"
                    else:
                        _LOGGER.error("Gateway admin error: %s", err)
                        errors["base"] = "gateway_admin_failed"
                except PortalError as err:
                    msg = str(err).lower()
                    if "401" in msg or "auth" in msg:
                        errors["base"] = "invalid_auth"
                    elif "no discovery" in msg or "gateway entry" in msg:
                        errors["base"] = "gateway_not_found"
                    else:
                        _LOGGER.error("Portal pairing error: %s", err)
                        errors["base"] = "unknown"
                except Exception as err:  # noqa: BLE001
                    _LOGGER.exception("Unexpected portal pairing error: %s", err)
                    errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )

    def _do_pairing_setup(self) -> None:
        """Synchronous helper for the portal-side setup steps."""
        self._client_name = default_client_name()
        priv_pem, csr_pem, _ = generate_keypair_and_csr(self._username)
        self._private_key_pem = priv_pem

        self._portal_url = resolve_portal_url(self._username)
        self._cert_pem = request_certificate(
            self._portal_url,
            self._username,
            self._password,
            csr_pem,
            self._client_name,
        )

        identity = derive_identity(self._cert_pem, self._username)
        self._sip_username = identity["sip_username"]
        self._fingerprint = identity["fingerprint_sha1"]
        self._own_uuid = identity["own_portal_uuid"]

        # Get the gateway UUID from the gateway itself — the portal's
        # discovery event has a race for brand-new identities.
        gw_info = gateway_local_info(self._gateway_ip, self._gateway_password)
        self._gateway_uuid = gw_info["uuid"]
        self._gateway_name = gw_info.get("portalname") or "ABB Welcome Gateway"

        self._integrity_eight, self._integrity_display = compute_integrity_code(
            self._fingerprint
        )
        send_connect_event(
            self._portal_url,
            self._cert_pem,
            self._private_key_pem,
            self._gateway_uuid,
            self._own_uuid,
            self._integrity_eight,
        )

    def _do_gateway_authorize(self) -> None:
        """Approve our pairing on the gateway via its admin CGI."""
        self._gateway_sid = gateway_authorize(
            self._gateway_ip,
            self._gateway_password,
            self._client_name,
            self._integrity_eight,
        )

    async def async_step_poll_acl(
        self, user_input: dict | None = None
    ) -> ConfigFlowResult:
        """Poll for the ACL-update event the gateway pushed after auto-approve."""
        try:
            payload = await self.hass.async_add_executor_job(
                poll_acl_update,
                self._portal_url,
                self._cert_pem,
                self._private_key_pem,
                self._own_uuid,
                POLL_ATTEMPTS,
                POLL_INTERVAL,
            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.exception("ACL polling error: %s", err)
            return self.async_abort(reason="unknown")

        if not payload:
            return self.async_abort(reason="acl_timeout")

        try:
            sip_password, sip_domain, doors_meta = await self.hass.async_add_executor_job(
                parse_acl_update, payload, self._private_key_pem
            )
        except PortalError as err:
            _LOGGER.error("ACL parse failed: %s", err)
            return self.async_abort(reason="acl_parse_failed")

        self._sip_password = sip_password
        self._sip_domain = sip_domain
        self._doors = [
            {
                "name": d["name"],
                "address": d["address"],
                "station_id": d["station_id"],
                "body": "1",
                "index": idx,
            }
            for idx, d in enumerate(doors_meta)
        ]

        abort = await self._check_unique(self._gateway_uuid)
        if abort is not None:
            return abort

        return await self.async_step_confirm()

    async def async_step_confirm(
        self, user_input: dict | None = None
    ) -> ConfigFlowResult:
        """Show discovered doors and create the entry."""
        if user_input is not None:
            return self.async_create_entry(
                title=f"ABB Welcome ({self._gateway_name})",
                data={
                    CONF_GATEWAY_IP: self._gateway_ip,
                    "sip_username": self._sip_username,
                    "sip_password": self._sip_password,
                    "sip_domain": self._sip_domain,
                    "doors": self._doors,
                    "gateway_uuid": self._gateway_uuid,
                    "own_portal_uuid": self._own_uuid,
                    "client_name": self._client_name,
                    "gateway_admin_password": self._gateway_password,
                    "private_key_pem": self._private_key_pem.decode(),
                    "certificate_pem": self._cert_pem.decode(),
                },
            )

        door_lines = "\n".join(
            f"- {d['name']} (sip:{d['station_id']}@{self._sip_domain})"
            for d in self._doors
        )
        return self.async_show_form(
            step_id="confirm",
            data_schema=vol.Schema({}),
            description_placeholders={
                "door_count": str(len(self._doors)),
                "door_names": door_lines,
                "sip_username": self._sip_username,
                "sip_domain": self._sip_domain,
            },
        )


class ABBWelcomeOptionsFlow(OptionsFlow):
    """Allow the user to change the unlock strategy after setup."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        self._entry = config_entry

    async def async_step_init(
        self, user_input: dict | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        current = self._entry.options.get(
            CONF_UNLOCK_STRATEGY, DEFAULT_UNLOCK_STRATEGY
        )
        schema = vol.Schema(
            {
                vol.Required(CONF_UNLOCK_STRATEGY, default=current): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=list(UNLOCK_STRATEGIES),
                        translation_key=CONF_UNLOCK_STRATEGY,
                        mode=selector.SelectSelectorMode.DROPDOWN,
                    )
                ),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
