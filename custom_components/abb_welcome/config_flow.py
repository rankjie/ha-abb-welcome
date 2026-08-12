"""Config flow for ABB Welcome integration."""

from __future__ import annotations

import re
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
from homeassistant.helpers.storage import Store

from .const import (
    CONF_ABB_PASSWORD,
    CONF_ABB_USERNAME,
    CONF_ALLOW_PICKUP,
    CONF_DEFAULT_UNLOCK_STATION_ID,
    CONF_GATEWAY_IP,
    CONF_GATEWAY_PASSWORD,
    CONF_GATEWAY_PROFILE,
    CONF_GATEWAY_UUID_OVERRIDE,
    CONF_LAN_RTSP_HOST,
    CONF_LAN_RTSP_PORT,
    CONF_TALKBACK_OUTPUT_GAIN_DB,
    CONF_UNLOCK_STRATEGY,
    DEFAULT_ALLOW_PICKUP,
    DEFAULT_LAN_RTSP_PORT,
    DOMAIN,
    GATEWAY_CAPABILITIES,
    GATEWAY_PROFILE_APP_MANAGED,
    GATEWAY_PROFILE_WEB_ADMIN,
    GATEWAY_PROFILES,
    MAX_TALKBACK_OUTPUT_GAIN_DB,
    MIN_TALKBACK_OUTPUT_GAIN_DB,
    UNLOCK_STRATEGIES,
    UNLOCK_STRATEGY_FAST,
    UNLOCK_STRATEGY_HYBRID,
    UNLOCK_STRATEGY_STANDARD,
    gateway_capabilities,
    gateway_profile,
    talkback_output_gain_db,
    unlockable_station_ids,
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
from .redaction import get_redacting_logger

_LOGGER = get_redacting_logger(__name__)
_LOG_PREFIX = "[abb] "


def _log_info(msg: str, *args: object) -> None:
    _LOGGER.info(_LOG_PREFIX + msg, *args)


def _log_error(msg: str, *args: object) -> None:
    _LOGGER.error(_LOG_PREFIX + msg, *args)


POLL_ATTEMPTS = 60
# Roughly five minutes for the user to complete the gateway UI flow.
POLL_ATTEMPTS_MANUAL = 100
POLL_INTERVAL = 3.0

PENDING_PAIRING_STORAGE_VERSION = 1
PENDING_PAIRING_SCHEMA_VERSION = 1
PENDING_PAIRING_STORAGE_KEY = f"{DOMAIN}.pending_app_managed_pairing"
PENDING_PAIRING_ACTION = "pending_pairing_action"
PENDING_PAIRING_ACTION_RESUME = "resume"
PENDING_PAIRING_ACTION_DISCARD = "discard"
PENDING_PAIRING_PHASE_AWAITING_ACL = "awaiting_acl"
PENDING_PAIRING_PHASE_ACL_RECEIVED = "acl_received"

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

STEP_PROFILE_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(
            CONF_GATEWAY_PROFILE, default=GATEWAY_PROFILE_WEB_ADMIN
        ): selector.SelectSelector(
            selector.SelectSelectorConfig(
                options=list(GATEWAY_PROFILES),
                translation_key=CONF_GATEWAY_PROFILE,
                mode=selector.SelectSelectorMode.DROPDOWN,
            )
        )
    }
)

STEP_WEB_ADMIN_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_ABB_USERNAME): str,
        vol.Required(CONF_ABB_PASSWORD): selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
        ),
        vol.Required(CONF_GATEWAY_IP): str,
        vol.Required(CONF_GATEWAY_PASSWORD): selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
        ),
        vol.Optional(CONF_GATEWAY_UUID_OVERRIDE, default=""): str,
    }
)

STEP_APP_MANAGED_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_ABB_USERNAME): str,
        vol.Required(CONF_ABB_PASSWORD): selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
        ),
        vol.Required(CONF_GATEWAY_IP): str,
        vol.Required(CONF_GATEWAY_UUID_OVERRIDE): str,
    }
)

STEP_PENDING_PAIRING_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(
            PENDING_PAIRING_ACTION, default=PENDING_PAIRING_ACTION_RESUME
        ): selector.SelectSelector(
            selector.SelectSelectorConfig(
                options=[
                    PENDING_PAIRING_ACTION_RESUME,
                    PENDING_PAIRING_ACTION_DISCARD,
                ],
                translation_key=PENDING_PAIRING_ACTION,
                mode=selector.SelectSelectorMode.DROPDOWN,
            )
        )
    }
)


def _gateway_port_reachable(host: str, port: int, timeout: float = 5) -> bool:
    """Return whether the profile-specific setup port is reachable."""
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
        self._gateway_uuid_override = ""
        self._gateway_name = ""
        self._gateway_sid = ""
        self._fingerprint = ""
        self._integrity_eight = ""
        self._integrity_display = ""
        self._doors: list[dict] = []
        self._manual_authorize = False
        self._authorize_error_msg = ""
        self._gateway_profile = GATEWAY_PROFILE_WEB_ADMIN
        self._acl_timed_out = False
        self._pending_pairing_checked = False
        self._pending_pairing: dict[str, object] | None = None
        self._pending_pairing_phase = PENDING_PAIRING_PHASE_AWAITING_ACL

    def _pending_store(self) -> Store[dict[str, object]]:
        """Return private storage for the single unfinished app pairing."""
        return Store(
            self.hass,
            PENDING_PAIRING_STORAGE_VERSION,
            PENDING_PAIRING_STORAGE_KEY,
            private=True,
        )

    @staticmethod
    def _valid_pending_pairing(data: object) -> bool:
        """Return whether persisted pending state has the expected shape."""
        if not isinstance(data, dict):
            return False
        required_strings = (
            "gateway_profile",
            "gateway_ip",
            "portal_url",
            "private_key_pem",
            "certificate_pem",
            "client_name",
            "sip_username",
            "own_portal_uuid",
            "gateway_uuid",
            "gateway_name",
            "integrity_eight",
            "integrity_display",
        )
        return (
            data.get("schema_version") == PENDING_PAIRING_SCHEMA_VERSION
            and data.get("gateway_profile") == GATEWAY_PROFILE_APP_MANAGED
            and all(
                isinstance(data.get(key), str) and data[key] for key in required_strings
            )
            and _UUID_RE.fullmatch(str(data["own_portal_uuid"])) is not None
            and _UUID_RE.fullmatch(str(data["gateway_uuid"])) is not None
            and data.get("phase")
            in {
                PENDING_PAIRING_PHASE_AWAITING_ACL,
                PENDING_PAIRING_PHASE_ACL_RECEIVED,
            }
            and (
                data.get("phase") != PENDING_PAIRING_PHASE_ACL_RECEIVED
                or (
                    isinstance(data.get("sip_password"), str)
                    and bool(data["sip_password"])
                    and isinstance(data.get("sip_domain"), str)
                    and bool(data["sip_domain"])
                    and isinstance(data.get("doors"), list)
                )
            )
        )

    def _pending_pairing_data(self) -> dict[str, object]:
        """Serialize only the identity and state needed to finish pairing."""
        data: dict[str, object] = {
            "schema_version": PENDING_PAIRING_SCHEMA_VERSION,
            "phase": self._pending_pairing_phase,
            "gateway_profile": self._gateway_profile,
            "gateway_ip": self._gateway_ip,
            "portal_url": self._portal_url,
            "private_key_pem": self._private_key_pem.decode(),
            "certificate_pem": self._cert_pem.decode(),
            "client_name": self._client_name,
            "sip_username": self._sip_username,
            "own_portal_uuid": self._own_uuid,
            "gateway_uuid": self._gateway_uuid,
            "gateway_name": self._gateway_name,
            "integrity_eight": self._integrity_eight,
            "integrity_display": self._integrity_display,
        }
        if self._pending_pairing_phase == PENDING_PAIRING_PHASE_ACL_RECEIVED:
            data.update(
                {
                    "sip_password": self._sip_password,
                    "sip_domain": self._sip_domain,
                    "doors": self._doors,
                }
            )
        return data

    def _restore_pending_pairing(self, data: dict[str, object]) -> None:
        """Restore an unfinished app-managed pairing into this flow."""
        self._gateway_profile = str(data["gateway_profile"])
        self._gateway_ip = str(data["gateway_ip"])
        self._portal_url = str(data["portal_url"])
        self._private_key_pem = str(data["private_key_pem"]).encode()
        self._cert_pem = str(data["certificate_pem"]).encode()
        self._client_name = str(data["client_name"])
        self._sip_username = str(data["sip_username"])
        self._own_uuid = str(data["own_portal_uuid"])
        self._gateway_uuid = str(data["gateway_uuid"])
        self._gateway_uuid_override = self._gateway_uuid
        self._gateway_name = str(data["gateway_name"])
        self._integrity_eight = str(data["integrity_eight"])
        self._integrity_display = str(data["integrity_display"])
        self._pending_pairing_phase = str(data["phase"])
        if self._pending_pairing_phase == PENDING_PAIRING_PHASE_ACL_RECEIVED:
            self._sip_password = str(data["sip_password"])
            self._sip_domain = str(data["sip_domain"])
            self._doors = list(data["doors"])
        self._manual_authorize = True

    async def _async_find_pending_pairing(self) -> ConfigFlowResult | None:
        """Offer recovery before accepting credentials for a new identity."""
        if self._gateway_profile == GATEWAY_PROFILE_WEB_ADMIN:
            return None
        if self._pending_pairing_checked:
            return None
        self._pending_pairing_checked = True
        try:
            pending = await self._pending_store().async_load()
        except Exception:  # noqa: BLE001
            _log_error("Could not load pending pairing state (details redacted)")
            return await self.async_step_pending_pairing_invalid()
        if pending is None:
            return None
        if not self._valid_pending_pairing(pending):
            _log_error("Pending pairing state is invalid (contents redacted)")
            return await self.async_step_pending_pairing_invalid()
        self._pending_pairing = pending
        return await self.async_step_pending_pairing()

    async def _async_save_pending_pairing(self) -> None:
        """Persist a sent app-managed request before asking for approval."""
        pending = self._pending_pairing_data()
        await self._pending_store().async_save(pending)
        self._pending_pairing = pending

    async def _async_clear_pending_pairing(self) -> None:
        """Remove recovery state after success or explicit confirmation."""
        await self._pending_store().async_remove()
        self._pending_pairing = None

    async def _check_unique(self, gateway_uuid: str) -> ConfigFlowResult | None:
        await self.async_set_unique_id(gateway_uuid)
        self._abort_if_unique_id_configured()
        for entry in self._async_current_entries():
            if entry.data.get(CONF_GATEWAY_IP) == self._gateway_ip:
                return self.async_abort(reason="already_configured")
        return None

    async def async_step_user(self, user_input: dict | None = None) -> ConfigFlowResult:
        """Select the gateway family before collecting credentials."""
        if user_input is not None:
            profile = str(user_input[CONF_GATEWAY_PROFILE])
            if profile not in GATEWAY_CAPABILITIES:
                return self.async_show_form(
                    step_id="user",
                    data_schema=STEP_PROFILE_DATA_SCHEMA,
                    errors={"base": "invalid_profile"},
                )
            self._gateway_profile = profile
            return await self.async_step_credentials()

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_PROFILE_DATA_SCHEMA,
        )

    async def async_step_credentials(
        self, user_input: dict | None = None
    ) -> ConfigFlowResult:
        """Collect profile-specific credentials and start pairing."""
        errors: dict[str, str] = {}
        capabilities = GATEWAY_CAPABILITIES[self._gateway_profile]

        pending_result = await self._async_find_pending_pairing()
        if pending_result is not None:
            return pending_result

        if user_input is not None:
            self._username = user_input[CONF_ABB_USERNAME].strip()
            self._password = user_input[CONF_ABB_PASSWORD]
            self._gateway_ip = user_input[CONF_GATEWAY_IP].strip()
            self._gateway_password = user_input.get(CONF_GATEWAY_PASSWORD, "")
            uuid_raw = user_input.get(CONF_GATEWAY_UUID_OVERRIDE, "").strip().lower()
            if not capabilities.admin_available and not uuid_raw:
                errors[CONF_GATEWAY_UUID_OVERRIDE] = "uuid_required"
            elif uuid_raw and not _UUID_RE.fullmatch(uuid_raw):
                errors[CONF_GATEWAY_UUID_OVERRIDE] = "invalid_uuid"
            self._gateway_uuid_override = uuid_raw

            if not errors and not capabilities.admin_available:
                self._gateway_uuid = uuid_raw
                abort = await self._check_unique(uuid_raw)
                if abort is not None:
                    return abort

            if not errors:
                reachable = await self.hass.async_add_executor_job(
                    _gateway_port_reachable,
                    self._gateway_ip,
                    capabilities.probe_port,
                )
                if not reachable:
                    errors["base"] = (
                        "sip_tls_unavailable"
                        if not capabilities.admin_available
                        else "cannot_connect"
                    )

            if not errors:
                # Phase 1: portal-side setup + send connect event to gateway.
                # Errors here are unrecoverable (we never put a pending request
                # on the gateway), so they go straight back to the form.
                try:
                    await self.hass.async_add_executor_job(self._do_pairing_setup)
                except GatewayAdminError as err:
                    msg = str(err).lower()
                    if "login failed" in msg:
                        errors["base"] = "gateway_admin_auth_failed"
                    elif "missing uuid" in msg or "op=6" in msg:
                        # Local op=6 lookup failed and user didn't supply an
                        # override. Tell them how to recover.
                        errors["base"] = "gateway_op6_failed"
                    else:
                        _log_error(
                            "Gateway admin error during setup (details redacted)"
                        )
                        errors["base"] = "gateway_admin_failed"
                except PortalError as err:
                    msg = str(err).lower()
                    if "401" in msg or "auth" in msg:
                        errors["base"] = "invalid_auth"
                    elif "no discovery" in msg or "gateway entry" in msg:
                        errors["base"] = "gateway_not_found"
                    else:
                        _log_error("Portal pairing error (details redacted)")
                        errors["base"] = "unknown"
                except Exception:  # noqa: BLE001
                    _LOGGER.error("Unexpected portal setup error (details redacted)")
                    errors["base"] = "unknown"
                else:
                    if capabilities.approval_method == "automatic_acl":
                        try:
                            await self._async_save_pending_pairing()
                        except Exception:  # noqa: BLE001
                            _log_error(
                                "Could not persist pending pairing state "
                                "(details redacted)"
                            )
                            return self.async_abort(reason="pending_storage_failed")
                        return await self.async_step_poll_acl()
                    # Phase 2: auto-approve on the gateway. By this point the
                    # connect event was successfully sent, so the gateway has
                    # a pending request — recoverable via the manual UI even
                    # if our CGI calls fail.
                    try:
                        await self.hass.async_add_executor_job(
                            self._do_gateway_authorize
                        )
                    except GatewayAdminError as err:
                        msg = str(err).lower()
                        if "login failed" in msg:
                            # Wrong admin password — manual flow can't recover.
                            errors["base"] = "gateway_admin_auth_failed"
                        else:
                            _log_info(
                                "Auto-approve failed (details redacted); offering "
                                "manual approval via the gateway web UI"
                            )
                            self._manual_authorize = True
                            self._authorize_error_msg = (
                                "Gateway CGI approval failed; details are redacted"
                            )
                            return await self.async_step_manual_authorize()
                    except Exception:  # noqa: BLE001
                        _LOGGER.error(
                            "Unexpected error during auto-approve (details redacted)"
                        )
                        errors["base"] = "unknown"
                    else:
                        return await self.async_step_poll_acl()

        return self.async_show_form(
            step_id="credentials",
            data_schema=(
                STEP_APP_MANAGED_DATA_SCHEMA
                if not capabilities.admin_available
                else STEP_WEB_ADMIN_DATA_SCHEMA
            ),
            errors=errors,
            description_placeholders={"profile": self._gateway_profile},
        )

    async def async_step_pending_pairing(
        self, user_input: dict | None = None
    ) -> ConfigFlowResult:
        """Resume or explicitly discard a persisted app-managed identity."""
        if user_input is not None:
            action = str(user_input[PENDING_PAIRING_ACTION])
            if action == PENDING_PAIRING_ACTION_DISCARD:
                return await self.async_step_discard_pending_pairing()
            if action == PENDING_PAIRING_ACTION_RESUME:
                if self._pending_pairing is None:
                    return await self.async_step_pending_pairing_invalid()
                self._restore_pending_pairing(self._pending_pairing)
                abort = await self._check_unique(self._gateway_uuid)
                if abort is not None:
                    return abort
                if self._pending_pairing_phase == PENDING_PAIRING_PHASE_ACL_RECEIVED:
                    return await self.async_step_confirm()
                return await self.async_step_poll_acl()

        pending = self._pending_pairing or {}
        return self.async_show_form(
            step_id="pending_pairing",
            data_schema=STEP_PENDING_PAIRING_DATA_SCHEMA,
            description_placeholders={
                "client_name": str(pending.get("client_name", "")),
                "integrity_code": str(pending.get("integrity_display", "")),
            },
        )

    async def async_step_discard_pending_pairing(
        self, user_input: dict | None = None
    ) -> ConfigFlowResult:
        """Require confirmation before forgetting a recoverable identity."""
        if user_input is not None:
            try:
                await self._async_clear_pending_pairing()
            except Exception:  # noqa: BLE001
                _log_error("Could not discard pending pairing state")
                return self.async_abort(reason="pending_storage_failed")
            self._pending_pairing_checked = True
            return await self.async_step_credentials()
        return self.async_show_form(
            step_id="discard_pending_pairing",
            data_schema=vol.Schema({}),
        )

    async def async_step_pending_pairing_invalid(
        self, user_input: dict | None = None
    ) -> ConfigFlowResult:
        """Safely handle unreadable or incompatible recovery state."""
        if user_input is not None:
            try:
                await self._async_clear_pending_pairing()
            except Exception:  # noqa: BLE001
                _log_error("Could not reset invalid pending pairing state")
                return self.async_abort(reason="pending_storage_failed")
            self._pending_pairing_checked = True
            return await self.async_step_credentials()
        return self.async_show_form(
            step_id="pending_pairing_invalid",
            data_schema=vol.Schema({}),
        )

    def _do_pairing_setup(self) -> None:
        """Synchronous helper for the portal-side setup steps."""
        capabilities = GATEWAY_CAPABILITIES[self._gateway_profile]
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
        # discovery event has a race for brand-new identities. If the user
        # supplied an override (some firmware revisions have a broken
        # portalclient.cgi op=6 — see GitHub issue #1), skip the local
        # lookup entirely and trust the value they pasted in.
        if not capabilities.admin_available:
            self._gateway_uuid = self._gateway_uuid_override
            self._gateway_name = "M2240x / ASI22"
        elif self._gateway_uuid_override:
            self._gateway_uuid = self._gateway_uuid_override
            self._gateway_name = "ABB Welcome Gateway"
        else:
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

    async def async_step_manual_authorize(
        self, user_input: dict | None = None
    ) -> ConfigFlowResult:
        """Show manual-approval instructions when auto-approve fails.

        The pairing request is already on the gateway (the portal connect
        event went through), so the user can finish the approval via the
        gateway's own web UI.
        """
        if user_input is not None:
            return await self.async_step_poll_acl()

        return self.async_show_form(
            step_id="manual_authorize",
            data_schema=vol.Schema({}),
            description_placeholders={
                "gateway_ip": self._gateway_ip,
                "client_name": self._client_name,
                "integrity_code": self._integrity_display,
                "error_detail": self._authorize_error_msg or "(no details)",
            },
        )

    async def async_step_app_authorize(
        self, user_input: dict | None = None
    ) -> ConfigFlowResult:
        """Offer another ACL poll after automatic app pairing timed out."""
        if user_input is not None:
            self._acl_timed_out = False
            return await self.async_step_poll_acl()

        return self.async_show_form(
            step_id="app_authorize",
            data_schema=vol.Schema({}),
            errors={"base": "acl_timeout_retry"} if self._acl_timed_out else {},
            description_placeholders={
                "client_name": self._client_name,
                "integrity_code": self._integrity_display,
            },
        )

    async def async_step_poll_acl(
        self, user_input: dict | None = None
    ) -> ConfigFlowResult:
        """Poll for the ACL update produced by pairing."""
        attempts = POLL_ATTEMPTS_MANUAL if self._manual_authorize else POLL_ATTEMPTS
        try:
            payload = await self.hass.async_add_executor_job(
                poll_acl_update,
                self._portal_url,
                self._cert_pem,
                self._private_key_pem,
                self._own_uuid,
                attempts,
                POLL_INTERVAL,
            )
        except Exception:  # noqa: BLE001
            _LOGGER.error("ACL polling error (details redacted)")
            return self.async_abort(reason="unknown")

        if not payload:
            capabilities = GATEWAY_CAPABILITIES[self._gateway_profile]
            if capabilities.approval_method == "automatic_acl":
                self._acl_timed_out = True
                return await self.async_step_app_authorize()
            return self.async_abort(reason="acl_timeout")

        try:
            (
                sip_password,
                sip_domain,
                doors_meta,
            ) = await self.hass.async_add_executor_job(
                parse_acl_update, payload, self._private_key_pem
            )
        except PortalError:
            _log_error("ACL parse failed (details redacted)")
            return self.async_abort(reason="acl_parse_failed")

        self._sip_password = sip_password
        self._sip_domain = sip_domain
        self._doors = []
        for idx, d in enumerate(doors_meta):
            door = {
                "name": d["name"],
                "address": d["address"],
                "station_id": d["station_id"],
                "body": "1",
                "index": idx,
            }
            if d.get("local_id"):
                door["local_id"] = d["local_id"]
            if d.get("type"):
                door["type"] = d["type"]
            if d.get("can_unlock") is False:
                door["can_unlock"] = False
            self._doors.append(door)

        capabilities = GATEWAY_CAPABILITIES[self._gateway_profile]
        if capabilities.approval_method == "automatic_acl":
            self._pending_pairing_phase = PENDING_PAIRING_PHASE_ACL_RECEIVED
            try:
                await self._async_save_pending_pairing()
            except Exception:  # noqa: BLE001
                _log_error(
                    "Could not persist completed ACL pairing state (details redacted)"
                )
                return self.async_abort(reason="pending_storage_failed")

        abort = await self._check_unique(self._gateway_uuid)
        if abort is not None:
            return abort

        return await self.async_step_confirm()

    async def async_step_confirm(
        self, user_input: dict | None = None
    ) -> ConfigFlowResult:
        """Show discovered doors and create the entry."""
        if user_input is not None:
            entry_data = {
                CONF_GATEWAY_PROFILE: self._gateway_profile,
                CONF_GATEWAY_IP: self._gateway_ip,
                "sip_username": self._sip_username,
                "sip_password": self._sip_password,
                "sip_domain": self._sip_domain,
                "doors": self._doors,
                "gateway_uuid": self._gateway_uuid,
                "own_portal_uuid": self._own_uuid,
                "client_name": self._client_name,
                "portal_url": self._portal_url,
                "private_key_pem": self._private_key_pem.decode(),
                "certificate_pem": self._cert_pem.decode(),
            }
            capabilities = GATEWAY_CAPABILITIES[self._gateway_profile]
            if capabilities.admin_available:
                entry_data["gateway_admin_password"] = self._gateway_password
            result = self.async_create_entry(
                title=f"ABB Welcome ({self._gateway_name})",
                data=entry_data,
            )
            if not capabilities.admin_available:
                try:
                    await self._async_clear_pending_pairing()
                except Exception:  # noqa: BLE001
                    _log_error(
                        "Entry was prepared but pending pairing state could not be "
                        "cleared"
                    )
                    return self.async_abort(reason="pending_storage_failed")
            return result

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

    async def async_step_init(self, user_input: dict | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        is_app_managed = (
            gateway_profile(self._entry.data) == GATEWAY_PROFILE_APP_MANAGED
        )
        station_ids = unlockable_station_ids(self._entry.data.get("doors"))
        station_id_set = set(station_ids)
        multiple_app_doors = is_app_managed and len(station_ids) > 1
        submitted: dict | None = None

        if user_input is not None:
            data = dict(user_input)
            submitted = data
            strategy = str(data.get(CONF_UNLOCK_STRATEGY, ""))
            selected_station = str(data.get(CONF_DEFAULT_UNLOCK_STATION_ID, "")).strip()
            if multiple_app_doors and strategy == UNLOCK_STRATEGY_FAST:
                errors["base"] = "fast_multi_door_unsupported"
            if (
                is_app_managed
                and strategy == UNLOCK_STRATEGY_HYBRID
                and selected_station not in station_id_set
            ):
                errors[CONF_DEFAULT_UNLOCK_STATION_ID] = (
                    "invalid_default_unlock_station"
                )
            if not is_app_managed or selected_station not in station_id_set:
                data.pop(CONF_DEFAULT_UNLOCK_STATION_ID, None)
            data[CONF_LAN_RTSP_HOST] = str(data.get(CONF_LAN_RTSP_HOST) or "").strip()
            data[CONF_LAN_RTSP_PORT] = int(
                data.get(CONF_LAN_RTSP_PORT) or DEFAULT_LAN_RTSP_PORT
            )
            if not errors:
                return self.async_create_entry(title="", data=data)

        current = (
            submitted.get(CONF_UNLOCK_STRATEGY)
            if submitted is not None
            else self._entry.options.get(
                CONF_UNLOCK_STRATEGY,
                gateway_capabilities(self._entry.data).default_unlock_strategy,
            )
        )
        if multiple_app_doors and current == UNLOCK_STRATEGY_FAST:
            current = UNLOCK_STRATEGY_STANDARD
        strategy_options = list(UNLOCK_STRATEGIES)
        if multiple_app_doors:
            strategy_options.remove(UNLOCK_STRATEGY_FAST)
        current_default_station = str(
            submitted.get(CONF_DEFAULT_UNLOCK_STATION_ID, "")
            if submitted is not None
            else self._entry.options.get(CONF_DEFAULT_UNLOCK_STATION_ID, "")
        ).strip()
        if current_default_station not in station_id_set:
            current_default_station = ""
        current_rtsp_host = (
            submitted.get(CONF_LAN_RTSP_HOST, "")
            if submitted is not None
            else self._entry.options.get(CONF_LAN_RTSP_HOST, "")
        )
        current_rtsp_port = int(
            (
                submitted.get(CONF_LAN_RTSP_PORT, DEFAULT_LAN_RTSP_PORT)
                if submitted is not None
                else self._entry.options.get(CONF_LAN_RTSP_PORT, DEFAULT_LAN_RTSP_PORT)
            )
            or DEFAULT_LAN_RTSP_PORT
        )
        current_allow_pickup = bool(
            submitted.get(CONF_ALLOW_PICKUP, DEFAULT_ALLOW_PICKUP)
            if submitted is not None
            else self._entry.options.get(CONF_ALLOW_PICKUP, DEFAULT_ALLOW_PICKUP)
        )
        current_talkback_output_gain_db = float(
            submitted.get(
                CONF_TALKBACK_OUTPUT_GAIN_DB,
                talkback_output_gain_db(self._entry.data, self._entry.options),
            )
            if submitted is not None
            else talkback_output_gain_db(self._entry.data, self._entry.options)
        )
        schema_fields = {
            vol.Required(
                CONF_UNLOCK_STRATEGY, default=current
            ): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=strategy_options,
                    translation_key=CONF_UNLOCK_STRATEGY,
                    mode=selector.SelectSelectorMode.DROPDOWN,
                )
            ),
            vol.Optional(
                CONF_LAN_RTSP_HOST, default=current_rtsp_host
            ): selector.TextSelector(),
            vol.Required(CONF_LAN_RTSP_PORT, default=current_rtsp_port): vol.All(
                vol.Coerce(int), vol.Range(min=1024, max=65535)
            ),
            vol.Required(
                CONF_ALLOW_PICKUP, default=current_allow_pickup
            ): selector.BooleanSelector(),
            vol.Required(
                CONF_TALKBACK_OUTPUT_GAIN_DB,
                default=current_talkback_output_gain_db,
            ): vol.All(
                vol.Coerce(float),
                vol.Range(
                    min=MIN_TALKBACK_OUTPUT_GAIN_DB,
                    max=MAX_TALKBACK_OUTPUT_GAIN_DB,
                ),
            ),
        }
        if is_app_managed and station_ids:
            door_names = {
                str(door.get("station_id", "")).strip(): str(
                    door.get("name") or door.get("station_id") or "Door"
                )
                for door in self._entry.data.get("doors", [])
                if isinstance(door, dict)
            }
            station_selector = selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=[
                        {
                            "value": station_id,
                            "label": door_names.get(station_id, "Door"),
                        }
                        for station_id in station_ids
                    ],
                    mode=selector.SelectSelectorMode.DROPDOWN,
                )
            )
            if current_default_station:
                schema_fields[
                    vol.Optional(
                        CONF_DEFAULT_UNLOCK_STATION_ID,
                        default=current_default_station,
                    )
                ] = station_selector
            else:
                schema_fields[vol.Optional(CONF_DEFAULT_UNLOCK_STATION_ID)] = (
                    station_selector
                )
        schema = vol.Schema(schema_fields)
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
