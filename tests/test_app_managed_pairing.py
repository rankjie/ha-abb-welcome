"""Config-flow pairing tests with Home Assistant imports stubbed."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import re
import sys
import types
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


def _install_stubs() -> None:
    vol = types.ModuleType("voluptuous")

    class _SchemaKey(str):
        def __new__(cls, value, default=None):
            instance = str.__new__(cls, value)
            instance.default = default
            return instance

    vol.Schema = lambda value: value
    vol.Required = lambda key, **kwargs: _SchemaKey(
        key, kwargs.get("default")
    )
    vol.Optional = lambda key, **kwargs: _SchemaKey(
        key, kwargs.get("default")
    )
    vol.All = lambda *values: values[0]
    vol.Coerce = lambda value: value
    vol.Range = lambda **kwargs: object()
    sys.modules["voluptuous"] = vol

    homeassistant = types.ModuleType("homeassistant")
    config_entries = types.ModuleType("homeassistant.config_entries")

    class ConfigEntry:
        pass

    class ConfigFlow:
        def __init_subclass__(cls, **kwargs):
            return super().__init_subclass__()

        def async_create_entry(self, *, title, data):
            return {"type": "create_entry", "title": title, "data": data}

        def async_show_form(self, **kwargs):
            return {"type": "form", **kwargs}

        def add_suggested_values_to_schema(self, data_schema, suggested_values):
            self.__dict__["suggested_values"] = dict(suggested_values)
            return data_schema

        def async_show_progress(self, **kwargs):
            return {"type": "progress", "flow": self, **kwargs}

        def async_show_progress_done(self, *, next_step_id):
            return {"type": "progress_done", "flow": self, "step_id": next_step_id}

        def async_update_progress(self, progress):
            self.__dict__.setdefault("progress_updates", []).append(progress)

        def async_notify_flow_changed(self):
            self.__dict__["flow_changes"] = self.__dict__.get("flow_changes", 0) + 1

        def async_abort(self, **kwargs):
            return {"type": "abort", **kwargs}

        async def async_set_unique_id(self, unique_id):
            self.unique_id = unique_id

        def _abort_if_unique_id_configured(self):
            return None

        def _async_current_entries(self):
            return []

    class OptionsFlow:
        def async_create_entry(self, *, title, data):
            return {"type": "create_entry", "title": title, "data": data}

        def async_show_form(self, **kwargs):
            return {"type": "form", **kwargs}

    config_entries.ConfigEntry = ConfigEntry
    config_entries.ConfigFlow = ConfigFlow
    config_entries.ConfigFlowResult = dict
    config_entries.OptionsFlow = OptionsFlow

    const = types.ModuleType("homeassistant.const")
    const.__version__ = "2099.1.0"

    core = types.ModuleType("homeassistant.core")
    core.callback = lambda function: function

    helpers = types.ModuleType("homeassistant.helpers")
    selector = types.ModuleType("homeassistant.helpers.selector")
    storage = types.ModuleType("homeassistant.helpers.storage")

    class _Selector:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    class _Config:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    selector.TextSelector = _Selector
    selector.SelectSelector = _Selector
    selector.BooleanSelector = _Selector
    selector.TextSelectorConfig = _Config
    selector.SelectSelectorConfig = _Config
    selector.TextSelectorType = types.SimpleNamespace(PASSWORD="password")
    selector.SelectSelectorMode = types.SimpleNamespace(DROPDOWN="dropdown")
    helpers.selector = selector

    class Store:
        def __init__(self, hass, version, key, *, private=False):
            self.hass = hass
            self.key = key
            self.private = private

        async def async_load(self):
            return self.hass.storage.get(self.key)

        async def async_save(self, data):
            self.hass.storage[self.key] = data

        async def async_remove(self):
            self.hass.storage.pop(self.key, None)

    storage.Store = Store

    sys.modules["homeassistant"] = homeassistant
    sys.modules["homeassistant.config_entries"] = config_entries
    sys.modules["homeassistant.const"] = const
    sys.modules["homeassistant.core"] = core
    sys.modules["homeassistant.helpers"] = helpers
    sys.modules["homeassistant.helpers.selector"] = selector
    sys.modules["homeassistant.helpers.storage"] = storage


def _load_config_flow():
    _install_stubs()
    package = types.ModuleType("abb_pairing_test")
    package.__path__ = [str(_PKG_DIR)]
    sys.modules["abb_pairing_test"] = package
    for name in ("const", "redaction", "text", "portal", "pairing_report", "config_flow"):
        full_name = f"abb_pairing_test.{name}"
        spec = importlib.util.spec_from_file_location(
            full_name, _PKG_DIR / f"{name}.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[full_name] = module
        spec.loader.exec_module(module)
    return sys.modules["abb_pairing_test.config_flow"]


class _FakeHass:
    def __init__(self, storage=None):
        self.storage = storage if storage is not None else {}

    @property
    def loop(self):
        return asyncio.get_running_loop()

    def async_create_task(self, coroutine):
        return asyncio.get_running_loop().create_task(coroutine)

    async def async_add_executor_job(self, function, *args):
        return function(*args)


def _run(step):
    """Run a flow step, following progress steps like the flow manager."""

    async def _drive():
        result = await step
        while isinstance(result, dict) and result.get("type") in (
            "progress",
            "progress_done",
        ):
            flow = result["flow"]
            if result["type"] == "progress":
                await asyncio.wait({result["progress_task"]})
            result = await getattr(flow, f"async_step_{result['step_id']}")()
        return result

    return asyncio.run(_drive())


@pytest.mark.parametrize("profile", ["web_admin", "app_managed"])
@pytest.mark.parametrize(
    ("supplied", "expected"),
    [
        ("synthetic.user@example.invalid", "synthetic.user@example.invalid"),
        ("Synthetic.User@Example.Invalid", "synthetic.user@example.invalid"),
        ("  Synthetic.User@Example.Invalid  ", "synthetic.user@example.invalid"),
    ],
)
def test_certificate_request_normalizes_username_only(profile, supplied, expected):
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = profile
    module._gateway_port_reachable = lambda *_args: True
    module.generate_keypair_and_csr = lambda *_args: (b"synthetic-key", b"csr", None)
    module.resolve_portal_url = lambda *_args: "https://portal.example.invalid"
    observed = []

    def request_certificate(_url, username, password, *_args):
        observed.append((username, password))
        raise module.PortalError("HTTP 401")

    module.request_certificate = request_certificate
    result = _run(flow.async_step_credentials({
        module.CONF_ABB_USERNAME: supplied,
        module.CONF_ABB_PASSWORD: "  Synthetic-Password  ",
        module.CONF_GATEWAY_IP: "192.0.2.10",
        module.CONF_GATEWAY_UUID_OVERRIDE: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    }))

    assert observed == [(expected, "  Synthetic-Password  ")]
    assert result["errors"]["base"] == "invalid_auth"


def _seed_pending_pairing(module, hass):
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = hass
    flow._gateway_profile = module.GATEWAY_PROFILES[1]
    flow._gateway_ip = "192.0.2.10"
    flow._portal_url = "https://api.example.invalid"
    flow._private_key_pem = b"private-key"
    flow._cert_pem = b"certificate"
    flow._client_name = "ha-test"
    flow._sip_username = "sip-user"
    flow._own_uuid = "11111111-1111-4111-8111-111111111111"
    flow._gateway_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    flow._gateway_name = "M2240x / ASI22"
    flow._integrity_eight = "1234ABCD"
    flow._integrity_display = "1234 ABCD"
    flow._password = "portal-password-must-not-be-stored"
    flow._gateway_password = "admin-password-must-not-be-stored"
    _run(flow._async_save_pending_pairing())
    return flow


def test_pending_pairing_survives_new_flow_without_new_connect() -> None:
    module = _load_config_flow()
    backing_store = {}
    _seed_pending_pairing(module, _FakeHass(backing_store))

    stored = backing_store[module.PENDING_PAIRING_STORAGE_KEY]
    assert "portal-password-must-not-be-stored" not in repr(stored)
    assert "admin-password-must-not-be-stored" not in repr(stored)

    calls = {"connect": 0, "certificate": 0, "poll": 0}
    module.send_connect_event = lambda *args: calls.__setitem__("connect", 1)
    module.request_certificate = lambda *args: calls.__setitem__("certificate", 1)

    def _poll(*args):
        calls["poll"] += 1

    module.poll_acl_update = _poll
    resumed = module.ABBWelcomeConfigFlow()
    resumed.hass = _FakeHass(backing_store)
    resumed._gateway_profile = module.GATEWAY_PROFILES[1]

    recovery = _run(resumed.async_step_credentials())
    assert recovery["step_id"] == "pending_pairing"
    waiting = _run(
        resumed.async_step_pending_pairing(
            {module.PENDING_PAIRING_ACTION: module.PENDING_PAIRING_ACTION_RESUME}
        )
    )
    assert waiting["step_id"] == "app_authorize"
    assert resumed._client_name == "ha-test"
    assert calls == {"connect": 0, "certificate": 0, "poll": 1}


def test_pending_pairing_acl_state_survives_reload_and_clears_on_success() -> None:
    module = _load_config_flow()
    backing_store = {}
    flow = _seed_pending_pairing(module, _FakeHass(backing_store))
    flow._manual_authorize = True
    module.poll_acl_update = lambda *args: "encrypted-acl"
    module.parse_acl_update = lambda *args: (
        "sip-password",
        "sip.example.invalid",
        [
            {
                "name": "Synthetic Door",
                "address": "sip:100000001@sip.example.invalid",
                "station_id": "100000001",
            }
        ],
    )

    confirm = _run(flow.async_step_poll_acl())
    assert confirm["step_id"] == "confirm"
    stored = backing_store[module.PENDING_PAIRING_STORAGE_KEY]
    assert stored["phase"] == module.PENDING_PAIRING_PHASE_ACL_RECEIVED

    resumed = module.ABBWelcomeConfigFlow()
    resumed.hass = _FakeHass(backing_store)
    resumed._gateway_profile = module.GATEWAY_PROFILES[1]
    recovery = _run(resumed.async_step_credentials())
    assert recovery["step_id"] == "pending_pairing"
    confirm_again = _run(
        resumed.async_step_pending_pairing(
            {module.PENDING_PAIRING_ACTION: module.PENDING_PAIRING_ACTION_RESUME}
        )
    )
    assert confirm_again["step_id"] == "confirm"
    created = _run(resumed.async_step_confirm({}))
    assert created["type"] == "create_entry"
    assert module.PENDING_PAIRING_STORAGE_KEY not in backing_store


def test_pending_pairing_requires_confirmation_before_discard() -> None:
    module = _load_config_flow()
    backing_store = {}
    _seed_pending_pairing(module, _FakeHass(backing_store))
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass(backing_store)
    flow._gateway_profile = module.GATEWAY_PROFILES[1]
    _run(flow.async_step_credentials())

    warning = _run(
        flow.async_step_pending_pairing(
            {module.PENDING_PAIRING_ACTION: module.PENDING_PAIRING_ACTION_DISCARD}
        )
    )
    assert warning["step_id"] == "discard_pending_pairing"
    assert module.PENDING_PAIRING_STORAGE_KEY in backing_store
    credentials = _run(flow.async_step_discard_pending_pairing({}))
    assert credentials["step_id"] == "credentials"
    assert module.PENDING_PAIRING_STORAGE_KEY not in backing_store


def test_invalid_pending_pairing_must_be_explicitly_reset() -> None:
    module = _load_config_flow()
    backing_store = {
        module.PENDING_PAIRING_STORAGE_KEY: {
            "schema_version": module.PENDING_PAIRING_SCHEMA_VERSION + 1,
            "private_key_pem": "must-not-appear-in-results",
        }
    }
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass(backing_store)
    flow._gateway_profile = module.GATEWAY_PROFILES[1]
    invalid = _run(flow.async_step_credentials())
    assert invalid["step_id"] == "pending_pairing_invalid"
    assert "must-not-appear-in-results" not in repr(invalid)
    assert module.PENDING_PAIRING_STORAGE_KEY in backing_store

    credentials = _run(flow.async_step_pending_pairing_invalid({}))
    assert credentials["step_id"] == "credentials"
    assert module.PENDING_PAIRING_STORAGE_KEY not in backing_store


def test_app_managed_setup_skips_cgi_and_sends_connect_once_across_retry() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[1]

    calls = {"connect": 0, "local_info": 0, "authorize": 0, "poll": 0}
    module.default_client_name = lambda: "ha-test"
    module.generate_keypair_and_csr = lambda username: (b"key", b"csr", object())
    module.resolve_portal_url = lambda username: "https://portal.invalid"
    module.request_certificate = lambda *args: b"cert"
    module.derive_identity = lambda *args: {
        "sip_username": "sip-user",
        "fingerprint_sha1": "A" * 40,
        "own_portal_uuid": "11111111-1111-1111-1111-111111111111",
    }
    module.compute_integrity_code = lambda fingerprint: ("1234ABCD", "1234 ABCD")

    def _connect(*args):
        calls["connect"] += 1

    def _local_info(*args):
        calls["local_info"] += 1
        return {"uuid": "should-not-be-used"}

    def _authorize(*args):
        calls["authorize"] += 1

    poll_results = iter((None, "encrypted-acl"))
    module.send_connect_event = _connect
    module.gateway_local_info = _local_info
    module.gateway_authorize = _authorize
    module._gateway_port_reachable = lambda host, port: port == 5061
    def _poll(*args):
        calls["poll"] += 1
        return next(poll_results)

    module.poll_acl_update = _poll
    module.parse_acl_update = lambda *args: (
        "sip-password",
        "sip.example.invalid",
        [
            {
                "name": "Synthetic Door",
                "address": "sip:100000001@sip.example.invalid",
                "station_id": "100000001",
            }
        ],
    )

    credentials = {
        module.CONF_ABB_USERNAME: "portal-user",
        module.CONF_ABB_PASSWORD: "portal-password",
        module.CONF_GATEWAY_IP: "192.0.2.10",
        module.CONF_GATEWAY_UUID_OVERRIDE: (
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        ),
    }
    waiting = _run(flow.async_step_credentials(credentials))
    assert waiting["step_id"] == "app_authorize"
    assert waiting["errors"]["base"] == "acl_timeout_retry"
    assert calls == {"connect": 1, "local_info": 0, "authorize": 0, "poll": 1}
    assert flow._gateway_name == "M2240x / ASI22"

    resumed = module.ABBWelcomeConfigFlow()
    resumed.hass = _FakeHass(flow.hass.storage)
    resumed._gateway_profile = module.GATEWAY_PROFILES[1]
    recovery = _run(resumed.async_step_credentials())
    assert recovery["step_id"] == "pending_pairing"
    confirmed = _run(
        resumed.async_step_pending_pairing(
            {module.PENDING_PAIRING_ACTION: module.PENDING_PAIRING_ACTION_RESUME}
        )
    )
    assert confirmed["step_id"] == "confirm"
    assert calls == {"connect": 1, "local_info": 0, "authorize": 0, "poll": 2}
    assert resumed._sip_password == "sip-password"
    created = _run(resumed.async_step_confirm({}))
    assert created["data"]["portal_url"] == "https://portal.invalid"


def test_app_managed_entry_omits_admin_and_portal_passwords() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[1]
    flow._gateway_ip = "192.0.2.10"
    flow._sip_username = "sip-user"
    flow._sip_password = "sip-password"
    flow._sip_domain = "sip-domain"
    flow._doors = []
    flow._gateway_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    flow._own_uuid = "11111111-1111-1111-1111-111111111111"
    flow._client_name = "ha-test"
    flow._username = "portal-user-must-not-be-stored"
    flow._gateway_password = "must-not-be-stored"
    flow._password = "portal-password-must-not-be-stored"
    flow._portal_url = "https://geo-resolved.example.invalid"
    flow._private_key_pem = b"key"
    flow._cert_pem = b"cert"
    flow._gateway_name = "M2240x / ASI22"

    result = _run(flow.async_step_confirm({}))
    data = result["data"]
    assert data[module.CONF_GATEWAY_PROFILE] == module.GATEWAY_PROFILES[1]
    assert data["portal_url"] == "https://geo-resolved.example.invalid"
    assert "gateway_admin_password" not in data
    assert module.CONF_ABB_USERNAME not in data
    assert module.CONF_ABB_PASSWORD not in data
    assert "portal-user-must-not-be-stored" not in repr(data)
    assert "portal-password-must-not-be-stored" not in repr(data)


def test_app_managed_requires_valid_uuid() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[1]
    base = {
        module.CONF_ABB_USERNAME: "user",
        module.CONF_ABB_PASSWORD: "password",
        module.CONF_GATEWAY_IP: "192.0.2.10",
    }
    missing = _run(flow.async_step_credentials(base))
    assert missing["errors"][module.CONF_GATEWAY_UUID_OVERRIDE] == "uuid_required"

    invalid = _run(
        flow.async_step_credentials(
            {**base, module.CONF_GATEWAY_UUID_OVERRIDE: "not-a-uuid"}
        )
    )
    assert invalid["errors"][module.CONF_GATEWAY_UUID_OVERRIDE] == "invalid_uuid"


def test_app_managed_probes_5061_and_maps_portal_auth_failure() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[1]
    probed = []

    def _probe(host, port):
        probed.append((host, port))
        return True

    def _fail_auth():
        raise module.PortalError("Portal authentication failed (HTTP 401)")

    module._gateway_port_reachable = _probe
    flow._ensure_portal_identity = _fail_auth
    result = _run(
        flow.async_step_credentials(
            {
                module.CONF_ABB_USERNAME: "user",
                module.CONF_ABB_PASSWORD: "bad-password",
                module.CONF_GATEWAY_IP: "192.0.2.10",
                module.CONF_GATEWAY_UUID_OVERRIDE: (
                    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
                ),
            }
        )
    )
    assert probed == [("192.0.2.10", 5061)]
    assert result["errors"]["base"] == "invalid_auth"


def test_app_managed_reports_unavailable_sip_without_pairing() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[1]
    module._gateway_port_reachable = lambda host, port: False
    pairing_calls = []
    flow._resolve_gateway_uuid = lambda: pairing_calls.append(True)
    result = _run(
        flow.async_step_credentials(
            {
                module.CONF_ABB_USERNAME: "user",
                module.CONF_ABB_PASSWORD: "password",
                module.CONF_GATEWAY_IP: "192.0.2.10",
                module.CONF_GATEWAY_UUID_OVERRIDE: (
                    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
                ),
            }
        )
    )
    assert result["errors"]["base"] == "sip_tls_unavailable"
    assert pairing_calls == []


def test_app_managed_acl_timeout_returns_same_approval_step() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[1]
    flow._manual_authorize = True
    flow._client_name = "ha-test"
    flow._integrity_display = "1234 ABCD"
    module.poll_acl_update = lambda *args: None
    result = _run(flow.async_step_poll_acl())
    assert result["step_id"] == "app_authorize"
    assert result["errors"]["base"] == "acl_timeout_retry"


def test_duplicate_app_managed_ip_aborts_before_pairing() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[1]
    flow._async_current_entries = lambda: [
        types.SimpleNamespace(data={module.CONF_GATEWAY_IP: "192.0.2.10"})
    ]
    result = _run(
        flow.async_step_credentials(
            {
                module.CONF_ABB_USERNAME: "user",
                module.CONF_ABB_PASSWORD: "password",
                module.CONF_GATEWAY_IP: "192.0.2.10",
                module.CONF_GATEWAY_UUID_OVERRIDE: (
                    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
                ),
            }
        )
    )
    assert result == {"type": "abort", "reason": "already_configured"}


def test_web_admin_pairing_keeps_local_uuid_cgi_path() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow._gateway_profile = module.GATEWAY_PROFILES[0]
    flow._username = "portal-user"
    flow._password = "portal-password"
    flow._gateway_ip = "192.0.2.10"
    flow._gateway_password = "admin-password"
    flow._gateway_uuid_override = ""
    calls = {"cgi": 0, "connect": 0}
    module.default_client_name = lambda: "ha-test"
    module.generate_keypair_and_csr = lambda username: (b"key", b"csr", object())
    module.resolve_portal_url = lambda username: "https://portal.invalid"
    module.request_certificate = lambda *args: b"cert"
    module.derive_identity = lambda *args: {
        "sip_username": "sip-user",
        "fingerprint_sha1": "A" * 40,
        "own_portal_uuid": "11111111-1111-4111-8111-111111111111",
    }
    module.compute_integrity_code = lambda fingerprint: ("1234ABCD", "1234 ABCD")

    def _cgi(*args):
        calls["cgi"] += 1
        return {
            "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "portalname": "Test Gateway",
        }

    def _connect(*args):
        calls["connect"] += 1

    module.gateway_local_info = _cgi
    module.send_connect_event = _connect
    flow._resolve_gateway_uuid()
    flow._ensure_portal_identity()
    flow._send_connect_request()
    assert calls == {"cgi": 1, "connect": 1}
    assert flow._gateway_name == "Test Gateway"


def _stub_web_admin_pairing(module, calls):
    names = iter(("ha-first", "ha-second", "ha-third"))
    module.default_client_name = lambda: next(names)
    module._gateway_port_reachable = lambda *_args: True
    module.generate_keypair_and_csr = lambda username: (b"key", b"csr", object())
    module.resolve_portal_url = lambda username: "https://portal.invalid"

    def _certificate(_url, username, *_args):
        calls["certificate"].append(username)
        return f"cert-{len(calls['certificate'])}".encode()

    def _connect(_url, cert, _key, gateway_uuid, *_args):
        calls["connect"].append((cert, gateway_uuid))

    module.request_certificate = _certificate
    module.derive_identity = lambda cert, username: {
        "sip_username": f"{username}_sip",
        "fingerprint_sha1": "A" * 40,
        "own_portal_uuid": "11111111-1111-4111-8111-111111111111",
    }
    module.compute_integrity_code = lambda fingerprint: ("1234ABCD", "1234 ABCD")
    module.send_connect_event = _connect
    module.poll_acl_update = lambda *args: None


def _web_admin_credentials(module, username="portal-user", uuid=""):
    return {
        module.CONF_ABB_USERNAME: username,
        module.CONF_ABB_PASSWORD: "portal-password",
        module.CONF_GATEWAY_IP: "192.0.2.10",
        module.CONF_GATEWAY_PASSWORD: "admin-password",
        module.CONF_GATEWAY_UUID_OVERRIDE: uuid,
    }


def test_web_admin_uuid_lookup_failure_does_not_register_portal_client() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[0]
    calls = {"certificate": [], "connect": []}
    _stub_web_admin_pairing(module, calls)

    def _empty_op6(*args):
        raise module.GatewayAdminError("Gateway op=6 response missing uuid: {}")

    module.gateway_local_info = _empty_op6
    module.gateway_authorize = lambda *args: "user_7"

    failed = _run(
        flow.async_step_credentials(_web_admin_credentials(module))
    )
    assert failed["errors"]["base"] == "gateway_op6_failed"
    assert calls == {"certificate": [], "connect": []}

    uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    _run(
        flow.async_step_credentials(_web_admin_credentials(module, uuid=uuid))
    )
    assert calls == {"certificate": ["portal-user"], "connect": [(b"cert-1", uuid)]}


def test_web_admin_retry_after_connect_reuses_issued_certificate() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[0]
    calls = {"certificate": [], "connect": []}
    _stub_web_admin_pairing(module, calls)
    uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    module.gateway_local_info = lambda *args: {"uuid": uuid}
    authorize_names = []

    def _authorize(_ip, password, client_name, _code):
        authorize_names.append(client_name)
        if password == "admin-password":
            raise module.GatewayAdminError("Gateway login failed (HTTP 200)")
        return "user_7"

    module.gateway_authorize = _authorize

    failed = _run(
        flow.async_step_credentials(_web_admin_credentials(module))
    )
    assert failed["errors"]["base"] == "gateway_admin_auth_failed"

    retry = _web_admin_credentials(module)
    retry[module.CONF_GATEWAY_PASSWORD] = "corrected-admin-password"
    _run(flow.async_step_credentials(retry))
    assert calls["certificate"] == ["portal-user"]
    assert calls["connect"] == [(b"cert-1", uuid), (b"cert-1", uuid)]
    assert authorize_names == ["ha-first", "ha-first"]

    # A different portal account cannot reuse the first account's identity.
    _run(
        flow.async_step_credentials(
            _web_admin_credentials(module, username="other-user")
        )
    )
    assert calls["certificate"] == ["portal-user", "other-user"]
    assert calls["connect"][-1] == (b"cert-2", uuid)


@pytest.mark.parametrize("stage", ["gateway_uuid", "approve"])
def test_device_without_web_admin_is_not_reported_as_a_wrong_password(stage) -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[0]
    _stub_web_admin_pairing(module, {"certificate": [], "connect": []})

    def _missing(*args):
        raise module.GatewayWebAdminMissingError(
            "Gateway web admin login endpoint not found (HTTP 404)"
        )

    uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    if stage == "gateway_uuid":
        module.gateway_local_info = _missing
    else:
        module.gateway_local_info = lambda *args: {"uuid": uuid}
        module.gateway_authorize = _missing

    failed = _run(flow.async_step_credentials(_web_admin_credentials(module)))
    assert failed["errors"]["base"] == "gateway_web_admin_missing"


@pytest.mark.parametrize(
    "status, body, expected",
    [
        (404, "<html>404 Not Found</html>", "GatewayWebAdminMissingError"),
        (200, "0", "GatewayAdminError"),
        (500, "", "GatewayAdminError"),
    ],
)
def test_gateway_login_tells_a_missing_web_admin_from_a_rejected_login(
    monkeypatch, status, body, expected
) -> None:
    _load_config_flow()
    portal = sys.modules["abb_pairing_test.portal"]

    class _Session:
        cookies: dict = {}

        def post(self, *args, **kwargs):
            return types.SimpleNamespace(
                status_code=status,
                content=body.encode(),
                headers={},
                request=types.SimpleNamespace(
                    method="POST", url="https://192.0.2.1/", headers={}, body=b""
                ),
            )

        def close(self) -> None:
            pass

    monkeypatch.setattr(portal.requests, "Session", _Session)
    with pytest.raises(portal.GatewayAdminError) as err:
        portal._gateway_login("192.0.2.1", "admin", "synthetic-password")
    assert type(err.value).__name__ == expected


def test_failed_certificate_request_keeps_issued_key_pair() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[0]
    calls = {"certificate": [], "connect": []}
    _stub_web_admin_pairing(module, calls)
    module.generate_keypair_and_csr = lambda username: (
        f"key-{username}".encode(), b"csr", object()
    )
    uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    module.gateway_local_info = lambda *args: {"uuid": uuid}
    module.gateway_authorize = lambda *args: (_ for _ in ()).throw(
        module.GatewayAdminError("Gateway login failed (HTTP 200)")
    )
    _run(flow.async_step_credentials(_web_admin_credentials(module)))
    assert (flow._cert_pem, flow._private_key_pem) == (b"cert-1", b"key-portal-user")

    issue = module.request_certificate
    module.request_certificate = lambda *args: (_ for _ in ()).throw(
        module.PortalError("Portal authentication failed (HTTP 401)")
    )
    rejected = _run(
        flow.async_step_credentials(
            _web_admin_credentials(module, username="wrong-user")
        )
    )
    assert rejected["errors"]["base"] == "invalid_auth"
    assert (flow._cert_pem, flow._private_key_pem) == (b"cert-1", b"key-portal-user")

    module.request_certificate = issue
    _run(flow.async_step_credentials(_web_admin_credentials(module)))
    assert calls["certificate"] == ["portal-user"]
    assert flow._private_key_pem == b"key-portal-user"


def test_acl_parsing_builds_doors_before_confirmation() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[1]
    flow._portal_url = "https://portal.invalid"
    flow._cert_pem = b"cert"
    flow._private_key_pem = b"key"
    flow._own_uuid = "11111111-1111-4111-8111-111111111111"
    flow._gateway_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    flow._client_name = "ha-test"
    flow._integrity_display = "1234 ABCD"
    module.poll_acl_update = lambda *args: "encrypted-acl"
    module.parse_acl_update = lambda *args: (
        "sip-password",
        "sip.example.invalid",
        [
            {
                "name": "Synthetic Door",
                "address": "sip:100000001@sip.example.invalid",
                "station_id": "100000001",
                "local_id": "synthetic-local-client",
                "type": "1",
                "second_lock": True,
            }
        ],
    )
    result = _run(flow.async_step_poll_acl())
    assert result["step_id"] == "confirm"
    assert flow._sip_password == "sip-password"
    assert flow._doors == [
        {
            "name": "Synthetic Door",
            "address": "sip:100000001@sip.example.invalid",
            "station_id": "100000001",
            "local_id": "synthetic-local-client",
            "body": "1",
            "index": 0,
            "type": "1",
            "second_lock": True,
        }
    ]


def _options_input(module, strategy: str, default_station: str = "") -> dict:
    data = {
        module.CONF_UNLOCK_STRATEGY: strategy,
        module.CONF_LAN_RTSP_HOST: "",
        module.CONF_LAN_RTSP_PORT: 18556,
        module.CONF_ALLOW_PICKUP: True,
    }
    if default_station:
        data[module.CONF_DEFAULT_UNLOCK_STATION_ID] = default_station
    return data


def _options_entry(module, doors: list[dict]):
    return types.SimpleNamespace(
        data={
            module.CONF_GATEWAY_PROFILE: module.GATEWAY_PROFILE_APP_MANAGED,
            "doors": doors,
        },
        options={},
    )


def _schema_default(result: dict, field: str):
    for key in result["data_schema"]:
        if key == field:
            return key.default
    raise AssertionError(f"missing schema field {field}")


def test_app_multi_door_options_reject_fast_and_require_hybrid_default() -> None:
    module = _load_config_flow()
    doors = [
        {"name": "Synthetic Back", "station_id": "station-back"},
        {"name": "Synthetic Front", "station_id": "station-front"},
    ]
    flow = module.ABBWelcomeOptionsFlow(_options_entry(module, doors))
    fast = _run(
        flow.async_step_init(
            _options_input(module, module.UNLOCK_STRATEGY_FAST)
        )
    )
    assert fast["errors"]["base"] == "fast_multi_door_unsupported"

    hybrid_missing = _run(
        flow.async_step_init(
            _options_input(module, module.UNLOCK_STRATEGY_HYBRID)
        )
    )
    assert hybrid_missing["errors"][module.CONF_DEFAULT_UNLOCK_STATION_ID] == (
        "invalid_default_unlock_station"
    )

    invalid_input = _options_input(
        module,
        module.UNLOCK_STRATEGY_HYBRID,
        "station-missing",
    )
    invalid_input[module.CONF_LAN_RTSP_HOST] = "attempt.example.invalid"
    invalid_input[module.CONF_LAN_RTSP_PORT] = 19001
    invalid_input[module.CONF_ALLOW_PICKUP] = False
    hybrid_invalid = _run(flow.async_step_init(invalid_input))
    assert hybrid_invalid["errors"][module.CONF_DEFAULT_UNLOCK_STATION_ID] == (
        "invalid_default_unlock_station"
    )
    assert _schema_default(hybrid_invalid, module.CONF_LAN_RTSP_HOST) == (
        "attempt.example.invalid"
    )
    assert _schema_default(hybrid_invalid, module.CONF_LAN_RTSP_PORT) == 19001
    assert _schema_default(hybrid_invalid, module.CONF_ALLOW_PICKUP) is False
    assert _schema_default(
        hybrid_invalid, module.CONF_DEFAULT_UNLOCK_STATION_ID
    ) is None

    valid_input = _options_input(
        module,
        module.UNLOCK_STRATEGY_HYBRID,
        "station-front",
    )
    valid_input[module.CONF_LAN_RTSP_HOST] = "ha.example.invalid"
    valid_input[module.CONF_LAN_RTSP_PORT] = 19000
    valid_input[module.CONF_ALLOW_PICKUP] = False
    hybrid_valid = _run(
        flow.async_step_init(valid_input)
    )
    assert hybrid_valid["type"] == "create_entry"
    assert hybrid_valid["data"][module.CONF_DEFAULT_UNLOCK_STATION_ID] == (
        "station-front"
    )
    assert hybrid_valid["data"][module.CONF_LAN_RTSP_HOST] == (
        "ha.example.invalid"
    )
    assert hybrid_valid["data"][module.CONF_LAN_RTSP_PORT] == 19000
    assert hybrid_valid["data"][module.CONF_ALLOW_PICKUP] is False


def test_app_single_door_options_allow_fast() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeOptionsFlow(
        _options_entry(
            module,
            [{"name": "Synthetic Front", "station_id": "station-front"}],
        )
    )
    result = _run(
        flow.async_step_init(
            _options_input(module, module.UNLOCK_STRATEGY_FAST)
        )
    )
    assert result["type"] == "create_entry"
    assert result["data"][module.CONF_UNLOCK_STRATEGY] == (
        module.UNLOCK_STRATEGY_FAST
    )


def test_pairing_progress_walks_each_stage_in_order() -> None:
    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[0]
    calls = {"certificate": [], "connect": []}
    _stub_web_admin_pairing(module, calls)
    shown_stages = []

    def _record(stage_after):
        def _stub(*args):
            shown_stages.append(flow._pairing_stage)
            return stage_after

        return _stub

    module.gateway_local_info = _record(
        {"uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}
    )
    module.gateway_authorize = _record("user_7")
    issue = module.request_certificate
    module.request_certificate = lambda *args: (
        shown_stages.append(flow._pairing_stage) or issue(*args)
    )

    async def _first_result():
        return await flow.async_step_credentials(_web_admin_credentials(module))

    first = asyncio.run(_first_result())
    assert first["type"] == "progress"
    assert first["step_id"] == "pairing"
    assert first["progress_action"] == "pairing_gateway_uuid"
    assert shown_stages == ["gateway_uuid", "certificate", "approve"]
    assert flow.flow_changes == 4


def test_pairing_failure_shows_redacted_debug_report() -> None:
    module = _load_config_flow()
    portal = sys.modules["abb_pairing_test.portal"]
    flow = module.ABBWelcomeConfigFlow()
    flow.hass = _FakeHass()
    flow._gateway_profile = module.GATEWAY_PROFILES[0]
    calls = {"certificate": [], "connect": []}
    _stub_web_admin_pairing(module, calls)
    portal_logger = portal._LOGGER
    portal_logger.setLevel(logging.WARNING)

    def _empty_op6(ip, password):
        portal._log(logging.DEBUG, "op=6 probe for %s returned %d bytes", ip, 0)
        portal._log(logging.INFO, "probe aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee 192.0.2.10")
        raise portal.GatewayAdminError(
            "Gateway op=6 response missing uuid (response keys: []; values redacted)"
        )

    module.gateway_local_info = _empty_op6
    result = _run(flow.async_step_credentials(_web_admin_credentials(module)))

    assert result["step_id"] == "credentials"
    assert result["errors"] == {"base": "gateway_op6_failed"}
    assert flow.suggested_values == _web_admin_credentials(module)
    report = result["description_placeholders"]["debug_report"]
    assert report.startswith("\n\n**Debug report**")
    version = json.loads((_PKG_DIR / "manifest.json").read_text())["version"]
    assert f"ABB Welcome {version}, Home Assistant 2099.1.0, profile web_admin" in report
    assert re.search(
        r"\n\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3} DEBUG abb_pairing_test.portal: "
        r"\[abb\] op=6 probe for <redacted> returned 0 bytes\n",
        report,
    )
    assert (
        "Pairing stage gateway_uuid failed: GatewayAdminError: Gateway op=6 "
        "response missing uuid (response keys: []; values redacted)"
    ) in report
    for secret in (
        "192.0.2.10",
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "portal-password",
        "admin-password",
    ):
        assert secret not in report
    # Capturing is temporary; the user's configured level is restored.
    assert portal_logger.level == logging.WARNING
    assert not any(
        isinstance(handler, sys.modules["abb_pairing_test.pairing_report"].PairingReport)
        for handler in portal_logger.handlers
    )
    assert calls == {"certificate": [], "connect": []}


def test_debug_report_keeps_start_and_end_of_long_runs() -> None:
    _load_config_flow()
    report_module = sys.modules["abb_pairing_test.pairing_report"]
    logger = logging.getLogger("abb_pairing_test.report_size")
    report = report_module.PairingReport((logger,), "test")
    total = report_module.HEAD_LINES + report_module.TAIL_LINES + 37
    with report.capture():
        for index in range(total):
            logger.debug("line %d", index)
    rendered = report.render()
    assert "line 0\n" in rendered
    assert f"line {report_module.HEAD_LINES - 1}\n" in rendered
    assert f"line {report_module.HEAD_LINES}\n" not in rendered
    assert "... 37 lines omitted ..." in rendered
    assert f"line {total - 1}\n" in rendered
    assert report_module.PairingReport((logger,), "empty").render() == ""


def test_acl_poll_progress_shows_attempts_then_timeout_report() -> None:
    import threading

    module = _load_config_flow()
    flow = module.ABBWelcomeConfigFlow()
    flow._gateway_profile = module.GATEWAY_PROFILES[0]
    flow._manual_authorize = True
    flow._client_name = "ha-test"
    flow._integrity_display = "1234 ABCD"
    release = threading.Event()

    class _ThreadedHass(_FakeHass):
        bound_loop = None

        @property
        def loop(self):
            return self.bound_loop

        async def async_add_executor_job(self, function, *args):
            return await asyncio.get_running_loop().run_in_executor(
                None, function, *args
            )

    flow.hass = _ThreadedHass()

    def _poll(_url, _cert, _key, _uuid, attempts, _interval, on_attempt):
        for attempt in (1, 2, 3):
            on_attempt(attempt)
        release.wait(5)
        return None

    module.poll_acl_update = _poll

    async def _drive():
        flow.hass.bound_loop = asyncio.get_running_loop()
        first = await flow.async_step_poll_acl()
        assert first["type"] == "progress"
        for _ in range(200):
            if flow._poll_attempt == 3:
                break
            await asyncio.sleep(0.01)
        refreshed = await flow.async_step_poll_acl()
        release.set()
        await asyncio.wait({first["progress_task"]})
        done = await flow.async_step_poll_acl()
        final = await getattr(flow, f"async_step_{done['step_id']}")()
        return refreshed, final

    refreshed, final = asyncio.run(_drive())
    attempts = str(module.POLL_ATTEMPTS_MANUAL)
    assert refreshed["description_placeholders"] == {
        "attempt": "3",
        "attempts": attempts,
        "client_name": "ha-test",
        "integrity_code": "1234 ABCD",
    }
    assert flow.progress_updates == [
        1 / module.POLL_ATTEMPTS_MANUAL,
        2 / module.POLL_ATTEMPTS_MANUAL,
        3 / module.POLL_ATTEMPTS_MANUAL,
    ]
    assert final["type"] == "abort"
    assert final["reason"] == "acl_timeout"
    assert (
        f"WARNING abb_pairing_test.config_flow: [abb] No ACL update arrived after {attempts} checks"
        in final["description_placeholders"]["debug_report"]
    )
