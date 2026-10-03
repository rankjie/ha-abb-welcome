"""Second-lock discovery, entity controls, and targeted SIP routing."""

from __future__ import annotations

import ast
import asyncio
import base64
import importlib.util
import logging
import sys
import types
from pathlib import Path
from urllib.parse import unquote

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"
_PACKAGE = "abb_second_lock_test"
package = types.ModuleType(_PACKAGE)
package.__path__ = [str(_PKG_DIR)]
sys.modules[_PACKAGE] = package


def _load(name):
    full_name = f"{_PACKAGE}.{name}"
    spec = importlib.util.spec_from_file_location(full_name, _PKG_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


const = _load("const")
_load("redaction")
text = _load("text")
portal = _load("portal")
sip_client = _load("sip_client")


def _topology():
    source = _PKG_DIR / "__init__.py"
    names = {
        "_parse_gateway_doors",
        "_doors_equal",
        "_async_refresh_doors_for_entry",
        "_fire_discovery_changed",
    }
    nodes = [
        node
        for node in ast.parse(source.read_text()).body
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in names
        )
        or (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "PRESERVED_DOOR_METADATA_KEYS"
                for target in node.targets
            )
        )
    ]
    namespace = {
        "unquote": unquote,
        "repair_utf8_mojibake": text.repair_utf8_mojibake,
        "topology_refresh_action": const.topology_refresh_action,
        "TOPOLOGY_REFRESH_ACTION_REFRESH": const.TOPOLOGY_REFRESH_ACTION_REFRESH,
        "EVENT_DISCOVERY_CHANGED": const.EVENT_DISCOVERY_CHANGED,
        "_LOGGER": logging.getLogger(__name__),
    }
    exec(
        compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace
    )
    return namespace


@pytest.mark.parametrize("flag, expected", [("0", False), ("1", True)])
def test_gateway_capability_is_parsed_per_station(flag, expected):
    parse = _topology()["_parse_gateway_doors"]
    doors = parse(
        f"outdoorstation_0+1+Front+{flag};outdoorstation_1+2+Back+0", "example.invalid"
    )
    assert [door["second_lock"] for door in doors] == [expected, False]
    assert [door["station_id"] for door in doors] == ["100000001", "100000002"]


def test_missing_gateway_capability_stays_unknown():
    doors = _topology()["_parse_gateway_doors"](
        "outdoorstation_0+1+Front", "example.invalid"
    )
    assert "second_lock" not in doors[0]


@pytest.mark.parametrize("flag", ["2", "yes"])
def test_invalid_gateway_capability_is_reported(flag):
    with pytest.raises(ValueError, match="second-lock"):
        _topology()["_parse_gateway_doors"](
            f"outdoorstation_0+1+Front+{flag}", "example.invalid"
        )


@pytest.fixture(scope="module")
def acl_identity():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    password = key.public_key().encrypt(b"synthetic-password", padding.PKCS1v15())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return base64.b64encode(password).decode(), pem


@pytest.mark.parametrize("flag, expected", [("0", False), ("1", True), (None, None)])
def test_acl_secondunlock_is_preserved(acl_identity, flag, expected):
    encrypted, pem = acl_identity
    payload = (
        encrypted
        + "\n[network]\ndomain=example.invalid\n[outdoorstation_0]\nname=Front\naddress=sip:100000001@example.invalid\ntype=1\n"
    )
    if flag is not None:
        payload += f"secondunlock={flag}\n"
    _, _, doors = portal.parse_acl_update(payload, pem)
    assert doors[0].get("second_lock") is expected


def test_invalid_acl_secondunlock_is_reported(acl_identity):
    encrypted, pem = acl_identity
    payload = (
        encrypted
        + "\n[network]\ndomain=example.invalid\n[outdoorstation_0]\nname=Front\naddress=sip:100000001@example.invalid\nsecondunlock=yes\n"
    )
    with pytest.raises(portal.PortalError, match="second-lock"):
        portal.parse_acl_update(payload, pem)


@pytest.mark.parametrize("strategy", ["hybrid", "fast", "standard"])
def test_second_lock_always_uses_targeted_invite(strategy, monkeypatch):
    door = {"name": "Front", "station_id": "100000001", "body": "1"}
    client = sip_client.SIPClient(
        "192.0.2.10",
        "synthetic-user",
        "synthetic-password",
        "example.invalid",
        doors=[door],
        unlock_strategy=strategy,
    )
    calls = []
    monkeypatch.setattr(
        client,
        "_unlock_fast",
        lambda spec, timeout: calls.append(("fast", spec.station_id, spec.unlock_body))
        or True,
    )
    monkeypatch.setattr(
        client,
        "_unlock_via_invite",
        lambda spec, timeout: calls.append(
            ("invite", spec.station_id, spec.unlock_body)
        )
        or True,
    )
    assert client.unlock_door(door, "a")
    assert calls == [("invite", "100000001", "a")]


@pytest.mark.parametrize("status", [200, 403])
def test_second_lock_message_and_teardown_follow_invite(monkeypatch, status):
    client = sip_client.SIPClient(
        "192.0.2.10",
        "synthetic-user",
        "synthetic-password",
        "example.invalid",
        unlock_strategy="fast",
    )
    calls = []
    sock = types.SimpleNamespace(
        settimeout=lambda _timeout: None, close=lambda: calls.append("close")
    )
    session = types.SimpleNamespace(
        target_uri="sip:100000002@example.invalid",
        established=True,
        close_media=lambda: calls.append("close_media"),
    )
    monkeypatch.setattr(
        sip_client, "_build_socket", lambda *_args: (sock, "192.0.2.20", 40000)
    )
    monkeypatch.setattr(sip_client, "_guess_media_ip", lambda *_args: "192.0.2.20")
    monkeypatch.setattr(
        sip_client, "_register_client", lambda *_args: calls.append("register")
    )

    def invite(*args):
        assert args[6].station_id == "100000002"
        calls.append("invite")
        return session

    def message(*args):
        calls.append(("message", args[-2], args[-1]))
        return sip_client.SipFrame(f"SIP/2.0 {status} Response", [], b"")

    monkeypatch.setattr(sip_client, "_start_invite_call", invite)
    monkeypatch.setattr(sip_client, "_send_plain_message", message)
    monkeypatch.setattr(
        sip_client,
        "_send_bye",
        lambda *_args: calls.append("bye")
        or sip_client.SipFrame("SIP/2.0 200 OK", [], b""),
    )
    assert client.unlock_door({"name": "Back", "station_id": "100000002"}, "a") is (
        status == 200
    )
    assert calls == [
        "register",
        "invite",
        ("message", session.target_uri, "a"),
        "bye",
        "close_media",
        "close",
    ]


@pytest.mark.parametrize(
    "old_capability, new_capability, changed",
    [(False, True, True), (True, False, True), (True, None, False)],
)
def test_capability_change_updates_topology_and_reloads(
    old_capability, new_capability, changed
):
    namespace = _topology()
    old = {
        "name": "Front",
        "station_id": "100000001",
        "body": "1",
        "second_lock": old_capability,
    }
    new = {**old, "second_lock": new_capability}
    if new_capability is None:
        del new["second_lock"]
    namespace["_fetch_doors_from_gateway"] = lambda *_args: [dict(new)]
    entry = types.SimpleNamespace(
        entry_id="synthetic-entry",
        data={
            "gateway_ip": "192.0.2.10",
            "gateway_admin_password": "synthetic-password",
            "sip_domain": "example.invalid",
            "doors": [old],
        },
    )
    reloaded = []
    events = []

    async def reload(entry_id):
        reloaded.append(entry_id)

    def update(updated, *, data):
        updated.data = data

    async def executor(function, *args):
        return function(*args)

    hass = types.SimpleNamespace(
        async_add_executor_job=executor,
        config_entries=types.SimpleNamespace(
            async_update_entry=update, async_reload=reload
        ),
        bus=types.SimpleNamespace(
            async_fire=lambda kind, data: events.append((kind, data))
        ),
    )
    assert (
        asyncio.run(
            namespace["_async_refresh_doors_for_entry"](
                hass, entry, reload_on_change=True
            )
        )
        is changed
    )
    assert entry.data["doors"][0]["second_lock"] is (
        old_capability if new_capability is None else new_capability
    )
    assert reloaded == (["synthetic-entry"] if changed else [])
    if changed:
        assert events[0][1]["door_count"] == 1
    else:
        assert events == []


def _button_module(monkeypatch):
    modules = {
        "homeassistant.components.button": {
            "ButtonEntity": type("ButtonEntity", (), {})
        },
        "homeassistant.config_entries": {"ConfigEntry": object},
        "homeassistant.const": {
            "EntityCategory": types.SimpleNamespace(DIAGNOSTIC="diagnostic")
        },
        "homeassistant.core": {"HomeAssistant": object},
        "homeassistant.exceptions": {
            "HomeAssistantError": type("HomeAssistantError", (Exception,), {})
        },
        "homeassistant.helpers.entity_platform": {"AddEntitiesCallback": object},
        f"{_PACKAGE}.coordinator": {"ABBWelcomeCoordinator": object},
        f"{_PACKAGE}.device": {"gateway_device_info": lambda data: {}},
    }
    for name, attrs in modules.items():
        module = types.ModuleType(name)
        module.__dict__.update(attrs)
        monkeypatch.setitem(sys.modules, name, module)
    return _load("button")


def test_buttons_keep_primary_identity_and_add_only_supported_locks(monkeypatch):
    module = _button_module(monkeypatch)
    doors = [
        {"name": "Front", "station_id": "100000001", "second_lock": True},
        {"name": "Back", "station_id": "100000002", "second_lock": False},
        {
            "name": "Camera",
            "station_id": "100000003",
            "second_lock": True,
            "can_unlock": False,
        },
    ]
    client = types.SimpleNamespace(unlock_door=lambda *_args: True)
    hass = types.SimpleNamespace(
        data={const.DOMAIN: {"synthetic-entry": {"sip_client": client}}}
    )
    entry = types.SimpleNamespace(
        entry_id="synthetic-entry",
        data={"gateway_uuid": "synthetic-gateway", "doors": doors},
    )
    entities = []
    asyncio.run(module.async_setup_entry(hass, entry, entities.extend))
    assert [entity._attr_unique_id for entity in entities] == [
        "synthetic-gateway_100000001",
        "synthetic-gateway_100000001_second_lock",
        "synthetic-gateway_100000002",
    ]
    assert entities[1]._attr_name == "Front Second lock"


@pytest.mark.parametrize("success", [True, False])
def test_second_button_sends_a_and_surfaces_failure(monkeypatch, success):
    module = _button_module(monkeypatch)
    calls = []
    client = types.SimpleNamespace(
        unlock_door=lambda *args: calls.append(args) or success
    )
    door = {"name": "Front", "station_id": "100000001", "second_lock": True}
    entity = module.ABBWelcomeDoorButton(
        client, door, "synthetic-gateway", "synthetic-entry", {}, second_lock=True
    )

    async def executor(function, *args):
        return function(*args)

    entity.hass = types.SimpleNamespace(async_add_executor_job=executor)
    if success:
        asyncio.run(entity.async_press())
    else:
        with pytest.raises(module.HomeAssistantError, match="Failed to unlock"):
            asyncio.run(entity.async_press())
    assert calls == [(door, "a")]
