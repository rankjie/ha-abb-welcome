"""Gateway relay actuators: discovery, button entities, and the relay command."""

from __future__ import annotations

import asyncio
import types

import pytest

from test_second_lock import _button_module, _topology, const, sip_client

# The issue reporter's getdevicelist shape, with names replaced.
_DEVICE_LIST = (
    "outdoorstation_0+1+Front+1;indoorstation_0+0+Hall+;"
    "relay_0+2+Gate++1;levelpushbutton++levelpushcall+"
)
_GATE = {"name": "Gate", "address": "2"}


def test_relays_are_parsed_apart_from_doors():
    namespace = _topology()
    assert namespace["_parse_gateway_relays"](_DEVICE_LIST) == [_GATE]
    doors = namespace["_parse_gateway_doors"](_DEVICE_LIST, "example.invalid")
    assert [door["station_id"] for door in doors] == ["100000001"]


def test_invalid_relay_address_is_reported():
    with pytest.raises(ValueError, match="relay address"):
        _topology()["_parse_gateway_relays"]("relay_0+gate+Gate++1")


@pytest.mark.parametrize(
    "old_relays, new_relays, changed",
    [(None, [_GATE], True), ([_GATE], [], True), ([_GATE], [_GATE], False), (None, [], False)],
)
def test_relay_change_updates_topology_and_reloads(old_relays, new_relays, changed):
    namespace = _topology()
    door = {"name": "Front", "station_id": "100000001", "body": "1"}
    namespace["_fetch_topology_from_gateway"] = lambda *_args: (
        [dict(door)],
        [dict(relay) for relay in new_relays],
    )
    data = {
        "gateway_ip": "192.0.2.10",
        "gateway_admin_password": "synthetic-password",
        "sip_domain": "example.invalid",
        "doors": [door],
    }
    if old_relays is not None:
        data["relays"] = old_relays
    entry = types.SimpleNamespace(entry_id="synthetic-entry", data=data)
    reloaded = []

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
        bus=types.SimpleNamespace(async_fire=lambda *_args: None),
    )
    assert (
        asyncio.run(
            namespace["_async_refresh_doors_for_entry"](
                hass, entry, reload_on_change=True
            )
        )
        is changed
    )
    assert entry.data.get("relays", []) == new_relays
    assert reloaded == (["synthetic-entry"] if changed else [])


@pytest.mark.parametrize("status", [200, 403])
def test_relay_command_goes_to_the_gateway_without_a_call(monkeypatch, status):
    client = sip_client.SIPClient(
        "192.0.2.10",
        "synthetic-user",
        "synthetic-password",
        "example.invalid",
        doors=[{"name": "Front", "station_id": "100000003", "body": "1"}],
        unlock_strategy="standard",
    )
    calls = []
    sock = types.SimpleNamespace(close=lambda: calls.append("close"))
    monkeypatch.setattr(
        sip_client, "_build_socket", lambda *_args: (sock, "192.0.2.20", 40000)
    )
    monkeypatch.setattr(
        sip_client, "_register_client", lambda *_args: calls.append("register")
    )

    def invite(*_args):
        raise AssertionError("a relay command must not place a call")

    def message(*args):
        calls.append(("message", args[-2], args[-1]))
        return sip_client.SipFrame(f"SIP/2.0 {status} Response", [], b"")

    monkeypatch.setattr(sip_client, "_start_invite_call", invite)
    monkeypatch.setattr(sip_client, "_send_plain_message", message)
    assert client.trigger_relay("2") is (status == 200)
    assert calls == [
        "register",
        ("message", "sip:100000001@example.invalid", "b:2"),
        "close",
    ]


def test_each_relay_gets_its_own_button(monkeypatch):
    module = _button_module(monkeypatch)
    hass = types.SimpleNamespace(
        data={const.DOMAIN: {"synthetic-entry": {"sip_client": object()}}}
    )
    entry = types.SimpleNamespace(
        entry_id="synthetic-entry",
        data={
            "gateway_uuid": "synthetic-gateway",
            "doors": [],
            "relays": [_GATE, {"name": "Garage", "address": "3"}],
        },
    )
    entities = []
    asyncio.run(module.async_setup_entry(hass, entry, entities.extend))
    assert [(e._attr_unique_id, e._attr_name) for e in entities] == [
        ("synthetic-gateway_relay_2", "Gate"),
        ("synthetic-gateway_relay_3", "Garage"),
    ]


@pytest.mark.parametrize("success", [True, False])
def test_relay_button_switches_its_relay_and_surfaces_failure(monkeypatch, success):
    module = _button_module(monkeypatch)
    calls = []
    client = types.SimpleNamespace(
        trigger_relay=lambda address: calls.append(address) or success
    )
    entity = module.ABBWelcomeRelayButton(client, _GATE, "synthetic-gateway", {})

    async def executor(function, *args):
        return function(*args)

    entity.hass = types.SimpleNamespace(async_add_executor_job=executor)
    if success:
        asyncio.run(entity.async_press())
    else:
        with pytest.raises(module.HomeAssistantError, match="Failed to switch relay"):
            asyncio.run(entity.async_press())
    assert calls == ["2"]
