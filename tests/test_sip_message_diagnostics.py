"""Opt-in MESSAGE events retain protocol data without forwarding private values."""

from __future__ import annotations

import ast
import asyncio
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"
_PACKAGE = "abb_message_diagnostics_test"
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


_load("redaction")
diagnostics = _load("message_diagnostics")
listener_module = _load("sip_listener")


def test_known_text_commands_remain_readable_and_private_tokens_are_masked():
    result = diagnostics.redact_message_body(
        b"c:2;d:1 a private-value sip:door@192.0.2.10 b:100000001"
    )
    assert result["body"] == "<redacted>"
    assert result["body_redacted"] is True
    assert diagnostics.redact_message_body(b"a")["body_redacted"] is False
    assert diagnostics.redact_message_body(b"c:2")["body"] == "c:2"
    assert diagnostics.redact_message_body(b"b:100000001")["body"] == "b:<redacted>"


def test_json_button_parameters_survive_and_private_fields_do_not():
    source = {
        "cmd": "actuator",
        "buttons": [
            {"id": 2, "func": 5, "params": {"addr": "199", "name": "private-name"}}
        ],
        "password": "synthetic-password",
        "authorization": "synthetic-digest",
        "token": {"button": 1, "cmd": "unlock"},
        "private-field-name": "private-value",
        "dst": "sip:private@192.0.2.10",
        "seq": 123456,
    }
    result = diagnostics.redact_message_body(json.dumps(source).encode())
    body = json.loads(result["body"])
    assert body["cmd"] == "actuator"
    assert body["buttons"][0] == {
        "id": 2,
        "func": 5,
        "params": {"addr": "199", "name": "<redacted>"},
    }
    assert body["token"] == "<redacted>"
    assert body["seq"] == "<redacted>"
    assert "synthetic-password" not in result["body"]
    assert "synthetic-digest" not in result["body"]
    assert "private" not in result["body"]


@pytest.mark.parametrize("value", [0, 200, True, "123456789", "synthetic-value"])
def test_unknown_or_invalid_address_values_are_masked(value):
    result = diagnostics.redact_message_body(json.dumps({"addr": value}).encode())
    assert json.loads(result["body"])["addr"] == "<redacted>"


def test_body_limits_binary_and_unknown_plaintext_do_not_leak():
    assert (
        diagnostics.redact_message_body(b"synthetic-password")["body"] == "<redacted>"
    )
    assert (
        diagnostics.redact_message_body(b'"synthetic-password"')["body"] == "<redacted>"
    )
    assert diagnostics.redact_message_body(b"password: 1 a 2")["body"] == "<redacted>"
    assert diagnostics.redact_message_body(b"\xffsecret")["body_format"] == "binary"
    at_limit = b"a" + b" " * (diagnostics.MAX_MESSAGE_BODY_BYTES - 1)
    assert diagnostics.redact_message_body(at_limit)["body"] == at_limit.decode()
    assert (
        diagnostics.redact_message_body(at_limit + b"a")["body_format"] == "too_large"
    )
    nested = {"data": "synthetic-password"}
    for _ in range(10):
        nested = {"data": nested}
    assert (
        "synthetic-password"
        not in diagnostics.redact_message_body(json.dumps(nested).encode())["body"]
    )


class _Writer:
    def __init__(self):
        self.sent = []

    def write(self, data):
        self.sent.append(data)

    async def drain(self):
        return None


def _frame(method="MESSAGE"):
    return listener_module._SipFrame(
        start_line=f"{method} sip:private@192.0.2.10 SIP/2.0",
        headers=[
            ("Via", "SIP/2.0/TLS private-host"),
            ("From", "<sip:private@example.invalid>"),
            ("To", "<sip:ha@example.invalid>"),
            ("Call-ID", "private-call-id"),
            ("CSeq", f"1 {method}"),
            ("Authorization", "private-auth"),
        ],
        body=b"c:2 private-body",
        raw=b"private-wire-frame",
    )


def test_diagnostic_dispatch_is_opt_in_expires_and_keeps_internal_consumer(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(
        listener_module,
        "time",
        types.SimpleNamespace(monotonic=lambda: clock[0], time=lambda: 1000.0),
    )
    events, internal = [], []
    listener = listener_module.SipListener(
        "gateway.invalid",
        "synthetic-user",
        "synthetic-password",
        "example.invalid",
        on_message=internal.append,
        on_message_diagnostic=events.append,
    )
    writer = _Writer()
    frame = _frame()

    def dispatch(message=frame):
        asyncio.run(listener._dispatch(message, writer, "192.0.2.20", 5061))

    dispatch()
    assert events == []
    listener.enable_message_diagnostics(5)
    dispatch()
    assert events == [
        {
            "body": "<redacted>",
            "body_format": "text",
            "body_redacted": True,
            "body_bytes": len(frame.body),
            "received_at": 1000.0,
        }
    ]
    dispatch(_frame("NOTIFY"))
    dispatch(_frame("OPTIONS"))
    assert len(events) == 1
    clock[0] = 105.0
    dispatch()
    assert len(events) == 1
    assert internal == [frame, frame, frame]
    assert b"SIP/2.0 200 OK" in writer.sent[-1]
    assert "private" not in json.dumps(events)


def test_manual_disable_and_stop_clear_diagnostics():
    events = []
    listener = listener_module.SipListener(
        "gateway.invalid",
        "synthetic-user",
        "synthetic-password",
        "example.invalid",
        on_message_diagnostic=events.append,
    )
    listener.enable_message_diagnostics(600)
    listener.enable_message_diagnostics(0)
    listener._emit_message(_frame())
    assert events == []
    listener.enable_message_diagnostics(600)
    asyncio.run(listener.stop())
    listener._emit_message(_frame())
    assert events == []


@pytest.mark.parametrize("duration", [-1, 601, 1.5, True])
def test_invalid_windows_fail_without_enabling(duration):
    listener = listener_module.SipListener(
        "gateway.invalid", "synthetic-user", "synthetic-password", "example.invalid"
    )
    with pytest.raises(ValueError, match="duration"):
        listener.enable_message_diagnostics(duration)
    assert listener._message_diagnostics_until == 0.0


def test_service_targets_one_entry_and_missing_listener_does_not_partially_enable():
    source = _PKG_DIR / "__init__.py"
    tree = ast.parse(source.read_text())
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_async_register_services"
    )
    registered = {}
    services = types.SimpleNamespace(
        has_service=lambda domain, name: name != "diagnose_messages",
        async_register=lambda domain, name, handler, **kwargs: registered.setdefault(
            name, handler
        ),
    )
    vol = types.SimpleNamespace(
        Schema=lambda value: value,
        Optional=lambda key, **kwargs: key,
        Required=lambda key, **kwargs: key,
        Any=lambda *args: args,
        All=lambda *args: args,
        Coerce=lambda value: value,
        Range=lambda **kwargs: kwargs,
    )
    namespace = {
        "DOMAIN": "abb_welcome",
        "vol": vol,
        "HomeAssistantError": RuntimeError,
        "callback": lambda function: function,
        "DEFAULT_MESSAGE_DIAGNOSTICS_SECONDS": 300,
        "MAX_MESSAGE_DIAGNOSTICS_SECONDS": 600,
    }
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id.startswith("SERVICE_")
            for target in node.targets
        ):
            exec(
                compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"),
                namespace,
            )
    exec(
        compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    calls = []
    hass = types.SimpleNamespace(
        services=services,
        data={
            "abb_welcome": {
                "one": {
                    "sip_listener": types.SimpleNamespace(
                        enable_message_diagnostics=lambda seconds: calls.append(seconds)
                    )
                },
                "two": {},
            }
        },
    )
    namespace["_async_register_services"](hass)
    handler = registered["diagnose_messages"]
    asyncio.run(handler(types.SimpleNamespace(data={"entry_id": "one", "duration": 5})))
    assert calls == [5]
    with pytest.raises(RuntimeError, match="no SIP listener"):
        asyncio.run(handler(types.SimpleNamespace(data={"duration": 5})))
    assert calls == [5]
    with pytest.raises(RuntimeError, match="not loaded"):
        asyncio.run(handler(types.SimpleNamespace(data={"entry_id": "missing"})))
