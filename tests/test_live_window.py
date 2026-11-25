"""Live windows held by websocket subscriptions, isolated from Home Assistant."""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import sys
import types
from pathlib import Path

import pytest

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"
_PACKAGE = "abb_live_window_test"


class _Hass:
    def __init__(self) -> None:
        self.data: dict = {"abb_welcome": {"entry": {}}}
        self.listeners: dict[str, list] = {}

    def async_create_background_task(self, coro, *, name: str):
        return asyncio.get_running_loop().create_task(coro, name=name)


class _Connection:
    def __init__(self) -> None:
        self.subscriptions: dict[int, object] = {}
        self.results: list[int] = []
        self.errors: list[tuple[int, str]] = []
        self.events: list[tuple[int, dict]] = []

    def send_result(self, msg_id):
        self.results.append(msg_id)

    def send_error(self, msg_id, code, _message):
        self.errors.append((msg_id, code))

    def send_message(self, message):
        self.events.append(message)


def _send(hass, signal):
    for listener in list(hass.listeners.get(signal, [])):
        listener()


def _connect(hass, signal, listener):
    hass.listeners.setdefault(signal, []).append(listener)
    return lambda: hass.listeners[signal].remove(listener)


def _load(monkeypatch, name):
    spec = importlib.util.spec_from_file_location(
        f"{_PACKAGE}.{name}", _PACKAGE_ROOT / f"{name}.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def modules(monkeypatch):
    """Load the real state and websocket modules with per-test HA stubs."""
    stubs = {
        "homeassistant": {},
        "homeassistant.core": {"HomeAssistant": object, "callback": lambda f: f},
        "homeassistant.helpers": {},
        "homeassistant.helpers.dispatcher": {
            "async_dispatcher_send": _send,
            "async_dispatcher_connect": _connect,
        },
        "homeassistant.components": {},
        "homeassistant.components.websocket_api": {
            "ActiveConnection": _Connection,
            "ERR_NOT_FOUND": "not_found",
            "websocket_command": lambda _schema: lambda f: f,
            "event_message": lambda msg_id, event: (msg_id, event),
        },
        _PACKAGE: {"__path__": [str(_PACKAGE_ROOT)]},
        f"{_PACKAGE}.const": {
            "DOMAIN": "abb_welcome",
            "DEFAULT_ALLOW_PICKUP": True,
            "DEFAULT_CAMERA_STILL_IMAGE": True,
            "DEFAULT_PREVIEW_BEFORE_ANSWER": False,
        },
        f"{_PACKAGE}.redaction": {"get_redacting_logger": logging.getLogger},
    }
    for name, attrs in stubs.items():
        module = types.ModuleType(name)
        module.__dict__.update(attrs)
        monkeypatch.setitem(sys.modules, name, module)
    state = _load(monkeypatch, "streaming_state")
    return state, _load(monkeypatch, "live_window")


def _subscribe(live, hass, connection, msg_id, station="door", entry="entry"):
    live.ws_live(hass, connection, {"id": msg_id, "entry_id": entry, "station_id": station})


def test_subscription_holds_the_station_until_the_last_viewer_leaves(modules) -> None:
    state, live = modules
    hass, connection = _Hass(), _Connection()
    _subscribe(live, hass, connection, 1)
    _subscribe(live, hass, connection, 2)
    assert connection.results == [1, 2]
    armed = state.get_state(hass, "entry")
    assert (armed.armed, armed.reason, armed.target_station_id) == (True, "live", "door")
    assert armed.auto_disarm_task is None

    connection.subscriptions.pop(1)()
    assert state.is_stream_allowed(hass, "entry", "door")
    connection.subscriptions.pop(2)()
    assert not state.is_armed(hass, "entry")
    assert connection.events == []


def test_another_armed_station_or_unknown_entry_is_refused(modules) -> None:
    state, live = modules
    hass, connection = _Hass(), _Connection()
    _subscribe(live, hass, connection, 1, station="front")
    _subscribe(live, hass, connection, 2, station="back")
    _subscribe(live, hass, connection, 3, entry="missing")
    assert connection.errors == [(2, "station_busy"), (3, "not_found")]
    assert state.get_state(hass, "entry").target_station_id == "front"


def test_a_ring_window_is_borrowed_and_its_end_reported_once(modules) -> None:
    async def scenario() -> None:
        state, live = modules
        hass, connection = _Hass(), _Connection()
        state.arm(hass, "entry", reason=state.ARM_REASON_RING, duration=60, station_id="door")
        _subscribe(live, hass, connection, 1)
        armed = state.get_state(hass, "entry")
        assert armed.reason == state.ARM_REASON_RING
        connection.subscriptions[1]()
        assert state.is_armed(hass, "entry"), "leaving does not end the ring"

        _subscribe(live, hass, connection, 2)
        state.disarm(hass, "entry")
        state.disarm(hass, "entry")
        assert connection.events == [(2, {"ended": True})]

    asyncio.run(scenario())


def test_a_timed_arm_takes_over_and_outlives_the_viewer(modules) -> None:
    async def scenario() -> None:
        state, live = modules
        hass, connection = _Hass(), _Connection()
        _subscribe(live, hass, connection, 1)
        state.arm(hass, "entry", reason=state.ARM_REASON_MANUAL, duration=60)
        connection.subscriptions.pop(1)()
        assert state.get_state(hass, "entry").reason == state.ARM_REASON_MANUAL
        assert connection.events == []

    asyncio.run(scenario())


def test_the_station_hanging_up_ends_only_its_live_window(modules) -> None:
    async def scenario() -> None:
        state, live = modules
        hass, connection = _Hass(), _Connection()
        _subscribe(live, hass, connection, 1)
        state.end_live(hass, "entry", "back")
        assert state.is_armed(hass, "entry")
        state.end_live(hass, "entry", "door")
        assert not state.is_armed(hass, "entry")
        assert connection.events == [(1, {"ended": True})]

        state.arm(hass, "entry", reason=state.ARM_REASON_MANUAL, duration=60, station_id="door")
        state.end_live(hass, "entry", "door")
        assert state.is_armed(hass, "entry"), "a switch window keeps its timer"

    asyncio.run(scenario())
