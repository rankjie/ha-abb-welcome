"""Focused tests for ABB Welcome event entity history handling."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"
_PACKAGE = "abb_event_test"


def _load_event_module():
    homeassistant = types.ModuleType("homeassistant")
    components = types.ModuleType("homeassistant.components")
    event_component = types.ModuleType("homeassistant.components.event")
    config_entries = types.ModuleType("homeassistant.config_entries")
    core = types.ModuleType("homeassistant.core")
    helpers = types.ModuleType("homeassistant.helpers")
    entity_platform = types.ModuleType("homeassistant.helpers.entity_platform")

    class EventEntity:
        def _trigger_event(self, event_type, event_attributes) -> None:
            if not hasattr(self, "triggered_events"):
                self.triggered_events = []
            self.triggered_events.append((event_type, event_attributes))

    event_component.EventEntity = EventEntity
    config_entries.ConfigEntry = object
    core.HomeAssistant = object
    core.callback = lambda function: function
    entity_platform.AddEntitiesCallback = object

    sys.modules["homeassistant"] = homeassistant
    sys.modules["homeassistant.components"] = components
    sys.modules["homeassistant.components.event"] = event_component
    sys.modules["homeassistant.config_entries"] = config_entries
    sys.modules["homeassistant.core"] = core
    sys.modules["homeassistant.helpers"] = helpers
    sys.modules["homeassistant.helpers.entity_platform"] = entity_platform

    package = types.ModuleType(_PACKAGE)
    package.__path__ = [str(_PKG_DIR)]
    sys.modules[_PACKAGE] = package

    const = types.ModuleType(f"{_PACKAGE}.const")
    const.DOMAIN = "abb_welcome"
    coordinator = types.ModuleType(f"{_PACKAGE}.coordinator")
    coordinator.ABBWelcomeCoordinator = object
    device = types.ModuleType(f"{_PACKAGE}.device")
    device.gateway_device_info = lambda data: data
    redaction = types.ModuleType(f"{_PACKAGE}.redaction")
    redaction.get_redacting_logger = lambda _name: object()
    sys.modules[const.__name__] = const
    sys.modules[coordinator.__name__] = coordinator
    sys.modules[device.__name__] = device
    sys.modules[redaction.__name__] = redaction

    full_name = f"{_PACKAGE}.event"
    spec = importlib.util.spec_from_file_location(full_name, _PKG_DIR / "event.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


def _event(event_id: str):
    return types.SimpleNamespace(
        event_id=event_id,
        event_type="ring",
        station_id="station-1",
        local_id="local-1",
        local_name="Front door",
        sender="sender-1",
        belongs_to="gateway-1",
        timestamp="2026-08-12T12:00:00Z",
    )


class _Coordinator:
    def __init__(self, events, *, notify_on_add: bool = False) -> None:
        self.data = types.SimpleNamespace(events=list(events))
        self.listener = None
        self.notify_on_add = notify_on_add

    def async_add_listener(self, listener) -> None:
        self.listener = listener
        if self.notify_on_add:
            listener()


def test_existing_history_is_not_replayed_and_one_future_event_fires() -> None:
    module = _load_event_module()
    coordinator = _Coordinator(
        [_event("historical-2"), _event("historical-1")],
        notify_on_add=True,
    )
    entity = module.ABBWelcomeEventEntity(
        coordinator,
        "gateway-1",
        [],
        {},
    )

    asyncio.run(entity.async_added_to_hass())
    assert coordinator.listener is not None
    assert getattr(entity, "triggered_events", []) == []

    coordinator.data.events.insert(0, _event("future-1"))
    coordinator.listener()
    assert [event_type for event_type, _ in entity.triggered_events] == ["ring"]
    assert entity.triggered_events[0][1]["event_id"] == "future-1"

    coordinator.listener()
    assert len(entity.triggered_events) == 1
