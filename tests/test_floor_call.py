"""Floor-call (level push) MESSAGEs fire the Floor call event entity."""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path

import pytest

from test_event_entity import _load_event_module

_SOURCE = (
    Path(__file__).resolve().parent.parent
    / "custom_components"
    / "abb_welcome"
    / "__init__.py"
)


def _is_level_push_message():
    node = next(
        n
        for n in ast.parse(_SOURCE.read_text()).body
        if isinstance(n, ast.FunctionDef) and n.name == "_is_level_push_message"
    )
    namespace = {"json": json}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(_SOURCE), "exec"), namespace)
    return namespace["_is_level_push_message"]


@pytest.mark.parametrize(
    "body, expected",
    [
        ("8", True),
        ('{"cmd":"levelpush","seq":3,"domain":"example.invalid"}', True),
        ('{"cmd":"updatelist","seq":3}', False),
        ("c:2", False),
        ("18", False),
        ("{not json", False),
    ],
)
def test_floor_call_messages_are_recognised(body, expected):
    assert _is_level_push_message()(body) is expected


def test_floor_call_entity_fires_pressed_while_registered():
    module = _load_event_module()
    entry_data = {}
    entity = module.ABBWelcomeFloorCallEntity(entry_data, "synthetic-gateway", {})
    entity.async_write_ha_state = lambda: None
    asyncio.run(entity.async_added_to_hass())

    entry_data["level_push_handler"]()
    assert entity.triggered_events == [("pressed", None)]

    asyncio.run(entity.async_will_remove_from_hass())
    assert "level_push_handler" not in entry_data
