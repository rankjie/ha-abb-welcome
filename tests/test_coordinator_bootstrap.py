"""Focused tests for cold-start portal screenshot lookup."""

from __future__ import annotations

import base64
import importlib.util
import sys
import types
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import requests

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"
_PACKAGE = "abb_coordinator_test"


def _load(module: str):
    full_name = f"{_PACKAGE}.{module}"
    spec = importlib.util.spec_from_file_location(full_name, _PKG_DIR / f"{module}.py")
    assert spec is not None and spec.loader is not None
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


homeassistant = sys.modules.setdefault(
    "homeassistant", types.ModuleType("homeassistant")
)
config_entries = types.ModuleType("homeassistant.config_entries")
config_entries.ConfigEntry = object
core = types.ModuleType("homeassistant.core")
core.HomeAssistant = object
helpers = sys.modules.setdefault(
    "homeassistant.helpers", types.ModuleType("homeassistant.helpers")
)
update_coordinator = types.ModuleType("homeassistant.helpers.update_coordinator")


class _DataUpdateCoordinator:
    """Import-only stand-in for Home Assistant's generic coordinator."""

    def __class_getitem__(cls, _item):
        return cls


update_coordinator.DataUpdateCoordinator = _DataUpdateCoordinator
homeassistant.config_entries = config_entries
homeassistant.core = core
helpers.update_coordinator = update_coordinator
sys.modules["homeassistant.config_entries"] = config_entries
sys.modules["homeassistant.core"] = core
sys.modules["homeassistant.helpers.update_coordinator"] = update_coordinator

package = types.ModuleType(_PACKAGE)
package.__path__ = [str(_PKG_DIR)]
sys.modules[_PACKAGE] = package
_load("const")
_load("redaction")
_load("text")
coordinator_module = _load("coordinator")


class _Response:
    def __init__(self, events: list[dict[str, Any]] | None = None) -> None:
        self._events = events

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict[str, list[dict[str, Any]]] | list[Any]:
        if self._events is None:
            return []
        return {"events": self._events}


class _Session:
    def __init__(
        self,
        results: Sequence[list[dict[str, Any]] | BaseException | None],
    ) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.closed = False

    def get(self, _url: str, *, params: dict[str, Any], timeout: int) -> _Response:
        assert timeout == 15
        self.calls.append((_url, dict(params)))
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return _Response(result)

    def close(self) -> None:
        self.closed = True


def _event(
    event_id: str,
    *,
    payload: str = "",
    event_type: str = "ring",
    timestamp: str = "2026-01-01T00:00:00Z",
) -> dict[str, Any]:
    return {
        "id": event_id,
        "type": f"com.abb.ispf.event.welcome.{event_type}",
        "timestamp": timestamp,
        "payload": payload,
    }


def _screenshot(event_id: str, timestamp: str = "2025-01-01T00:00:00Z"):
    payload = base64.b64encode(b"\xff\xd8jpeg data").decode()
    return _event(
        event_id,
        payload=payload,
        event_type="screenshot",
        timestamp=timestamp,
    )


def _coordinator(session: _Session):
    instance = coordinator_module.ABBWelcomeCoordinator.__new__(
        coordinator_module.ABBWelcomeCoordinator
    )
    instance._has_certs = True
    instance._newest_id = ""
    instance._screenshot_history_checked = False
    instance._portal_url = coordinator_module.DEFAULT_PORTAL_URL
    instance._data = coordinator_module.ABBWelcomeData()
    instance._station_names = {}
    instance._make_session = lambda: (session, [])
    instance._cleanup = lambda _paths: None
    return instance


def test_portal_event_queries_use_configured_regional_url() -> None:
    session = _Session([[], []])
    instance = _coordinator(session)
    instance._portal_url = "https://regional.example.invalid"

    instance.poll_events()

    assert [url for url, _params in session.calls] == [
        "https://regional.example.invalid/event",
        "https://regional.example.invalid/event",
    ]


def test_init_uses_legacy_default_or_configured_regional_portal_url(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        coordinator_module.DataUpdateCoordinator,
        "__init__",
        lambda self, *_args, **_kwargs: None,
    )

    class _Entry:
        entry_id = "entry"

        def __init__(self, portal_url: str | None) -> None:
            self.data = {} if portal_url is None else {"portal_url": portal_url}

    legacy = coordinator_module.ABBWelcomeCoordinator(object(), _Entry(None))
    regional = coordinator_module.ABBWelcomeCoordinator(
        object(), _Entry("https://regional.example.invalid/")
    )

    assert legacy._portal_url == coordinator_module.DEFAULT_PORTAL_URL
    assert regional._portal_url == "https://regional.example.invalid"


def test_cold_start_uses_single_screenshot_only_query_and_normal_anchor() -> None:
    normal_events = [
        _event(f"normal-{index}")
        for index in range(coordinator_module.HISTORY_PAGE_SIZE)
    ]
    session = _Session([normal_events, [_screenshot("historical-screenshot")]])
    instance = _coordinator(session)

    data = instance.poll_events()

    assert len(session.calls) == 2
    assert session.calls[0][1]["type"] == coordinator_module.HISTORY_TYPES
    assert session.calls[0][1]["pagination_limit"] == (
        coordinator_module.HISTORY_PAGE_SIZE
    )
    assert session.calls[1][1] == {
        "type": coordinator_module.SCREENSHOT_HISTORY_TYPE,
        "order": "desc",
        "pagination_limit": 1,
        "pagination_page": 1,
    }
    assert instance._newest_id == "normal-0"
    assert instance._screenshot_history_checked is True
    assert data.latest_screenshot == b"\xff\xd8jpeg data"
    assert data.events[0].event_id == "normal-0"
    assert data.events[-1].event_id == "historical-screenshot"


def test_normal_page_screenshot_is_preferred_without_extra_query() -> None:
    session = _Session([[_screenshot("normal-screenshot")]])
    instance = _coordinator(session)

    data = instance.poll_events()

    assert len(session.calls) == 1
    assert instance._screenshot_history_checked is True
    assert data.latest_screenshot_event_id == "normal-screenshot"
    assert instance._newest_id == "normal-screenshot"


def test_empty_screenshot_query_is_checked_and_incremental_stays_one_page() -> None:
    session = _Session([[_event("initial")], [], [_event("incremental")]])
    instance = _coordinator(session)

    instance.poll_events()
    data = instance.poll_events()

    assert len(session.calls) == 3
    assert instance._screenshot_history_checked is True
    assert session.calls[-1][1]["newer_than_id"] == "initial"
    assert session.calls[-1][1]["type"] == coordinator_module.HISTORY_TYPES
    assert [event.event_id for event in data.events] == ["incremental", "initial"]


def test_screenshot_query_failure_keeps_normal_events_and_retries(caplog) -> None:
    session = _Session(
        [
            [_event("initial", timestamp="2026-01-02T00:00:00Z")],
            requests.ConnectionError("private response must not be logged"),
            [],
            [_screenshot("historical-screenshot")],
        ]
    )
    instance = _coordinator(session)

    first_data = instance.poll_events()
    assert [event.event_id for event in first_data.events] == ["initial"]
    assert instance._screenshot_history_checked is False
    assert "private response" not in caplog.text

    second_data = instance.poll_events()

    assert instance._screenshot_history_checked is True
    assert second_data.latest_screenshot_event_id == "historical-screenshot"
    assert [event.event_id for event in second_data.events] == [
        "initial",
        "historical-screenshot",
    ]


def test_malformed_screenshot_response_retries_until_successful_empty_result() -> None:
    session = _Session([[_event("initial")], None, [], []])
    instance = _coordinator(session)

    first_data = instance.poll_events()
    assert [event.event_id for event in first_data.events] == ["initial"]
    assert instance._screenshot_history_checked is False

    instance.poll_events()

    assert instance._screenshot_history_checked is True
    assert len(session.calls) == 4


def test_incremental_overlap_is_deduplicated_and_history_cap_is_retained() -> None:
    initial_events = [
        _event(
            f"retained-{index}",
            timestamp=f"2026-01-01T00:{index // 60:02d}:{index % 60:02d}Z",
        )
        for index in range(coordinator_module.HISTORY_EVENT_CAP)
    ]
    session = _Session(
        [
            initial_events,
            [],
            [
                _event("newest", timestamp="2026-01-02T00:00:00Z"),
                initial_events[-1],
            ],
        ]
    )
    instance = _coordinator(session)

    instance.poll_events()
    data = instance.poll_events()

    assert len(session.calls) == 3
    assert len(data.events) == coordinator_module.HISTORY_EVENT_CAP
    assert data.events[0].event_id == "newest"
    assert sum(event.event_id == "retained-199" for event in data.events) == 1
