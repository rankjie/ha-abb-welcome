"""Focused tests for cold-start portal screenshot lookup."""

from __future__ import annotations

import asyncio
import base64
import http.client
import importlib.util
import json
import socket
import sys
import types
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
import requests
import urllib3

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
storage = types.ModuleType("homeassistant.helpers.storage")


class _Store:
    """In-memory stand-in for Home Assistant's JSON store."""

    def __init__(self, *_args: Any, data: Any = None, **_kwargs: Any) -> None:
        self.data = data
        self.saved: Any = None

    def __class_getitem__(cls, _item):
        return cls

    async def async_load(self) -> Any:
        return self.data

    def async_delay_save(self, data_func, _delay: float) -> None:
        self.saved = data_func()


storage.Store = _Store
homeassistant.config_entries = config_entries
homeassistant.core = core
helpers.update_coordinator = update_coordinator
sys.modules["homeassistant.config_entries"] = config_entries
sys.modules["homeassistant.core"] = core
sys.modules["homeassistant.helpers.update_coordinator"] = update_coordinator
sys.modules["homeassistant.helpers.storage"] = storage

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
    instance._screenshot_history_checked = False
    instance._portal_url = coordinator_module.DEFAULT_PORTAL_URL
    instance._data = coordinator_module.ABBWelcomeData()
    instance._ring_poll_task = None
    instance._station_names = {}
    instance._screenshot_store = _Store()
    instance._make_session = lambda: (session, [])
    instance._cleanup = lambda _paths: None
    return instance


def test_dedicated_history_ignores_mixed_cache_and_pages_related_events(
    monkeypatch,
) -> None:
    instance = _coordinator(_Session([]))
    instance._data.events = [
        coordinator_module.IntercomEvent("view", "call-surveillance", "", "")
    ]
    observed = []

    class Response:
        def __init__(self, events):
            self.raw = json.dumps({"events": events}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def raise_for_status(self):
            pass

        def iter_content(self, **_kwargs):
            return iter([self.raw])

    def get(_url, *, params, stream, allow_redirects, timeout):
        assert stream and not allow_redirects and 0 < timeout <= 4
        types, page = params["type"], params["pagination_page"]
        observed.append((types, page))
        if types == coordinator_module.RING_HISTORY_TYPE:
            return Response(
                [
                    dict(_event("real-ring"), belongsTo=None),
                    _event("view-unexpected", event_type="call-surveillance"),
                ]
            )
        if types == coordinator_module.CALL_OUTCOME_HISTORY_TYPES and page == 1:
            return Response(
                [
                    _event(f"unrelated-{number}", event_type="call-terminated")
                    for number in range(20)
                ]
            )
        if types == coordinator_module.CALL_OUTCOME_HISTORY_TYPES:
            return Response(
                [
                    dict(
                        _event("missed", event_type="call-missed"),
                        belongsTo="real-ring",
                    )
                ]
            )
        assert types == coordinator_module.SCREENSHOT_HISTORY_TYPE
        return Response([dict(_screenshot("visitor-photo"), belongsTo="real-ring")])

    def use_session():
        return types.SimpleNamespace(get=get, close=lambda: None), []

    monkeypatch.setattr(instance, "_make_session", use_session)
    events = instance._fetch_portal_call_history(include_photos=False)
    assert events[0].event_id == "real-ring"
    assert events[-1].belongs_to == "real-ring"
    assert len(events) == 22 and len(observed) == 3
    assert observed[-1] == (coordinator_module.CALL_OUTCOME_HISTORY_TYPES, 2)
    observed.clear()
    events = instance._fetch_portal_call_history(include_photos=True)
    assert events[-1].image_data == b"\xff\xd8jpeg data"
    assert observed[-1] == (coordinator_module.SCREENSHOT_HISTORY_TYPE, 1)
    assert [event.event_id for event in instance._data.events] == ["view"]


def test_photo_budget_survives_slow_outcomes_and_partial_is_not_cached(monkeypatch):
    instance = _coordinator(types.SimpleNamespace(close=lambda: None))
    clock = [0.0]
    monkeypatch.setattr(coordinator_module.time, "monotonic", lambda: clock[0])
    seen = []
    failures = [True]

    def read(_session, kind, _page, _limit, deadline):
        seen.append(kind)
        if kind == coordinator_module.RING_HISTORY_TYPE:
            return [coordinator_module.IntercomEvent("ring", "ring", "", "")]
        if kind == coordinator_module.CALL_OUTCOME_HISTORY_TYPES:
            clock[0] = deadline
            raise requests.Timeout()
        assert deadline > clock[0]
        if failures[0]:
            raise requests.Timeout()
        return [coordinator_module.IntercomEvent("shot", "screenshot", "", "", belongs_to="ring")]

    instance._read_call_history_page = read
    instance._call_history_lock = asyncio.Lock()
    instance._call_history_cache = {}

    async def executor(func, *args):
        return func(*args)

    instance.hass = types.SimpleNamespace(async_add_executor_job=executor)

    async def run():
        partial = await instance.async_fetch_call_history(True)
        assert partial.photos_incomplete
        assert True in instance._call_history_cache
        assert await instance.async_fetch_call_history(True, allow_partial=True) is partial
        failures[0] = False
        complete = await instance.async_fetch_call_history(True)
        assert not complete.photos_incomplete
        assert complete[-1].event_id == "shot"
        assert await instance.async_fetch_call_history(True) is complete

    asyncio.run(run())
    assert seen.count(coordinator_module.SCREENSHOT_HISTORY_TYPE) == 2


def test_photo_requests_reuse_a_read_as_old_as_the_row_cache(monkeypatch):
    instance = _coordinator(types.SimpleNamespace(close=lambda: None))
    clock = [0.0]
    monkeypatch.setattr(coordinator_module.time, "monotonic", lambda: clock[0])
    reads = []

    def fetch(include_photos):
        reads.append(include_photos)
        return (coordinator_module.IntercomEvent(f"ring-{len(reads)}", "ring", "", ""),)

    instance._fetch_portal_call_history = fetch
    instance._call_history_lock = asyncio.Lock()
    instance._call_history_cache = {}

    async def executor(func, *args):
        return func(*args)

    instance.hass = types.SimpleNamespace(async_add_executor_job=executor)

    async def run():
        rows = await instance.async_fetch_call_history(True)
        clock[0] = coordinator_module.CALL_HISTORY_PHOTO_CACHE_SECONDS - 1
        assert await instance.async_fetch_call_history(True, allow_partial=True) is rows
        assert len(reads) == 1
        # A row request after the short window reads the portal again.
        assert await instance.async_fetch_call_history(True) is not rows
        assert len(reads) == 2
        clock[0] += coordinator_module.CALL_HISTORY_PHOTO_CACHE_SECONDS
        await instance.async_fetch_call_history(True, allow_partial=True)
        assert len(reads) == 3

    asyncio.run(run())


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


def test_cold_start_uses_single_screenshot_only_query() -> None:
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
    assert "newer_than_id" not in session.calls[0][1]
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
    assert "newer_than_id" not in session.calls[0][1]


def test_empty_screenshot_query_is_checked_and_latest_page_is_polled_again() -> None:
    session = _Session(
        [[_event("initial")], [], [_event("newest"), _event("initial")]]
    )
    instance = _coordinator(session)

    instance.poll_events()
    data = instance.poll_events()

    assert len(session.calls) == 3
    assert instance._screenshot_history_checked is True
    assert "newer_than_id" not in session.calls[-1][1]
    assert session.calls[-1][1]["type"] == coordinator_module.HISTORY_TYPES
    assert [event.event_id for event in data.events] == ["newest", "initial"]


def test_poll_failure_logs_safe_error_class_without_exception_details(caplog) -> None:
    session = _Session(
        [requests.ConnectionError("private response must not be logged")]
    )
    instance = _coordinator(session)

    instance.poll_events()

    assert "Portal history poll failed (kind=connection, status=none)" in caplog.text
    assert "private response" not in caplog.text


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        (requests.exceptions.SSLError("private TLS details"), "tls"),
        (
            requests.ConnectionError(socket.gaierror("private DNS details")),
            "dns",
        ),
        (
            requests.ConnectionError(
                urllib3.exceptions.ProtocolError(
                    "private protocol details",
                    http.client.RemoteDisconnected("private remote details"),
                )
            ),
            "remote-close",
        ),
        (
            requests.ConnectionError(
                ConnectionResetError("private reset details")
            ),
            "reset",
        ),
        (
            requests.ConnectionError(
                ConnectionRefusedError("private refusal details")
            ),
            "refused",
        ),
    ],
)
def test_poll_failure_logs_safe_connection_cause(caplog, error, kind) -> None:
    session = _Session([error])
    instance = _coordinator(session)

    instance.poll_events()

    assert f"Portal history poll failed (kind={kind}, status=none)" in caplog.text
    assert "private" not in caplog.text


def test_http_poll_failure_logs_status_without_response_details(caplog) -> None:
    response = requests.Response()
    response.status_code = 400
    session = _Session(
        [
            requests.HTTPError(
                "private response must not be logged",
                response=response,
            )
        ]
    )
    instance = _coordinator(session)

    instance.poll_events()

    assert "Portal history poll failed (kind=http, status=400)" in caplog.text
    assert "private response" not in caplog.text


def test_repolling_latest_page_advances_screenshot_and_deduplicates() -> None:
    old_screenshot = _screenshot("old-screenshot", "2026-01-01T00:00:00Z")
    new_screenshot = _screenshot("new-screenshot", "2026-01-02T00:00:01Z")
    newest_ring = _event("new-ring", timestamp="2026-01-02T00:00:00Z")
    latest_page = [new_screenshot, newest_ring, old_screenshot]
    session = _Session([[old_screenshot], latest_page, latest_page])
    instance = _coordinator(session)

    first_screenshot_id = instance.poll_events().latest_screenshot_event_id
    second_screenshot_id = instance.poll_events().latest_screenshot_event_id
    third_data = instance.poll_events()

    assert first_screenshot_id == "old-screenshot"
    assert second_screenshot_id == "new-screenshot"
    assert third_data.latest_screenshot_event_id == "new-screenshot"
    assert [event.event_id for event in third_data.events] == [
        "new-screenshot",
        "new-ring",
        "old-screenshot",
    ]
    assert all("newer_than_id" not in params for _url, params in session.calls)


def test_station_snapshots_keep_the_newest_image_from_each_station() -> None:
    def ring(event_id: str, station_id: str, timestamp: str):
        return _event(
            event_id,
            timestamp=timestamp,
            payload=base64.b64encode(
                json.dumps({"local_id": f"sip:{station_id}@example.invalid"}).encode()
            ).decode(),
        )

    def screenshot(event_id: str, ring_id: str, timestamp: str):
        event = _screenshot(event_id, timestamp)
        event["belongsTo"] = ring_id
        event["payload"] = base64.b64encode(b"\xff\xd8" + event_id.encode()).decode()
        return event

    old_front = screenshot("old-front", "ring-old-front", "2026-01-01T12:00:01Z")
    new_front = screenshot("new-front", "ring-new-front", "2026-01-02T12:00:01Z")
    back = screenshot("back", "ring-back", "2026-01-02T11:00:01Z")
    old_page = [old_front, ring("ring-old-front", "01", "2026-01-01T12:00:00Z")]
    latest_page = [
        new_front,
        ring("ring-new-front", "01", "2026-01-02T12:00:00Z"),
        back,
        ring("ring-back", "02", "2026-01-02T11:00:00Z"),
        *old_page,
    ]
    instance = _coordinator(_Session([old_page, latest_page, latest_page]))
    assert instance.poll_events().latest_screenshots_by_station["01"].event_id == (
        "old-front"
    )

    for _ in range(2):
        data = instance.poll_events()
        assert data.latest_screenshot_event_id == "new-front"
        assert data.latest_screenshot == b"\xff\xd8new-front"
        assert data.latest_screenshots_by_station["01"].event_id == "new-front"
        assert data.latest_screenshots_by_station["01"].image_data == (
            data.latest_screenshot
        )
        assert data.latest_screenshots_by_station["02"].event_id == "back"
        assert data.latest_screenshots_by_station["02"].image_data == b"\xff\xd8back"


def test_ring_poll_refreshes_until_a_new_screenshot_arrives(monkeypatch) -> None:
    async def _run() -> None:
        instance = _coordinator(_Session([]))
        instance._data.latest_screenshot_event_id = "before-ring"
        refreshes = 0

        async def _refresh() -> None:
            nonlocal refreshes
            refreshes += 1
            if refreshes == 2:
                instance._data.latest_screenshot_event_id = "after-ring"

        class _Hass:
            @staticmethod
            def async_create_background_task(coro, *, name):
                return asyncio.create_task(coro, name=name)

        instance.hass = _Hass()
        instance.async_request_refresh = _refresh
        monkeypatch.setattr(
            coordinator_module,
            "RING_EVENT_POLL_DELAYS",
            (0.0, 0.0, 0.0),
        )

        instance.async_schedule_ring_poll()
        task = instance._ring_poll_task
        assert task is not None
        await task

        assert refreshes == 2
        assert instance._ring_poll_task is None

    asyncio.run(_run())


def test_repeated_ring_replaces_the_existing_poll_sequence() -> None:
    async def _run() -> None:
        instance = _coordinator(_Session([]))
        started = asyncio.Event()
        cancelled = 0

        async def _poll(_previous_id: str) -> None:
            nonlocal cancelled
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled += 1
                raise

        class _Hass:
            @staticmethod
            def async_create_background_task(coro, *, name):
                return asyncio.create_task(coro, name=name)

        instance.hass = _Hass()
        instance._async_poll_for_new_screenshot = _poll

        instance.async_schedule_ring_poll()
        await started.wait()
        started.clear()
        instance.async_schedule_ring_poll()
        await started.wait()

        assert cancelled == 1
        await instance.async_stop_ring_poll()

    asyncio.run(_run())


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


def _jpeg_screenshot(event_id: str, timestamp: str) -> dict[str, Any]:
    event = _screenshot(event_id, timestamp)
    event["payload"] = base64.b64encode(b"\xff\xd8" + event_id.encode()).decode()
    return event


def _surveillance(event_id: str, station_id: str, name: str, timestamp: str):
    return _event(
        event_id,
        event_type="call-surveillance",
        timestamp=timestamp,
        payload=base64.b64encode(
            json.dumps(
                {
                    "local_id": f"sip:{station_id}@example.invalid",
                    "local_name": name,
                }
            ).encode()
        ).decode(),
    )


def _linked(event: dict[str, Any], root_id: str) -> dict[str, Any]:
    event["belongsTo"] = root_id
    return event


def test_live_view_screenshots_follow_their_surveillance_call_station() -> None:
    # Live views opened from HA produce no ring: the screenshot and the
    # station-less call-terminated link to a call-surveillance root instead.
    page = [
        _linked(
            _event(
                "garage-end",
                event_type="call-terminated",
                timestamp="2026-11-15T13:16:51+01:00",
            ),
            "garage-view",
        ),
        _linked(
            _jpeg_screenshot("garage-shot", "2026-11-15T13:16:27+01:00"),
            "garage-view",
        ),
        _surveillance(
            "garage-view", "100000003", "Parking Garage", "2026-11-15T13:16:21+01:00"
        ),
        _linked(
            _jpeg_screenshot("inner-shot", "2026-11-15T13:16:01+01:00"),
            "inner-view",
        ),
        _surveillance("inner-view", "100000002", "Inner", "2026-11-15T13:15:58+01:00"),
    ]
    session = _Session([page])
    instance = _coordinator(session)

    by_station = instance.poll_events().latest_screenshots_by_station

    assert "com.abb.ispf.event.welcome.call-surveillance" in (
        session.calls[0][1]["type"].split(",")
    )
    assert by_station["100000002"].event_id == "inner-shot"
    assert by_station["100000003"].event_id == "garage-shot"
    assert by_station["100000003"].local_name == "Parking Garage"


def test_station_screenshots_survive_restart_until_a_newer_frame_arrives() -> None:
    async def _run() -> None:
        before_restart = _coordinator(_Session([[]]))
        before_restart.hass = types.SimpleNamespace(
            async_add_executor_job=lambda func: asyncio.sleep(0, func()),
        )
        before_restart._data.latest_screenshots_by_station["100000001"] = (
            coordinator_module.IntercomEvent(
                event_id="outdoor-shot",
                event_type="screenshot",
                timestamp="2026-11-13T12:07:15+01:00",
                sender="",
                image_data=b"\xff\xd8outdoor",
                station_id="100000001",
                local_name="Outdoor 1",
            )
        )
        before_restart._data.latest_screenshots_by_station["100000002"] = (
            coordinator_module.IntercomEvent(
                event_id="inner-old",
                event_type="screenshot",
                timestamp="2026-11-14T12:26:02+01:00",
                sender="",
                image_data=b"\xff\xd8inner-old",
                station_id="100000002",
            )
        )
        stored = before_restart._station_screenshots_payload()

        # After a restart the first page no longer reaches Outdoor 1's frame,
        # while Inner has a newer one.
        page = [
            _linked(
                _jpeg_screenshot("inner-new", "2026-11-15T13:11:23+01:00"),
                "inner-view",
            ),
            _surveillance(
                "inner-view", "100000002", "Inner", "2026-11-15T13:11:18+01:00"
            ),
        ]
        after_restart = _coordinator(_Session([page]))
        after_restart._screenshot_store = _Store(data=stored)
        after_restart.hass = before_restart.hass
        await after_restart.async_restore_station_screenshots()
        data = await after_restart._async_update_data()

        outdoor = data.latest_screenshots_by_station["100000001"]
        assert outdoor.event_id == "outdoor-shot"
        assert outdoor.image_data == b"\xff\xd8outdoor"
        assert outdoor.local_name == "Outdoor 1"
        assert data.latest_screenshots_by_station["100000002"].event_id == "inner-new"
        assert set(after_restart._screenshot_store.saved["stations"]) == {
            "100000001",
            "100000002",
        }

    asyncio.run(_run())


def test_older_page_frame_does_not_replace_a_newer_restored_frame() -> None:
    async def _run() -> None:
        restored = {
            "stations": {
                "100000002": {
                    "event_id": "inner-new",
                    "timestamp": "2026-11-15T13:11:23+01:00",
                    "local_name": "",
                    "image": base64.b64encode(b"\xff\xd8new").decode(),
                }
            }
        }
        page = [
            _linked(
                _jpeg_screenshot("inner-older", "2026-11-15T13:00:00+01:00"),
                "inner-view",
            ),
            _surveillance(
                "inner-view", "100000002", "Inner", "2026-11-15T12:59:58+01:00"
            ),
        ]
        instance = _coordinator(_Session([page]))
        instance._screenshot_store = _Store(data=restored)
        await instance.async_restore_station_screenshots()

        data = instance.poll_events()

        assert data.latest_screenshots_by_station["100000002"].event_id == "inner-new"

    asyncio.run(_run())


def test_malformed_screenshot_cache_is_ignored(caplog) -> None:
    async def _run() -> None:
        instance = _coordinator(_Session([]))
        instance._screenshot_store = _Store(
            data={
                "stations": {
                    "100000002": {
                        "event_id": "x",
                        "timestamp": "t",
                        "image": "not base64!",
                    }
                }
            }
        )
        await instance.async_restore_station_screenshots()
        assert instance._data.latest_screenshots_by_station == {}

    asyncio.run(_run())
    assert "Ignoring malformed cached station screenshot" in caplog.text
