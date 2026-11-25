"""Portal call grouping and authorization, without a running HA instance."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import types
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace as NS

import pytest


class _HTTPError(Exception):
    def __init__(self, *, headers):
        self.headers = headers


class _Coordinator:
    def __init__(self, **attrs):
        vars(self).update(attrs)


@pytest.fixture
def history(monkeypatch):
    source_dir = Path(__file__).resolve().parents[1] / "custom_components/abb_welcome"
    package = "abb_call_history_test"

    def stub(name, **attrs):
        item = types.ModuleType(name)
        vars(item).update(attrs)
        monkeypatch.setitem(sys.modules, name, item)
        return item

    responses = {}
    for name, status in [
        ("Unauthorized", 401),
        ("Forbidden", 403),
        ("NotFound", 404),
        ("BadRequest", 400),
        ("BadGateway", 502),
        ("ServiceUnavailable", 503),
    ]:
        responses[f"HTTP{name}"] = type(
            f"HTTP{name}", (_HTTPError,), {"status": status}
        )
    stub(
        "aiohttp",
        web=NS(
            **responses,
            Response=lambda **kwargs: NS(**kwargs),
            json_response=lambda body, **kwargs: NS(body=body, **kwargs),
        ),
    )
    stub("homeassistant")
    stub("homeassistant.auth")
    stub("homeassistant.auth.permissions")
    stub("homeassistant.auth.permissions.const", POLICY_READ="read")
    stub("homeassistant.components")
    stub(
        "homeassistant.components.http",
        KEY_HASS="ha",
        KEY_HASS_USER="user",
        HomeAssistantView=object,
    )
    stub("homeassistant.core", callback=lambda func: func)
    registry_module = stub(
        "homeassistant.helpers.entity_registry", async_get=lambda hass: hass.registry
    )
    stub("homeassistant.helpers", entity_registry=registry_module)
    stub(package, __path__=[str(source_dir)])
    stub(f"{package}.const", DOMAIN="abb_welcome")
    stub(
        f"{package}.coordinator",
        CALL_HISTORY_CACHE_SECONDS=15,
        CALL_HISTORY_PHOTO_CACHE_SECONDS=300,
        IntercomEvent=NS,
        ABBWelcomeCoordinator=NS(
            _timestamp_seconds=lambda value: datetime.fromisoformat(value).timestamp(),
        ),
    )
    name = f"{package}.call_history"
    source = os.environ.get("ABB_HISTORY_TEST_SOURCE", source_dir / "call_history.py")
    spec = importlib.util.spec_from_file_location(name, source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


JPEG = b"\xff\xd8ABB image\xff\xd9"


def event(id_, type_, *, station="", belongs_to="", photo=None):
    return NS(
        event_id=id_,
        event_type=type_,
        station_id=station,
        local_name=f"Entrance {station}" if station else "",
        belongs_to=belongs_to,
        image_data=photo,
        timestamp="2026-11-20T11:00:00+00:00",
    )


def test_only_explicit_call_links_link_photos_and_outcomes_per_door(history):
    events = (
            event("end", "call-terminated", belongs_to="answer"),
            event(
                "other-door",
                "screenshot",
                station="2",
                belongs_to="ring-1",
                photo=b"\xff\xd8wrong door",
            ),
            event("answer", "call-answered", station="1", belongs_to="ring-1"),
            event("right-photo", "screenshot", belongs_to="answer", photo=JPEG),
            event("view-photo", "screenshot", belongs_to="view", photo=JPEG),
            event("view", "call-surveillance", station="1"),
            event("unlinked", "screenshot", station="2", photo=JPEG),
            event("missed", "call-missed", belongs_to="ring-2"),
            event("ring-1", "ring", station="1"),
            event("ring-2", "ring", station="2"),
            event("ring-2", "ring", station="2"),
            event("ring-3", "ring", station="3"),
            event("ring-4", "ring", station="1"),
        )
    calls = {station: history.portal_calls(events, station) for station in "123"}
    assert {
        station: [(call.ring.event_id, call.outcome, call.photo) for call in rows]
        for station, rows in calls.items()
    } == {
        "1": [("ring-1", "answered", JPEG), ("ring-4", "ring", None)],
        "2": [("ring-2", "missed", None)],
        "3": [("ring-3", "ring", None)],
    }


def test_a_ring_without_a_station_is_not_shown_for_any_door(history):
    events = (event("ring", "ring"),)
    assert history.portal_calls(events, "1") == []
    assert history.portal_calls(events, "") == []


def test_history_is_bounded_and_rejects_cyclic_and_invalid_photos(history):
    calls = history.portal_calls(
        (
            event("answer", "call-answered", belongs_to="answer"),
            event("cycle", "screenshot", belongs_to="answer", photo=JPEG),
            event("wrong-format", "screenshot", belongs_to="0", photo=b"not jpeg"),
            event(
                "large",
                "screenshot",
                belongs_to="0",
                photo=b"\xff\xd8" + b"x" * history.MAX_JPEG_BYTES,
            ),
            *(event(str(index), "ring", station="1") for index in range(30)),
        ),
        "1",
    )
    assert len(calls) == 20
    assert all(call.photo is None for call in calls)


def test_history_rejects_a_station_mismatch_in_a_parent_chain(history):
    (call,) = history.portal_calls(
        (
            event("photo", "screenshot", belongs_to="answer", photo=JPEG),
            event("answer", "call-answered", station="2", belongs_to="ring"),
            event("ring", "ring", station="1"),
        ),
        "1",
    )
    assert call.photo is None and call.outcome == "ring"


def request(
    *, camera="camera.door", allow=None, call_id=None, fresh=None
):
    def entity(id_, entry="entry", platform="abb_welcome"):
        return NS(
            entity_id=id_, config_entry_id=entry, platform=platform, disabled_by=None
        )

    entities = {
        item.entity_id: item
        for item in [
            entity("camera.door"),
            entity("camera.back"),
            entity("event.abb_intercom"),
            entity("image.abb_screenshot"),
            entity("camera.other", "other"),
            entity("camera.generic", platform="generic"),
        ]
    }
    history_entities = {
        ("event", "test-gateway_intercom_events"): "event.abb_intercom",
        ("image", "test-gateway_latest_screenshot"): "image.abb_screenshot",
        # Simulate an invalid cross-entry registry mapping.
        ("event", "other-gateway_intercom_events"): "event.abb_intercom",
    }
    registry = NS(
        async_get=entities.get,
        async_get_entity_id=lambda kind, _, uid: history_entities.get((kind, uid)),
    )

    async def fetch_history(include_photos, **_kwargs):
        ring = event("ring", "ring", station="1")
        return (
            (
                event("shot", "screenshot", belongs_to="ring", photo=JPEG),
                ring,
            )
            if include_photos
            else (ring,)
        )

    entries = {
        id_: NS(domain="abb_welcome", data={"gateway_uuid": gw})
        for id_, gw in [
            ("entry", "test-gateway"),
            ("other", "other-gateway"),
        ]
    }
    camera_states = {
        "camera.door": NS(attributes={"station_id": "1"}),
        "camera.back": NS(attributes={"station_id": "2"}),
    }
    hass = NS(
        registry=registry,
        states=NS(get=camera_states.get),
        config_entries=NS(async_get_entry=entries.get),
        data={
            "abb_welcome": {
                id_: {
                    "coordinator": _Coordinator(
                        data=NS(events=[]),
                        has_certs=True,
                        async_fetch_call_history=fetch_history,
                    )
                }
                for id_ in entries
            },
        },
    )
    req = type("Request", (dict,), {})()
    if allow is not None:
        req["user"] = NS(
            permissions=NS(
                check_entity=lambda id_, policy: policy == "read" and id_ in allow
            )
        )
    req.query = {"camera": camera}
    if call_id is not None:
        req.query["call_id"] = call_id
    if fresh is not None:
        req.query["fresh"] = fresh
    req.app = {"ha": hass}
    return req


@pytest.mark.parametrize(
    ("camera", "allow", "code"),
    [
        ("camera.door", None, 401),
        ("camera.door", {"event.abb_intercom"}, 403),
        ("camera.door", {"camera.door", "image.abb_screenshot"}, 403),
        ("camera.generic", {"camera.generic", "event.abb_intercom"}, 403),
        ("camera.other", {"camera.other", "event.abb_intercom"}, 403),
        ("not-a-camera", set(), 400),
    ],
)
def test_request_checks_authentication_integration_and_entity_access(
    history, camera, allow, code
):
    with pytest.raises(_HTTPError) as error:
        asyncio.run(
            history.ABBCallHistoryView().get(request(camera=camera, allow=allow))
        )
    assert error.value.status == code


def test_metadata_excludes_jpeg_and_image_permission_is_checked_for_each_request(
    history,
):
    view = history.ABBCallHistoryView()
    assert view.requires_auth is True
    permissions = {"camera.door", "event.abb_intercom"}
    without_photo = asyncio.run(view.get(request(allow=permissions)))
    assert without_photo.body == {
        "calls": [
            {
                "id": "ring",
                "timestamp": "2026-11-20T11:00:00+00:00",
                "station": "Entrance 1",
                "outcome": "ring",
                "has_photo": False,
            }
        ]
    }
    assert "no-store" in without_photo.headers["Cache-Control"]
    with pytest.raises(_HTTPError) as error:
        asyncio.run(view.get(request(allow=permissions, call_id="ring")))
    assert error.value.status == 403
    permissions.add("image.abb_screenshot")
    assert (
        asyncio.run(view.get(request(allow=permissions))).body["calls"][0]["has_photo"]
        is True
    )
    photo = asyncio.run(view.get(request(allow=permissions, call_id="ring")))
    assert photo.body == JPEG and photo.content_type == "image/jpeg"
    assert "no-store" in photo.headers["Cache-Control"]
    with pytest.raises(_HTTPError) as error:
        asyncio.run(view.get(request(allow=permissions, call_id="shot")))
    assert error.value.status == 404


def test_portal_failure_is_not_reported_as_empty_history(history):
    req = request(allow={"camera.door", "event.abb_intercom"})

    async def unavailable(_include_photos, **_kwargs):
        raise ValueError("Synthetic invalid ABB response")

    req.app["ha"].data["abb_welcome"]["entry"][
        "coordinator"
    ].async_fetch_call_history = unavailable
    with pytest.raises(_HTTPError) as error:
        asyncio.run(history.ABBCallHistoryView().get(req))
    assert error.value.status == 502


def test_warm_metadata_survives_new_http_requests_and_refresh_is_separate(
    history, monkeypatch
):
    clock = [1000]
    monkeypatch.setattr(history, "monotonic", lambda: clock[0])
    permissions = {"camera.door", "event.abb_intercom", "image.abb_screenshot"}
    req = request(allow=permissions)
    coordinator = req.app["ha"].data["abb_welcome"]["entry"]["coordinator"]
    original = coordinator.async_fetch_call_history
    fetches = []

    async def fetch(include_photos, **kwargs):
        fetches.append(include_photos)
        return await original(include_photos, **kwargs)

    coordinator.async_fetch_call_history = fetch
    view = history.ABBCallHistoryView()
    first = asyncio.run(view.get(req)).body
    assert first["calls"][0]["has_photo"] is True
    assert fetches == [True]

    clock[0] += 30
    reload = request(allow=permissions)
    reload.app = req.app
    cached = asyncio.run(view.get(reload))
    assert cached.body == {**first, "stale": True}
    assert fetches == [True], "a new tab must not wait for ABB"
    assert "no-store" in cached.headers["Cache-Control"]
    all_cached_rows = view._rows[coordinator][(True, "1")].calls
    assert all(
        not isinstance(value, bytes)
        for row in all_cached_rows
        for value in row.values()
    )

    refresh = request(allow=permissions, fresh="1")
    refresh.app = req.app
    assert asyncio.run(view.get(refresh)).body == first
    assert fetches == [True, True]

    permissions.remove("image.abb_screenshot")
    assert asyncio.run(view.get(reload)).body["calls"][0]["has_photo"] is False
    assert fetches == [True, True, False]
    permissions.remove("event.abb_intercom")
    with pytest.raises(_HTTPError) as error:
        asyncio.run(view.get(reload))
    assert error.value.status == 403
    assert fetches == [True, True, False]

    permissions.add("event.abb_intercom")
    clock[0] += history.METADATA_CACHE_SECONDS
    assert asyncio.run(view.get(reload)).body["calls"][0]["has_photo"] is False
    assert fetches == [True, True, False, False]


def test_incomplete_photos_are_not_cached_or_exposed_without_permission(history):
    permissions = {"camera.door", "event.abb_intercom", "image.abb_screenshot"}
    req = request(allow=permissions)
    coordinator = req.app["ha"].data["abb_welcome"]["entry"]["coordinator"]
    original = coordinator.async_fetch_call_history
    fetches = []

    class Partial(tuple):
        photos_incomplete = True

    async def fetch(include_photos, **kwargs):
        fetches.append(include_photos)
        result = await original(include_photos, **kwargs)
        return Partial(result) if include_photos and fetches.count(True) == 2 else result

    coordinator.async_fetch_call_history = fetch
    view = history.ABBCallHistoryView()
    assert asyncio.run(view.get(req)).body["calls"][0]["has_photo"]
    refresh = request(allow=permissions, fresh="1")
    refresh.app = req.app
    assert asyncio.run(view.get(refresh)).body["photos_incomplete"] is True
    assert (True, "1") not in view._rows[coordinator]
    assert "photos_incomplete" not in asyncio.run(view.get(req)).body
    assert fetches == [True, True, True]
    permissions.remove("image.abb_screenshot")
    assert "photos_incomplete" not in asyncio.run(view.get(req)).body
    assert fetches[-1] is False


def test_multiple_linked_photos_are_indexed_and_permission_scoped(history):
    permissions = {"camera.door", "event.abb_intercom", "image.abb_screenshot"}
    req = request(allow=permissions)
    coordinator = req.app["ha"].data["abb_welcome"]["entry"]["coordinator"]
    second = b"\xff\xd8second"

    async def fetch(include_photos, **_kwargs):
        ring = event("ring", "ring", station="1")
        if not include_photos:
            return (ring,)
        return (ring, event("a", "screenshot", belongs_to="ring", photo=JPEG),
                event("b", "screenshot", belongs_to="ring", photo=second),
                event("unlinked", "screenshot", photo=JPEG))

    coordinator.async_fetch_call_history = fetch
    view = history.ABBCallHistoryView()
    assert asyncio.run(view.get(req)).body["calls"][0]["photo_count"] == 2
    photo_req = request(allow=permissions, call_id="ring")
    photo_req.app = req.app
    assert asyncio.run(view.get(photo_req)).body == JPEG
    photo_req.query["photo_index"] = "1"
    assert asyncio.run(view.get(photo_req)).body == second
    photo_req.query["photo_index"] = "2"
    with pytest.raises(_HTTPError) as error:
        asyncio.run(view.get(photo_req))
    assert error.value.status == 404
    permissions.remove("image.abb_screenshot")
    with pytest.raises(_HTTPError) as error:
        asyncio.run(view.get(photo_req))
    assert error.value.status == 403
    assert "photo_count" not in asyncio.run(view.get(req)).body["calls"][0]


def test_each_door_lists_only_its_own_calls_from_a_shared_cache(history):
    permissions = {"camera.door", "camera.back", "event.abb_intercom"}
    door = request(allow=permissions)
    back = request(camera="camera.back", allow=permissions)
    back.app = door.app
    view = history.ABBCallHistoryView()
    assert [row["id"] for row in asyncio.run(view.get(door)).body["calls"]] == ["ring"]
    assert asyncio.run(view.get(back)).body["calls"] == []
    assert [row["id"] for row in asyncio.run(view.get(door)).body["calls"]] == ["ring"]
