"""Read-only, authenticated projection of the ABB portal call history."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import monotonic
from typing import TYPE_CHECKING
from weakref import WeakKeyDictionary

import requests
from aiohttp import web
from homeassistant.auth.permissions.const import POLICY_READ
from homeassistant.components.http import KEY_HASS, KEY_HASS_USER, HomeAssistantView
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN
from .coordinator import (
    CALL_HISTORY_CACHE_SECONDS,
    ABBWelcomeCoordinator,
    IntercomEvent,
)

if TYPE_CHECKING:
    from homeassistant.auth.models import User

MAX_CALLS = 20
MAX_JPEG_BYTES = 2 * 1024 * 1024
METADATA_CACHE_SECONDS = 5 * 60
PRIVATE_HEADERS = {
    "Cache-Control": "private, no-store",
    "X-Content-Type-Options": "nosniff",
}
_OUTCOMES = {
    "call-answered": "answered",
    "call-missed": "missed",
    "call-terminated": "ended",
}


@dataclass
class PortalCall:
    ring: IntercomEvent
    outcome: str = "ring"
    photos: list[bytes] = field(default_factory=list)

    @property
    def photo(self) -> bytes | None:
        return self.photos[0] if self.photos else None

    def as_dict(self, *, photo_allowed: bool) -> dict[str, str | bool | None]:
        row = {
            "id": self.ring.event_id,
            "timestamp": _iso_timestamp(self.ring.timestamp),
            "station": self.ring.local_name or self.ring.station_id,
            "outcome": self.outcome,
            "has_photo": photo_allowed and self.photo is not None,
        }
        if photo_allowed and len(self.photos) > 1:
            row["photo_count"] = len(self.photos)
        return row


@dataclass(frozen=True)
class _HistoryRows:
    saved_at: float
    calls: tuple[dict[str, str | bool | None], ...]

    def response(self, *, stale: bool = False) -> web.Response:
        data: dict[str, object] = {"calls": list(self.calls)}
        if stale:
            data["stale"] = True
        return web.json_response(data, headers=PRIVATE_HEADERS)


def _iso_timestamp(value: str | float) -> str | None:
    try:
        timestamp = ABBWelcomeCoordinator._timestamp_seconds(value)
        if timestamp is not None:
            return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        pass
    return None


def _related_call(event: IntercomEvent, events: dict[str, IntercomEvent]) -> str | None:
    """Resolve only explicit ABB parent links, never timestamps or gateway IDs."""
    parent_id = event.belongs_to
    seen = {event.event_id}
    station_id = event.station_id
    while parent_id and parent_id not in seen:
        parent = events.get(parent_id)
        if parent is None or parent.event_type == "call-surveillance":
            break
        if station_id and parent.station_id and station_id != parent.station_id:
            break
        station_id = station_id or parent.station_id
        if parent.event_type == "ring":
            return parent_id
        if parent.event_type not in _OUTCOMES:
            break
        seen.add(parent_id)
        parent_id = parent.belongs_to
    return None


def portal_calls(events: tuple[IntercomEvent, ...]) -> list[PortalCall]:
    """Build at most 20 newest calls from the dedicated portal history read."""
    by_id: dict[str, IntercomEvent] = {}
    calls: dict[str, PortalCall] = {}
    for event in events:
        if not event.event_id or event.event_id in by_id:
            continue
        by_id[event.event_id] = event
        if event.event_type == "ring" and len(calls) < MAX_CALLS:
            calls[event.event_id] = PortalCall(event)

    for event in by_id.values():
        if event.event_type != "screenshot" and event.event_type not in _OUTCOMES:
            continue
        root = _related_call(event, by_id)
        call = calls.get(root) if root is not None else None
        if call is None:
            continue
        if event.event_type == "screenshot":
            photo = event.image_data
            if (
                photo
                and len(photo) <= MAX_JPEG_BYTES
                and photo.startswith(b"\xff\xd8")
            ):
                call.photos.append(photo)
        elif call.outcome == "ring" or (
            call.outcome == "ended" and event.event_type != "call-terminated"
        ):
            # A later teardown doesn't hide a known answer or missed result.
            call.outcome = _OUTCOMES[event.event_type]
    return list(calls.values())


def _can_read(user: User, entity: er.RegistryEntry | None) -> bool:
    return bool(
        entity is not None
        and entity.disabled_by is None
        and user.permissions.check_entity(entity.entity_id, POLICY_READ)
    )


def _gateway_entity(
    registry: er.EntityRegistry, entry_id: str, kind: str, unique_id: str
) -> er.RegistryEntry | None:
    entity_id = registry.async_get_entity_id(kind, DOMAIN, unique_id)
    entity = registry.async_get(entity_id) if entity_id else None
    return entity if entity is not None and entity.config_entry_id == entry_id else None


class ABBCallHistoryView(HomeAssistantView):
    """Return call rows or one linked JPEG without starting intercom media."""

    url = f"/api/{DOMAIN}/call_history"
    name = f"api:{DOMAIN}:call_history"
    requires_auth = True

    def __init__(self) -> None:
        super().__init__()
        # Per coordinator and image permission, never store JPEG data here.
        # An unloaded gateway loses its cache with its coordinator.
        self._rows: WeakKeyDictionary[
            ABBWelcomeCoordinator, dict[bool, _HistoryRows]
        ] = WeakKeyDictionary()

    async def get(self, request: web.Request) -> web.Response:
        user = request.get(KEY_HASS_USER)
        if user is None:
            raise web.HTTPUnauthorized(headers=PRIVATE_HEADERS)
        camera_id = request.query.get("camera", "")
        call_id = request.query.get("call_id")
        photo_index_raw = request.query.get("photo_index")
        fresh = request.query.get("fresh")
        if (
            not camera_id.startswith("camera.")
            or not camera_id[7:]
            or len(camera_id) > 255
        ):
            raise web.HTTPBadRequest(headers=PRIVATE_HEADERS)
        if call_id is not None and not 0 < len(call_id) <= 256:
            raise web.HTTPBadRequest(headers=PRIVATE_HEADERS)
        if photo_index_raw is not None and (
            call_id is None or not photo_index_raw.isascii()
            or not photo_index_raw.isdecimal() or len(photo_index_raw) > 2
            or int(photo_index_raw) >= 30
        ):
            raise web.HTTPBadRequest(headers=PRIVATE_HEADERS)
        photo_index = int(photo_index_raw) if photo_index_raw is not None else 0
        if fresh is not None and (fresh != "1" or call_id is not None):
            raise web.HTTPBadRequest(headers=PRIVATE_HEADERS)

        hass = request.app[KEY_HASS]
        registry = er.async_get(hass)
        camera = registry.async_get(camera_id)
        if camera is None or camera.platform != DOMAIN or not _can_read(user, camera):
            raise web.HTTPForbidden(headers=PRIVATE_HEADERS)
        entry_id = camera.config_entry_id
        entry = hass.config_entries.async_get_entry(entry_id) if entry_id else None
        if entry is None or entry.domain != DOMAIN:
            raise web.HTTPNotFound(headers=PRIVATE_HEADERS)
        coordinator = hass.data.get(DOMAIN, {}).get(entry_id, {}).get("coordinator")
        if not coordinator or not coordinator.has_certs:
            raise web.HTTPServiceUnavailable(headers=PRIVATE_HEADERS)

        gateway_uuid = entry.data.get("gateway_uuid", "unknown")
        event_entity = _gateway_entity(
            registry, entry_id, "event", f"{gateway_uuid}_intercom_events"
        )
        if not _can_read(user, event_entity):
            raise web.HTTPForbidden(headers=PRIVATE_HEADERS)
        image_entity = _gateway_entity(
            registry, entry_id, "image", f"{gateway_uuid}_latest_screenshot"
        )
        photo_allowed = _can_read(user, image_entity)
        if call_id is not None and not photo_allowed:
            raise web.HTTPForbidden(headers=PRIVATE_HEADERS)

        if call_id is None and fresh is None:
            by_permission = self._rows.get(coordinator)
            snapshot = (
                by_permission.get(photo_allowed) if by_permission is not None else None
            )
            if snapshot is not None:
                age = monotonic() - snapshot.saved_at
                if age < METADATA_CACHE_SECONDS:
                    return snapshot.response(stale=age >= CALL_HISTORY_CACHE_SECONDS)
                by_permission.pop(photo_allowed, None)

        try:
            events = await coordinator.async_fetch_call_history(
                photo_allowed, allow_partial=call_id is not None,
                force_refresh=fresh is not None,
            )
        except (requests.RequestException, OSError, ValueError, TypeError) as err:
            raise web.HTTPBadGateway(headers=PRIVATE_HEADERS) from err
        if (
            hass.data.get(DOMAIN, {}).get(entry_id, {}).get("coordinator")
            is not coordinator
        ):
            raise web.HTTPServiceUnavailable(headers=PRIVATE_HEADERS)
        if not _can_read(user, camera) or not _can_read(user, event_entity):
            raise web.HTTPForbidden(headers=PRIVATE_HEADERS)
        photo_allowed = photo_allowed and _can_read(user, image_entity)
        if call_id is not None and not photo_allowed:
            raise web.HTTPForbidden(headers=PRIVATE_HEADERS)
        calls = portal_calls(events)
        if call_id is None:
            snapshot = _HistoryRows(
                monotonic(),
                tuple(call.as_dict(photo_allowed=photo_allowed) for call in calls),
            )
            if photo_allowed and getattr(events, "photos_incomplete", False):
                self._rows.get(coordinator, {}).pop(True, None)
                return web.json_response(
                    {"calls": list(snapshot.calls), "photos_incomplete": True},
                    headers=PRIVATE_HEADERS,
                )
            self._rows.setdefault(coordinator, {})[photo_allowed] = snapshot
            return snapshot.response()
        for call in calls:
            if call.ring.event_id == call_id and photo_index < len(call.photos):
                return web.Response(
                    body=call.photos[photo_index], content_type="image/jpeg", headers=PRIVATE_HEADERS
                )
        raise web.HTTPNotFound(headers=PRIVATE_HEADERS)
