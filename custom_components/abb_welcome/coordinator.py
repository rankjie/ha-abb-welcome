"""DataUpdateCoordinator that polls the ABB portal for intercom events."""

from __future__ import annotations

import base64
import json
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import urllib3
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DEFAULT_PORTAL_URL, DOMAIN
from .redaction import get_redacting_logger
from .text import repair_utf8_mojibake

_LOGGER = get_redacting_logger(__name__)
_LOG = "[abb] "

HISTORY_TYPES = ",".join(
    [
        "com.abb.ispf.event.welcome.ring",
        "com.abb.ispf.event.welcome.call-answered",
        "com.abb.ispf.event.welcome.call-terminated",
        "com.abb.ispf.event.welcome.call-missed",
        "com.abb.ispf.event.welcome.door-open",
        "com.abb.ispf.event.welcome.screenshot",
        "com.abb.ispf.event.welcome.light",
    ]
)

POLL_INTERVAL_SECONDS = 30
HISTORY_PAGE_SIZE = 20
HISTORY_EVENT_CAP = 200
SCREENSHOT_HISTORY_TYPE = "com.abb.ispf.event.welcome.screenshot"


@dataclass
class IntercomEvent:
    """A single intercom event from the portal."""

    event_id: str
    event_type: str  # ring, screenshot, door-open, call-terminated, etc.
    timestamp: str
    sender: str
    belongs_to: str = ""
    image_data: bytes | None = None
    payload_text: str = ""
    station_id: str = ""
    local_id: str = ""
    local_name: str = ""


@dataclass
class ABBWelcomeData:
    """Coordinator data: latest events + latest screenshot."""

    events: list[IntercomEvent] = field(default_factory=list)
    latest_screenshot: bytes | None = None
    latest_screenshot_event_id: str = ""
    latest_screenshots_by_station: dict[str, IntercomEvent] = field(
        default_factory=dict
    )
    last_event: IntercomEvent | None = None
    newest_event_id: str = ""


class ABBWelcomeCoordinator(DataUpdateCoordinator[ABBWelcomeData]):
    """Poll the ABB portal for intercom events."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{entry.entry_id}_events",
            update_interval=None,  # we drive polling manually
        )
        self._cert_pem: bytes = entry.data.get("certificate_pem", "").encode()
        self._key_pem: bytes = entry.data.get("private_key_pem", "").encode()
        self._newest_id: str = ""
        self._screenshot_history_checked = False
        self._portal_url = str(
            entry.data.get("portal_url", DEFAULT_PORTAL_URL) or DEFAULT_PORTAL_URL
        ).rstrip("/")
        self._data = ABBWelcomeData()
        self._has_certs = bool(self._cert_pem and self._key_pem)
        self._station_names = {
            str(door.get("station_id", "")).strip(): str(
                door.get("name") or door.get("station_id") or ""
            )
            for door in entry.data.get("doors", []) or []
            if str(door.get("station_id", "")).strip()
        }

    @staticmethod
    def _timestamp_seconds(value: str | int | float | None) -> float | None:
        if value in (None, ""):
            return None
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip()
        if not text:
            return None
        if text.isdigit():
            return float(text)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()

    def _station_event_for_screenshot(
        self,
        screenshot: IntercomEvent,
        events: list[IntercomEvent],
    ) -> IntercomEvent | None:
        """Find the station event that most likely produced a screenshot."""
        candidates = [
            evt
            for evt in events
            if evt.event_id != screenshot.event_id and evt.station_id
        ]
        if not candidates:
            return None

        if screenshot.belongs_to:
            for evt in candidates:
                if (
                    evt.event_id == screenshot.belongs_to
                    or evt.belongs_to == screenshot.belongs_to
                ):
                    return evt

        screenshot_ts = self._timestamp_seconds(screenshot.timestamp)
        if screenshot_ts is None:
            return candidates[0]

        def score(evt: IntercomEvent) -> tuple[float, int]:
            evt_ts = self._timestamp_seconds(evt.timestamp)
            delta = abs((evt_ts or screenshot_ts) - screenshot_ts)
            event_priority = 0 if evt.event_type == "ring" else 1
            return (delta, event_priority)

        best = min(candidates, key=score)
        best_ts = self._timestamp_seconds(best.timestamp)
        if best_ts is not None and abs(best_ts - screenshot_ts) > 120:
            return None
        return best

    @property
    def has_certs(self) -> bool:
        return self._has_certs

    def _make_session(self) -> tuple[requests.Session, list[str]]:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        ct = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        ct.write(self._cert_pem)
        ct.close()
        kt = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        kt.write(self._key_pem)
        kt.close()
        s = requests.Session()
        s.cert = (ct.name, kt.name)
        return s, [ct.name, kt.name]

    def _cleanup(self, paths: list[str]) -> None:
        for p in paths:
            try:
                Path(p).unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def _raw_event_has_screenshot(event: dict[str, Any]) -> bool:
        """Return whether an event contains a JPEG-like screenshot payload."""
        if (event.get("type") or "").rsplit(".", 1)[-1] != "screenshot":
            return False
        payload_b64 = event.get("payload", "")
        if not isinstance(payload_b64, str) or not payload_b64:
            return False
        try:
            pad = "=" * (-len(payload_b64) % 4)
            return base64.b64decode(payload_b64 + pad)[:2] == b"\xff\xd8"
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _response_events(response: requests.Response) -> list[dict[str, Any]]:
        """Return dictionary events from a successful portal response."""
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise TypeError("Unexpected portal event response")
        events = data.get("events") or []
        if not isinstance(events, list):
            raise TypeError("Unexpected portal events value")
        return [event for event in events if isinstance(event, dict)]

    def _fetch_latest_historical_screenshot(
        self,
        session: requests.Session,
    ) -> list[dict[str, Any]]:
        """Fetch the newest screenshot without scanning mixed history pages."""
        response = session.get(
            f"{self._portal_url}/event",
            params={
                "type": SCREENSHOT_HISTORY_TYPE,
                "order": "desc",
                "pagination_limit": 1,
                "pagination_page": 1,
            },
            timeout=15,
        )
        events = self._response_events(response)
        return [event for event in events if self._raw_event_has_screenshot(event)][:1]

    @staticmethod
    def _deduplicate_events(events: list[IntercomEvent]) -> list[IntercomEvent]:
        """Keep newest-first events while removing duplicate portal IDs."""
        unique: list[IntercomEvent] = []
        seen_ids: set[str] = set()
        for event in events:
            if event.event_id:
                if event.event_id in seen_ids:
                    continue
                seen_ids.add(event.event_id)
            unique.append(event)
        return unique

    def poll_events(self) -> ABBWelcomeData:
        """Synchronous poll — called via async_add_executor_job."""
        if not self._has_certs:
            return self._data

        session, tmps = self._make_session()
        try:
            params: dict[str, Any] = {
                "type": HISTORY_TYPES,
                "order": "desc",
                "pagination_limit": HISTORY_PAGE_SIZE,
                "pagination_page": 1,
            }
            if self._newest_id:
                params["newer_than_id"] = self._newest_id

            response = session.get(
                f"{self._portal_url}/event", params=params, timeout=15
            )
            normal_events = self._response_events(response)
            raw_events = list(normal_events)

            if not self._screenshot_history_checked:
                if any(
                    self._raw_event_has_screenshot(event) for event in normal_events
                ):
                    self._screenshot_history_checked = True
                else:
                    try:
                        historical = self._fetch_latest_historical_screenshot(session)
                    except (requests.RequestException, ValueError, TypeError):
                        # Do not include response details here: portal errors can
                        # contain private identifiers or payload fragments.
                        _LOGGER.warning(
                            _LOG + "Initial screenshot history lookup failed"
                        )
                    else:
                        self._screenshot_history_checked = True
                        raw_events.extend(historical)

            if not raw_events:
                return self._data

            new_events: list[IntercomEvent] = []
            newest_screenshot: bytes | None = None
            newest_screenshot_id = ""

            for evt in raw_events:
                etype = (evt.get("type") or "").rsplit(".", 1)[-1]
                event_id = evt.get("id", "")
                payload_b64 = evt.get("payload", "")

                ie = IntercomEvent(
                    event_id=event_id,
                    event_type=etype,
                    timestamp=evt.get("timestamp", ""),
                    sender=evt.get("sender", ""),
                    belongs_to=evt.get("belongsTo", ""),
                )

                if payload_b64:
                    try:
                        pad = "=" * (-len(payload_b64) % 4)
                        raw = base64.b64decode(payload_b64 + pad)
                        if raw[:2] == b"\xff\xd8":
                            ie.image_data = raw
                            if not newest_screenshot:
                                newest_screenshot = raw
                                newest_screenshot_id = event_id
                        else:
                            ie.payload_text = raw.decode("utf-8", "replace")[:500]
                            payload = json.loads(ie.payload_text)
                            if isinstance(payload, dict):
                                ie.local_id = str(payload.get("local_id", "")).strip()
                                ie.local_name = repair_utf8_mojibake(
                                    str(payload.get("local_name", "")).strip()
                                )
                                if ie.local_id:
                                    ie.station_id = ie.local_id.split("@", 1)[
                                        0
                                    ].removeprefix("sip:")
                    except Exception:
                        pass

                if ie.station_id and not ie.local_name:
                    ie.local_name = self._station_names.get(ie.station_id, "")

                new_events.append(ie)

            station_match_events = new_events + self._data.events
            for ie in new_events:
                if not ie.image_data:
                    continue
                station_event = self._station_event_for_screenshot(
                    ie, station_match_events
                )
                if station_event is None:
                    continue
                ie.station_id = station_event.station_id
                ie.local_id = station_event.local_id
                ie.local_name = station_event.local_name or self._station_names.get(
                    ie.station_id, ""
                )

            # The mixed-history page remains the sole incremental polling
            # anchor.  A historical screenshot must never move this backward.
            if normal_events:
                first_id = normal_events[0].get("id", "")
                if first_id:
                    self._newest_id = first_id

            # Prepend new events to the existing newest-first list, removing
            # portal page overlap before applying the retained history cap.
            merged_events = self._deduplicate_events(new_events + self._data.events)
            merged_events.sort(
                key=lambda event: (
                    self._timestamp_seconds(event.timestamp) is not None,
                    self._timestamp_seconds(event.timestamp) or 0,
                ),
                reverse=True,
            )
            self._data.events = merged_events[:HISTORY_EVENT_CAP]

            if newest_screenshot:
                self._data.latest_screenshot = newest_screenshot
                self._data.latest_screenshot_event_id = newest_screenshot_id

            for ie in new_events:
                if ie.image_data and ie.station_id:
                    self._data.latest_screenshots_by_station[ie.station_id] = ie

            # Latest non-screenshot event for the sensor
            for ie in new_events:
                if ie.event_type != "screenshot":
                    self._data.last_event = ie
                    break

            _LOGGER.info(
                _LOG + "Polled %d new events (%d screenshots)",
                len(new_events),
                sum(1 for e in new_events if e.image_data),
            )
            return self._data

        except requests.RequestException as err:
            _LOGGER.warning(_LOG + "Event poll failed: %s", err)
            return self._data
        finally:
            session.close()
            self._cleanup(tmps)

    async def _async_update_data(self) -> ABBWelcomeData:
        return await self.hass.async_add_executor_job(self.poll_events)
