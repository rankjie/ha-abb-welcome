"""DataUpdateCoordinator that polls the ABB portal for intercom events."""

from __future__ import annotations

import base64
import logging
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
import urllib3
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)
_LOG = "[abb] "

PORTAL_URL = "https://api.eu.mybuildings.abb.com"

HISTORY_TYPES = ",".join([
    "com.abb.ispf.event.welcome.ring",
    "com.abb.ispf.event.welcome.call-answered",
    "com.abb.ispf.event.welcome.call-terminated",
    "com.abb.ispf.event.welcome.call-missed",
    "com.abb.ispf.event.welcome.door-open",
    "com.abb.ispf.event.welcome.screenshot",
    "com.abb.ispf.event.welcome.light",
])

POLL_INTERVAL_SECONDS = 30


@dataclass
class IntercomEvent:
    """A single intercom event from the portal."""

    event_id: str
    event_type: str  # ring, screenshot, door-open, call-terminated, etc.
    timestamp: str
    sender: str
    image_data: bytes | None = None
    payload_text: str = ""
    station_id: str = ""


@dataclass
class ABBWelcomeData:
    """Coordinator data: latest events + latest screenshot."""

    events: list[IntercomEvent] = field(default_factory=list)
    latest_screenshot: bytes | None = None
    latest_screenshot_event_id: str = ""
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
        self._data = ABBWelcomeData()
        self._has_certs = bool(self._cert_pem and self._key_pem)

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

    def poll_events(self) -> ABBWelcomeData:
        """Synchronous poll — called via async_add_executor_job."""
        if not self._has_certs:
            return self._data

        session, tmps = self._make_session()
        try:
            params: dict[str, Any] = {
                "type": HISTORY_TYPES,
                "order": "desc",
                "pagination_limit": 20,
                "pagination_page": 1,
            }
            if self._newest_id:
                params["newer_than_id"] = self._newest_id

            resp = session.get(
                f"{PORTAL_URL}/event", params=params, timeout=15
            )
            resp.raise_for_status()
            data = resp.json()
            raw_events = data.get("events") or []

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
                            ie.payload_text = raw.decode("utf-8", "replace")[:200]
                    except Exception:
                        pass

                new_events.append(ie)

            if raw_events:
                first_id = raw_events[0].get("id", "")
                if first_id:
                    self._newest_id = first_id

            # Prepend new events to existing list (newest first), cap at 200
            self._data.events = new_events + self._data.events
            self._data.events = self._data.events[:200]

            if newest_screenshot:
                self._data.latest_screenshot = newest_screenshot
                self._data.latest_screenshot_event_id = newest_screenshot_id

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
