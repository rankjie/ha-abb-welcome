"""Camera entities for ABB Welcome outdoor stations.

One Camera entity per door (outdoor station).  Calling
:py:meth:`stream_source` triggers an outbound SIP INVITE to that station
through the shared :class:`IntercomDialer`, allocates a UDP RTP receive
socket, hands the resulting RTP feed to ``ffmpeg`` through a loopback
port, and returns the ``tcp://127.0.0.1:<port>`` MPEG-TS URL HA's
``stream`` component will consume.

Streams self-destruct after :data:`STREAM_MAX_SECONDS` to match the
gateway's own no-answer timeout (~33 s) and avoid hogging the
exclusive outdoor-station media slot.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.components.ffmpeg import get_ffmpeg_manager
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .intercom_dialer import Door, IntercomDialer
from .media_pipeline import MediaPipeline

_LOGGER = logging.getLogger(__name__)

STREAM_MAX_SECONDS = 30


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up one camera per door if SIP creds + doors are present."""
    data = hass.data[DOMAIN][entry.entry_id]
    sip_user = entry.data.get("sip_username")
    sip_pass = entry.data.get("sip_password")
    sip_domain = entry.data.get("sip_domain")
    gw_ip = entry.data.get("gateway_ip")
    raw_doors = entry.data.get("doors", []) or []
    if not (sip_user and sip_pass and sip_domain and gw_ip and raw_doors):
        return

    dialer = IntercomDialer(
        host=gw_ip, username=sip_user, password=sip_pass, domain=sip_domain
    )
    data["intercom_dialer"] = dialer

    async def _close_dialer(*_args) -> None:
        await dialer.close()

    entry.async_on_unload(_close_dialer)

    gateway_uuid = entry.data.get("gateway_uuid", "unknown")
    cameras: list[Camera] = []
    for raw in raw_doors:
        if not isinstance(raw, dict):
            continue
        addr = raw.get("address", "")
        if not addr:
            continue
        cameras.append(
            ABBWelcomeCamera(
                hass=hass,
                dialer=dialer,
                door=Door(
                    name=raw.get("name") or addr,
                    address=addr,
                    station_id=str(raw.get("station_id", "")),
                ),
                gateway_uuid=gateway_uuid,
            )
        )
    if cameras:
        async_add_entities(cameras)


class ABBWelcomeCamera(Camera):
    """Camera entity that dials the outdoor station on demand."""

    _attr_has_entity_name = True
    _attr_supported_features = CameraEntityFeature.STREAM
    _attr_icon = "mdi:doorbell-video"
    # The intercom is exclusive — running multiple streams against one
    # gateway concurrently is asking for trouble.  Cameras share a class-
    # level lock to enforce serial usage.
    _shared_lock: asyncio.Lock | None = None

    def __init__(
        self,
        hass: HomeAssistant,
        dialer: IntercomDialer,
        door: Door,
        gateway_uuid: str,
    ) -> None:
        super().__init__()
        self.hass = hass
        self._dialer = dialer
        self._door = door
        self._attr_name = door.name
        self._attr_unique_id = f"{gateway_uuid}_camera_{door.station_id or door.address}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, gateway_uuid)},
            name="ABB Welcome Gateway",
            manufacturer="ABB / Busch-Jaeger",
            model="IP Gateway (MRANGE)",
        )
        self._pipeline: MediaPipeline | None = None
        self._stream_url: str | None = None
        self._stream_started_at: float = 0.0
        self._auto_hangup_task: asyncio.Task | None = None

    @classmethod
    def _get_lock(cls) -> asyncio.Lock:
        if cls._shared_lock is None:
            cls._shared_lock = asyncio.Lock()
        return cls._shared_lock

    async def stream_source(self) -> str | None:
        """Return a URL HA's stream component can read.

        Lazily dials the outdoor station + spawns ffmpeg.  Subsequent
        calls within the active window return the same URL.
        """
        lock = self._get_lock()
        async with lock:
            now = time.monotonic()
            if (
                self._pipeline is not None
                and self._stream_url is not None
                and now - self._stream_started_at < STREAM_MAX_SECONDS - 2
            ):
                return self._stream_url
            await self._teardown_locked()
            try:
                self._stream_url = await self._setup_locked()
                self._stream_started_at = now
            except Exception as err:  # noqa: BLE001
                _LOGGER.exception("Failed to start stream for %s: %s", self._door.name, err)
                await self._teardown_locked()
                return None
            self._auto_hangup_task = self.hass.async_create_background_task(
                self._auto_hangup(), name=f"abb_camera_auto_hangup_{self._door.station_id}"
            )
            return self._stream_url

    async def _setup_locked(self) -> str:
        ffmpeg_binary = "ffmpeg"
        try:
            ffmpeg_binary = get_ffmpeg_manager(self.hass).binary or "ffmpeg"
        except Exception:  # noqa: BLE001
            pass

        pipeline = MediaPipeline(
            gateway_host=self._dialer.host, ffmpeg_binary=ffmpeg_binary
        )
        audio_sock, video_sock = await pipeline.setup()
        audio_port = audio_sock.getsockname()[1]
        video_port = video_sock.getsockname()[1]

        call = await self._dialer.dial(
            self._door, audio_port=audio_port, video_port=video_port
        )

        gw_audio: tuple[str, int] | None = None
        gw_video: tuple[str, int] | None = None
        for m in call.answer.medias:
            if m.media == "audio" and m.connection_ip and m.port:
                gw_audio = (m.connection_ip, m.port)
            elif m.media == "video" and m.connection_ip and m.port:
                gw_video = (m.connection_ip, m.port)

        url = await pipeline.start(gw_audio, gw_video)
        self._pipeline = pipeline
        _LOGGER.info("[abb] camera %s stream URL: %s", self._door.name, url)
        return url

    async def _auto_hangup(self) -> None:
        try:
            await asyncio.sleep(STREAM_MAX_SECONDS)
        except asyncio.CancelledError:
            return
        _LOGGER.info("[abb] camera %s auto-hangup safety net", self._door.name)
        async with self._get_lock():
            await self._teardown_locked()

    async def _teardown_locked(self) -> None:
        if self._auto_hangup_task is not None:
            self._auto_hangup_task.cancel()
            self._auto_hangup_task = None
        if self._pipeline is not None:
            try:
                await self._pipeline.stop()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("pipeline stop failed: %s", err)
            self._pipeline = None
        if self._dialer.in_call:
            try:
                await self._dialer.hangup()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("dialer hangup failed: %s", err)
        self._stream_url = None
        self._stream_started_at = 0.0

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        # Snapshot would require a transient dial just to grab one keyframe.
        # Skip for now — HA's stream component falls back to an HLS-derived
        # snapshot once a stream has been live.
        return None
