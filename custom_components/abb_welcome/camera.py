"""Camera entities for ABB Welcome outdoor stations.

Each camera owns:

* a tiny RTSP server (per-entity, stable port for the entity's
  lifetime) — go2rtc connects to it as a client when a downstream
  WebRTC consumer wants the stream
* a :class:`StreamSession` that SIP-dials the gateway and forwards
  RTP packets via the RTSP server's TCP-interleaved framing

Streaming is gated and lazy:

* the per-gateway *armed* flag (see :mod:`streaming_state`) decides
  whether streaming is permitted right now — accidentally opening the
  intercom locks out the whole building, so it stays off by default
* DESCRIBE only returns the advertised SDP; it never dials the gateway
* on PLAY we start forwarding RTP through the same TCP socket
* on the *last* TEARDOWN (or connection close) we BYE the gateway
  after a brief grace period so the building's intercom is freed
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Iterable
from http import HTTPStatus
from typing import Any, Protocol
from urllib.parse import urljoin, urlparse

from aiohttp import ClientError, ClientSession, ClientTimeout
from go2rtc_client.ws import (
    Go2RtcWsClient,
)
from go2rtc_client.ws import (
    WebRTCAnswer as Go2RTCAnswer,
)
from go2rtc_client.ws import (
    WebRTCCandidate as Go2RTCCandidate,
)
from go2rtc_client.ws import (
    WebRTCOffer as Go2RTCOffer,
)
from go2rtc_client.ws import (
    WsError as Go2RTCWsError,
)
from homeassistant.components.camera import (
    Camera,
    CameraCapabilities,
    CameraEntityFeature,
    StreamType,
    WebRTCAnswer,
    WebRTCCandidate,
    WebRTCError,
    WebRTCSendMessage,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from webrtc_models import RTCIceCandidateInit

from .const import (
    DOMAIN,
    GATEWAY_PROFILE_APP_MANAGED,
    GO2RTC_RTSP_HOST,
    GO2RTC_RTSP_PORT,
    gateway_profile,
    talkback_output_gain_db,
)
from .device import gateway_device_info
from .intercom_dialer import Door, IntercomDialer
from .media_pipeline import StreamSession
from .redaction import get_redacting_logger
from .rtsp_server import (
    AUDIO_RTP_CHANNEL,
    VIDEO_RTP_CHANNEL,
    RtspServer,
    RtspSession,
)
from .streaming_state import (
    get_state,
    is_armed,
    is_pickup_allowed,
    is_stream_allowed,
    signal_armed_changed,
)

_LOGGER = get_redacting_logger(__name__)

_GO2RTC_DOMAIN = "go2rtc"
_REQUEST_TIMEOUT = ClientTimeout(total=10)
_TEARDOWN_GRACE_SECONDS = 2.0


def _safe_key(value: str) -> str:
    key = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return key or "station"


def _raw_int(raw: dict, *keys: str) -> int | None:
    for key in keys:
        value = raw.get(key)
        if value is None or value == "":
            continue
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            continue
        return parsed if parsed > 0 else None
    return None


def _camera_count_from_raw(raw: dict) -> int:
    explicit = _raw_int(raw, "camera_count", "sub_camera_count", "cameras")
    if explicit is not None:
        return explicit
    return 1


def _door_key(door: Door) -> str:
    return _safe_key(door.station_id or door.address)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    data.setdefault("camera_entities_by_entity_id", {})
    data.setdefault("camera_entities_by_station", {})
    sip_user = entry.data.get("sip_username")
    sip_pass = entry.data.get("sip_password")
    sip_domain = entry.data.get("sip_domain")
    gw_ip = entry.data.get("gateway_ip")
    raw_doors = entry.data.get("doors", []) or []
    if not (sip_user and sip_pass and sip_domain and gw_ip and raw_doors):
        return

    gateway_uuid = entry.data.get("gateway_uuid", "unknown")
    exact_door_targets = (
        gateway_profile(entry.data) == GATEWAY_PROFILE_APP_MANAGED
    )
    talkback_gain_db = talkback_output_gain_db(entry.data, entry.options)
    device_info = gateway_device_info(entry.data)
    door_meta: dict[str, tuple[Door, str, bool | str | int | None]] = {}
    camera_entities: dict[tuple[str, int], ABBWelcomeCamera] = {}
    created_indexes: dict[str, set[int]] = {}
    detected_counts: dict[str, int] = {}
    stream_coordinators: dict[tuple[str, int], StationStreamCoordinator] = (
        data.setdefault("stream_coordinators", {})
    )

    def _build_camera(
        door: Door,
        *,
        camera_index: int,
        camera_count: int,
        station_type: str,
        can_unlock: bool | str | int | None,
    ) -> ABBWelcomeCamera:
        exposed_index = camera_index if camera_index > 1 else None
        key = _door_key(door)
        coordinator_key = (key, exposed_index or 0)
        coordinator = stream_coordinators.get(coordinator_key)
        if coordinator is None:
            coordinator = StationStreamCoordinator(
                hass=hass,
                entry_id=entry.entry_id,
                dialer=dialer,
                incoming_listener=data.get("sip_listener"),
                door=door,
                camera_index=exposed_index,
                talkback_output_gain_db=talkback_gain_db,
                peer_coordinators=lambda: stream_coordinators.values(),
            )
            stream_coordinators[coordinator_key] = coordinator
        camera = ABBWelcomeCamera(
            hass=hass,
            entry_id=entry.entry_id,
            coordinator=coordinator,
            door=door,
            gateway_uuid=gateway_uuid,
            camera_index=exposed_index,
            camera_count=camera_count,
            station_type=station_type,
            can_unlock=can_unlock,
            device_info=device_info,
        )
        camera_entities[(key, camera_index)] = camera
        created_indexes.setdefault(key, set()).add(camera_index)
        return camera

    def _on_camera_count_for_key(
        key: str,
        count: int,
        body: str,
        *,
        source: str,
        fallback_name: str = "unknown",
    ) -> None:
        if count < 1:
            return
        meta = door_meta.get(key)
        if meta is None:
            _LOGGER.info(
                "[abb] camera setup: detected camera count=%d for unknown "
                "door=%s source=%s body=%r",
                count, fallback_name, source, body[:200],
            )
            return

        stored_door, station_type, can_unlock = meta
        previous_count = detected_counts.get(key, 1)
        detected_counts[key] = max(previous_count, count)
        for index in created_indexes.get(key, set()):
            entity = camera_entities.get((key, index))
            if entity is not None:
                entity.set_camera_count(detected_counts[key])

        new_cameras: list[Camera] = []
        for camera_index in range(2, count + 1):
            if camera_index in created_indexes.get(key, set()):
                continue
            new_cameras.append(
                _build_camera(
                    stored_door,
                    camera_index=camera_index,
                    camera_count=count,
                    station_type=station_type,
                    can_unlock=can_unlock,
                )
            )

        if not new_cameras:
            _LOGGER.info(
                "[abb] camera setup: camera count=%d for door=%s produced no "
                "new entities (already have indexes=%s)",
                count, stored_door.name, sorted(created_indexes.get(key, set())),
            )
            return

        _LOGGER.info(
            "[abb] camera setup: adding %d detected sub-camera entity(s) for "
            "door=%s count=%d source=%s source_body=%r",
            len(new_cameras), stored_door.name, count, source, body[:200],
        )
        async_add_entities(new_cameras)

    def _on_camera_count_detected(door: Door, count: int, body: str) -> None:
        _on_camera_count_for_key(
            _door_key(door),
            count,
            body,
            source="intercom_dialer",
            fallback_name=door.name,
        )

    def _on_listener_camera_count_for_door(
        door: Door, count: int, body: str, source: str = "sip_listener"
    ) -> None:
        _on_camera_count_for_key(
            _door_key(door), count, body, source=source, fallback_name=door.name
        )

    def _on_listener_camera_count(
        station_id: str, count: int, body: str, source: str = "sip_listener"
    ) -> None:
        _on_camera_count_for_key(
            _safe_key(station_id), count, body, source=source, fallback_name=station_id
        )

    data["camera_count_door_handler"] = _on_listener_camera_count_for_door
    data["camera_count_handler"] = _on_listener_camera_count

    dialer = IntercomDialer(
        host=gw_ip,
        username=sip_user,
        password=sip_pass,
        domain=sip_domain,
        on_camera_count=_on_camera_count_detected,
        custom_media_crypto=exact_door_targets,
    )
    data["intercom_dialer"] = dialer

    async def _close_dialer(*_args) -> None:
        await dialer.close()

    async def _close_stream_coordinators(*_args) -> None:
        for coordinator in list(stream_coordinators.values()):
            await coordinator.force_close()

    entry.async_on_unload(_close_stream_coordinators)
    entry.async_on_unload(_close_dialer)

    cameras: list[Camera] = []
    for raw in raw_doors:
        if not isinstance(raw, dict):
            continue
        addr = raw.get("address", "")
        if not addr:
            continue
        door = Door(
            name=raw.get("name") or addr,
            address=addr,
            station_id=str(raw.get("station_id", "")),
            local_id=str(raw.get("local_id") or ""),
            exact_target=exact_door_targets,
        )
        camera_count = _camera_count_from_raw(raw)
        station_type = str(raw.get("type", "")).strip()
        can_unlock = raw.get("can_unlock")
        key = _door_key(door)
        door_meta[key] = (door, station_type, can_unlock)
        detected_counts[key] = camera_count
        _LOGGER.info(
            "[abb] camera setup: station metadata redacted "
            "type=%s can_unlock=%s initial_camera_count=%d",
            station_type or "unknown", can_unlock, camera_count,
        )
        for camera_index in range(1, camera_count + 1):
            cameras.append(
                _build_camera(
                    door=door,
                    camera_index=camera_index,
                    camera_count=camera_count,
                    station_type=station_type,
                    can_unlock=can_unlock,
                )
            )
            _LOGGER.info(
                "[abb] camera setup: added entity door=%s camera_index=%s "
                "switch_body=%s",
                door.name,
                camera_index if camera_index > 1 else "default",
                f"d:{camera_index}" if camera_index > 1 else "none",
            )
    if cameras:
        async_add_entities(cameras)


def _go2rtc_url(hass: HomeAssistant) -> str | None:
    bucket = hass.data.get(_GO2RTC_DOMAIN)
    url = getattr(bucket, "url", bucket)
    if isinstance(url, str) and url:
        return url.rstrip("/") + "/"
    return None


def _go2rtc_session(hass: HomeAssistant) -> ClientSession:
    bucket = hass.data.get(_GO2RTC_DOMAIN)
    session = getattr(bucket, "session", None)
    if session is not None:
        return session
    return async_get_clientsession(hass)


class PacketSink(Protocol):
    """A non-RTSP consumer of raw RTP packets (e.g. the ring-clip recorder).

    Registered sinks keep the coordinator's packet handlers installed and
    the underlying media session open even when no RTSP client is attached,
    coexisting with RTSP consumers rather than replacing them.
    """

    def on_video(self, packet: bytes) -> None: ...

    def on_audio(self, packet: bytes) -> None: ...


class StationStreamCoordinator:
    """Own one gateway media session and fan it out to RTSP consumers."""

    def __init__(
        self,
        *,
        hass: HomeAssistant,
        entry_id: str,
        dialer: IntercomDialer,
        incoming_listener: object | None,
        door: Door,
        camera_index: int | None,
        talkback_output_gain_db: float = 0.0,
        peer_coordinators: Callable[
            [], Iterable[StationStreamCoordinator]
        ]
        | None = None,
    ) -> None:
        self.hass = hass
        self.entry_id = entry_id
        self.door = door
        self.camera_index = camera_index
        self._stream_lock = asyncio.Lock()
        self._rtsp_play_sessions: list[RtspSession] = []
        self._close_task: asyncio.Task | None = None
        self._talkback_owner = ""
        self._temporary_talkback_active = False
        self._temporary_talkback_task: asyncio.Task | None = None
        self._peer_coordinators = peer_coordinators
        self._state_callbacks: list[Callable[[], None]] = []
        self._packet_sinks: list[PacketSink] = []
        self._handlers_installed = False
        self._call_ended_callbacks: list[Callable[[str, str], None]] = []
        self.session = StreamSession(
            dialer=dialer,
            door=door,
            gateway_host=dialer.host,
            camera_index=camera_index,
            incoming_listener=incoming_listener,
            pickup_allowed=lambda: is_pickup_allowed(self.hass, self.entry_id),
            on_call_ended=self._on_gateway_call_ended,
            talkback_output_gain_db=talkback_output_gain_db,
        )

    @property
    def active(self) -> bool:
        return self.session.active

    @property
    def client_count(self) -> int:
        return len(self._rtsp_play_sessions)

    @property
    def video_codec(self) -> str:
        return self.session.video_codec

    @property
    def video_fmtp(self) -> str | None:
        return self.session.video_fmtp

    @property
    def talkback_ready(self) -> bool:
        return self.session.talkback_ready

    @property
    def talkback_owner(self) -> str:
        return self._talkback_owner

    @property
    def temporary_talkback_active(self) -> bool:
        return self._temporary_talkback_active

    def talkback_stats(self) -> dict[str, Any]:
        stats = self.session.talkback_stats()
        stats["owner"] = self._talkback_owner
        return stats

    def add_state_callback(self, callback: Callable[[], None]) -> None:
        if callback not in self._state_callbacks:
            self._state_callbacks.append(callback)

    def remove_state_callback(self, callback: Callable[[], None]) -> None:
        self._state_callbacks = [
            existing for existing in self._state_callbacks if existing is not callback
        ]

    def _notify_state(self) -> None:
        for callback in list(self._state_callbacks):
            try:
                callback()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("[abb] stream coordinator callback failed: %s", err)

    def add_call_ended_callback(self, callback: Callable[[str, str], None]) -> None:
        """Register a callback fired whenever the underlying call ends.

        Unlike ``_on_gateway_call_ended``'s RTSP-session teardown, this
        fires even when only packet sinks (no RTSP clients) are attached —
        the ring-clip recorder uses it to end its current segment.
        """
        if callback not in self._call_ended_callbacks:
            self._call_ended_callbacks.append(callback)

    def remove_call_ended_callback(self, callback: Callable[[str, str], None]) -> None:
        self._call_ended_callbacks = [
            existing
            for existing in self._call_ended_callbacks
            if existing is not callback
        ]

    def _notify_call_ended_listeners(self, call_id: str, reason: str) -> None:
        for listener in list(self._call_ended_callbacks):
            try:
                listener(call_id, reason)
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug(
                    "[abb] stream coordinator call-ended callback failed: %s", err
                )

    def add_packet_sink(self, sink: PacketSink) -> None:
        """Register a non-RTSP RTP consumer (e.g. the ring-clip recorder)."""
        if sink not in self._packet_sinks:
            self._packet_sinks.append(sink)
        self._ensure_handlers_installed()
        self._notify_state()

    def remove_packet_sink(self, sink: PacketSink) -> None:
        self._packet_sinks = [
            existing for existing in self._packet_sinks if existing is not sink
        ]
        if not self._rtsp_play_sessions and not self._packet_sinks:
            self._clear_handlers()
            self._schedule_close()
        self._notify_state()

    def _ensure_handlers_installed(self) -> None:
        """Idempotently wire this coordinator's fan-out as the packet handlers.

        The coordinator is the sole owner of ``StreamSession``'s single
        video/audio handler pair; RTSP sessions and packet sinks are both
        fanned out from ``_forward_video``/``_forward_audio`` below.
        """
        if self._handlers_installed:
            return
        self.session.set_packet_handlers(
            on_video=self._forward_video,
            on_audio=self._forward_audio,
        )
        self._handlers_installed = True

    def _clear_handlers(self) -> None:
        self.session.set_packet_handlers(on_video=None, on_audio=None)
        self._handlers_installed = False

    async def async_open_for_ring(self) -> bool:
        """Open (or reuse) the media session for native ring-clip capture.

        Installs the packet handlers so registered sinks receive RTP even
        with no RTSP viewer attached, then opens the underlying media
        session if it is not already active. Returns whether media ended
        up open; never raises (open failures are logged and reported via
        the return value only).
        """
        self._cancel_close_task()
        self._ensure_handlers_installed()
        async with self._stream_lock:
            if not self.session.active:
                try:
                    await self.session.open()
                except Exception as err:  # noqa: BLE001
                    _LOGGER.warning(
                        "[abb] stream coordinator: failed to open media for "
                        "ring clip capture station=%s: %s",
                        self.door.station_id or self.door.address,
                        err,
                    )
        self._notify_state()
        return self.session.active

    def _cancel_close_task(self) -> None:
        if self._close_task is not None and not self._close_task.done():
            self._close_task.cancel()
        self._close_task = None

    def _coordinator_group(self) -> list[StationStreamCoordinator]:
        peers = list(self._peer_coordinators()) if self._peer_coordinators else []
        if not any(peer is self for peer in peers):
            peers.append(self)
        return peers

    def _temporary_talkback_unavailable_reason(
        self,
        session_id: str,
        *,
        own_reservation: bool = False,
    ) -> str | None:
        for coordinator in self._coordinator_group():
            is_own_reservation = own_reservation and coordinator is self
            if (
                coordinator._temporary_talkback_active
                and not is_own_reservation
            ):
                return "another unattended announcement is already in progress"
            if coordinator._rtsp_play_sessions:
                return "an RTSP camera stream is already in use"
            if coordinator.session.active:
                return "an intercom stream or call is already active"
            if coordinator._talkback_owner and not is_own_reservation:
                if session_id and coordinator._talkback_owner != session_id:
                    return "talkback is owned by another session"
                return "talkback already has an owner"
            close_task = coordinator._close_task
            if close_task is not None and not close_task.done():
                return "a camera stream is still closing"
            if coordinator._stream_lock.locked() and not is_own_reservation:
                return "the camera stream is busy"
        return None

    def _temporary_talkback_in_group(self) -> bool:
        return any(
            coordinator._temporary_talkback_active
            for coordinator in self._coordinator_group()
        )

    def _reject_rtsp_during_temporary_talkback(self, sess: RtspSession) -> bool:
        self._discard_rtsp_play_session(sess)
        if not self._rtsp_play_sessions and not self._packet_sinks:
            self._clear_handlers()
        sess.close()
        self._notify_state()
        return False

    async def attach_rtsp_session(self, sess: RtspSession) -> bool:
        if self._temporary_talkback_in_group():
            return self._reject_rtsp_during_temporary_talkback(sess)
        self._cancel_close_task()
        _LOGGER.info(
            "[abb] stream coordinator: attach RTSP session station=%s "
            "session=%s active_before=%s clients_before=%d",
            self.door.station_id or self.door.address,
            sess.session_id,
            self.session.active,
            len(self._rtsp_play_sessions),
        )
        self._add_rtsp_play_session(sess)
        if self._temporary_talkback_in_group():
            return self._reject_rtsp_during_temporary_talkback(sess)
        self._ensure_handlers_installed()
        self._notify_state()
        try:
            async with self._stream_lock:
                if self._temporary_talkback_in_group():
                    return self._reject_rtsp_during_temporary_talkback(sess)
                if not self.session.active:
                    await self.session.open()
        except Exception:
            self._discard_rtsp_play_session(sess)
            if not self._rtsp_play_sessions and not self._packet_sinks:
                self._clear_handlers()
            sess.close()
            self._notify_state()
            raise

        self._notify_state()
        _LOGGER.info(
            "[abb] stream coordinator: attached RTSP session station=%s "
            "session=%s active=%s clients=%d",
            self.door.station_id or self.door.address,
            sess.session_id,
            self.session.active,
            len(self._rtsp_play_sessions),
        )
        return True

    def detach_rtsp_session(self, sess: RtspSession) -> None:
        self._discard_rtsp_play_session(sess)
        _LOGGER.info(
            "[abb] stream coordinator: detached RTSP session station=%s "
            "session=%s active=%s clients=%d",
            self.door.station_id or self.door.address,
            sess.session_id,
            self.session.active,
            len(self._rtsp_play_sessions),
        )
        if not self._rtsp_play_sessions and not self._packet_sinks:
            self._clear_handlers()
            self._schedule_close()
        self._notify_state()

    def _on_gateway_call_ended(self, call_id: str, reason: str) -> None:
        # Fires even with zero RTSP viewers so a sink-only (ring-clip)
        # capture also learns the call ended.
        self._notify_call_ended_listeners(call_id, reason)
        if not self._rtsp_play_sessions:
            return
        sessions = list(self._rtsp_play_sessions)
        self._rtsp_play_sessions = []
        if not self._packet_sinks:
            self._clear_handlers()
        _LOGGER.info(
            "[abb] stream coordinator: closing %d RTSP client(s) after "
            "gateway call ended station=%s call_id=%s reason=%s",
            len(sessions),
            self.door.station_id or self.door.address,
            call_id,
            reason,
        )
        for sess in sessions:
            sess.close()
        self._notify_state()

    async def force_close(self) -> None:
        self._cancel_close_task()
        self._rtsp_play_sessions = []
        # Unconditional: force_close tears everything down for entry unload /
        # entity removal, so any sink is force-notified and dropped rather
        # than allowed to keep the session open.
        self._notify_call_ended_listeners("", "force_close")
        self._packet_sinks = []
        self._clear_handlers()
        temporary_task = self._temporary_talkback_task
        if (
            temporary_task is not None
            and temporary_task is not asyncio.current_task()
            and not temporary_task.done()
        ):
            temporary_task.cancel()
            try:
                await temporary_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        async with self._stream_lock:
            if self.session.active:
                await self.session.close()
        self._talkback_owner = ""
        self._temporary_talkback_active = False
        self._temporary_talkback_task = None
        self._notify_state()

    def _schedule_close(self) -> None:
        self._cancel_close_task()
        self._close_task = self.hass.async_create_background_task(
            self._delayed_close(),
            name=f"abb_stream_close_{self.door.station_id or self.door.address}",
        )

    async def _delayed_close(self) -> None:
        try:
            await asyncio.sleep(_TEARDOWN_GRACE_SECONDS)
        except asyncio.CancelledError:
            return
        if self._rtsp_play_sessions or self._packet_sinks:
            return
        async with self._stream_lock:
            if self._rtsp_play_sessions or self._packet_sinks:
                return
            if self.session.active:
                await self.session.close()
        self._talkback_owner = ""
        self._notify_state()

    def _add_rtsp_play_session(self, sess: RtspSession) -> None:
        if any(client is sess for client in self._rtsp_play_sessions):
            return
        self._rtsp_play_sessions.append(sess)

    def _discard_rtsp_play_session(self, sess: RtspSession) -> None:
        self._rtsp_play_sessions = [
            client for client in self._rtsp_play_sessions if client is not sess
        ]

    def _forward_video(self, packet: bytes) -> None:
        for client in list(self._rtsp_play_sessions):
            if not client.push_rtp(VIDEO_RTP_CHANNEL, packet):
                self._discard_rtsp_play_session(client)
        for sink in list(self._packet_sinks):
            try:
                sink.on_video(packet)
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("[abb] packet sink on_video failed: %s", err)
        if not self._rtsp_play_sessions and not self._packet_sinks:
            self._clear_handlers()
            self._schedule_close()
            self._notify_state()

    def _forward_audio(self, packet: bytes) -> None:
        for client in list(self._rtsp_play_sessions):
            if not client.push_rtp(AUDIO_RTP_CHANNEL, packet):
                self._discard_rtsp_play_session(client)
        for sink in list(self._packet_sinks):
            try:
                sink.on_audio(packet)
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("[abb] packet sink on_audio failed: %s", err)
        if not self._rtsp_play_sessions and not self._packet_sinks:
            self._clear_handlers()
            self._schedule_close()
            self._notify_state()

    def start_talkback(self, session_id: str = "") -> dict[str, Any]:
        if self._temporary_talkback_active:
            raise RuntimeError("an unattended announcement is already in progress")
        session_id = str(session_id or "").strip()
        if self._talkback_owner and session_id and self._talkback_owner != session_id:
            _LOGGER.info(
                "[abb] talkback owner changing for station=%s old=%s new=%s",
                self.door.station_id or self.door.address,
                self._talkback_owner,
                session_id,
            )
        self._talkback_owner = session_id
        stats = self.session.start_talkback()
        stats["owner"] = self._talkback_owner
        self._notify_state()
        return stats

    def stop_talkback(self, session_id: str = "") -> dict[str, Any]:
        if self._temporary_talkback_active:
            raise RuntimeError("an unattended announcement is already in progress")
        session_id = str(session_id or "").strip()
        if session_id and self._talkback_owner and session_id != self._talkback_owner:
            stats = self.talkback_stats()
            stats["ignored"] = True
            stats["ignore_reason"] = "talkback_session_owner_mismatch"
            return stats
        stats = self.session.stop_talkback()
        self._talkback_owner = ""
        stats["owner"] = self._talkback_owner
        self._notify_state()
        return stats

    def feed_talkback_pcm16le(
        self,
        pcm: bytes,
        session_id: str = "",
    ) -> dict[str, Any]:
        if self._temporary_talkback_active:
            raise RuntimeError("an unattended announcement is already in progress")
        session_id = str(session_id or "").strip()
        if session_id and self._talkback_owner and session_id != self._talkback_owner:
            stats = self.talkback_stats()
            stats["queued_frames_now"] = 0
            stats["ignored"] = True
            stats["ignore_reason"] = "talkback_session_owner_mismatch"
            return stats
        owner_claimed = False
        if session_id and not self._talkback_owner:
            self._talkback_owner = session_id
            owner_claimed = True
        stats = self.session.feed_talkback_pcm16le(pcm)
        stats["owner"] = self._talkback_owner
        # The audio feed runs 10-20x/sec; writing HA entity state on every
        # chunk floods the state machine, recorder and websocket subscribers
        # for no benefit (the counters are diagnostics).  Only reflect real
        # transitions — here, the first time this session claims talkback.
        if owner_claimed:
            self._notify_state()
        return stats

    async def send_talkback_tone(
        self,
        *,
        duration_ms: int = 1200,
        frequency_hz: int = 880,
        amplitude: float = 0.35,
        session_id: str = "",
    ) -> dict[str, Any]:
        if self._temporary_talkback_active:
            raise RuntimeError("an unattended announcement is already in progress")
        session_id = str(session_id or "").strip()
        if session_id and self._talkback_owner and session_id != self._talkback_owner:
            stats = self.talkback_stats()
            stats["ignored"] = True
            stats["ignore_reason"] = "talkback_session_owner_mismatch"
            return stats
        if session_id and not self._talkback_owner:
            self._talkback_owner = session_id
        stats = await self.session.send_talkback_tone(
            duration_ms=duration_ms,
            frequency_hz=frequency_hz,
            amplitude=amplitude,
        )
        stats["owner"] = self._talkback_owner
        self._notify_state()
        return stats

    async def send_talkback_pcm16le_audio(
        self,
        pcm: bytes,
        *,
        session_id: str = "",
    ) -> dict[str, Any]:
        """Play a complete decoded clip using talkback owner semantics."""
        if self._temporary_talkback_active:
            raise RuntimeError("an unattended announcement is already in progress")
        session_id = str(session_id or "").strip()
        if session_id and self._talkback_owner and session_id != self._talkback_owner:
            stats = self.talkback_stats()
            stats["ignored"] = True
            stats["ignore_reason"] = "talkback_session_owner_mismatch"
            return stats
        if session_id and not self._talkback_owner:
            self._talkback_owner = session_id
        stats = await self.session.send_talkback_pcm16le_audio(pcm)
        stats["owner"] = self._talkback_owner
        self._notify_state()
        return stats

    async def send_temporary_talkback_pcm16le_audio(
        self,
        pcm: bytes,
        *,
        session_id: str = "",
    ) -> dict[str, Any]:
        """Open a short-lived, audio-only consumer-free talkback call."""
        session_id = str(session_id or "").strip()
        unavailable_reason = self._temporary_talkback_unavailable_reason(session_id)
        if unavailable_reason is not None:
            raise RuntimeError(unavailable_reason)

        self._temporary_talkback_active = True
        self._temporary_talkback_task = asyncio.current_task()
        self._talkback_owner = session_id
        self._notify_state()
        try:
            async with self._stream_lock:
                unavailable_reason = self._temporary_talkback_unavailable_reason(
                    session_id,
                    own_reservation=True,
                )
                if unavailable_reason is not None:
                    raise RuntimeError(unavailable_reason)
                self.session.set_packet_handlers(on_video=None, on_audio=None)
                try:
                    await self.session.open()
                    return await self.session.send_talkback_pcm16le_audio(pcm)
                finally:
                    if self.session.active:
                        await self.session.close()
        finally:
            self._talkback_owner = ""
            self._temporary_talkback_active = False
            self._temporary_talkback_task = None
            self._notify_state()


class ABBWelcomeCamera(Camera):
    """Camera entity backed by per-entity RTSP server + lazy SIP dial."""

    _attr_has_entity_name = True
    _attr_supported_features = CameraEntityFeature.STREAM
    _attr_icon = "mdi:doorbell-video"

    def __init__(
        self,
        *,
        hass: HomeAssistant,
        entry_id: str,
        coordinator: StationStreamCoordinator,
        door: Door,
        gateway_uuid: str,
        camera_index: int | None,
        camera_count: int,
        station_type: str,
        can_unlock: bool | str | int | None,
        device_info,
    ) -> None:
        super().__init__()
        self.hass = hass
        self._entry_id = entry_id
        self._coordinator = coordinator
        self._door = door
        self._gateway_uuid = gateway_uuid
        self._camera_index = camera_index
        self._camera_count = camera_count
        self._station_type = station_type
        self._can_unlock = can_unlock
        station_key = _safe_key(door.station_id or door.address)
        camera_suffix = (
            f"_cam{camera_index}"
            if camera_index is not None and camera_index > 1
            else ""
        )
        self._attr_name = (
            f"{door.name} Camera {camera_index}"
            if camera_index is not None and camera_index > 1
            else door.name
        )
        self._attr_unique_id = f"{gateway_uuid}_camera_{station_key}{camera_suffix}"
        self._attr_device_info = device_info
        self._stream_name = f"abb_{station_key}{camera_suffix}"

        self._rtsp = RtspServer(
            host="127.0.0.1",
            on_describe=self._on_rtsp_describe,
            on_play=self._on_rtsp_play,
            on_teardown=self._on_rtsp_teardown,
        )

        # WebRTC session bookkeeping (one Go2RtcWsClient per HA frontend
        # session).
        self._ws_clients: dict[str, Go2RtcWsClient] = {}
        self._ws_pending_candidates: dict[str, list[str]] = {}

        self._state_callback = self.async_write_ha_state
        self._unsub_armed: callable | None = None

    def set_camera_count(self, count: int) -> None:
        if count <= self._camera_count:
            return
        self._camera_count = count
        _LOGGER.info(
            "[abb] camera %s: updated detected camera_count=%d",
            self._attr_name, count,
        )
        self.async_write_ha_state()

    @property
    def camera_capabilities(self) -> CameraCapabilities:
        return CameraCapabilities(frontend_stream_types={StreamType.WEB_RTC})

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        talkback_stats = self._coordinator.talkback_stats()
        snapshot = self._station_screenshot()
        armed_state = get_state(self.hass, self._entry_id)
        attrs: dict[str, Any] = {
            "go2rtc_stream": self._stream_name,
            "rtsp_url": self._rtsp.url if self._rtsp.port else "",
            "lan_rtsp_url": self._lan_rtsp_url(),
            "lan_rtsp_proxy_running": self._lan_rtsp_proxy_running(),
            "lan_rtsp_proxy_port": self._lan_rtsp_proxy_port(),
            "armed": is_armed(self.hass, self._entry_id),
            "stream_target_station_id": armed_state.target_station_id,
            "stream_allowed": self._stream_allowed(),
            "pickup_allowed": is_pickup_allowed(self.hass, self._entry_id),
            "ws_sessions": len(self._ws_clients),
            "rtsp_sessions": self._rtsp.session_count,
            "stream_clients": self._coordinator.client_count,
            "stream_active": self._coordinator.active,
            "temporary_talkback_active": (
                self._coordinator.temporary_talkback_active
            ),
            "snapshot_event_id": snapshot.event_id if snapshot else "",
            "snapshot_station_id": snapshot.station_id if snapshot else "",
            "talkback_ready": self._coordinator.talkback_ready,
            "talkback_talking": bool(talkback_stats.get("talking")),
            "talkback_packets": int(talkback_stats.get("packets", 0) or 0),
            "talkback_voice_packets": int(
                talkback_stats.get("voice_packets", 0) or 0
            ),
            "talkback_underrun_packets": int(
                talkback_stats.get("underrun_packets", 0) or 0
            ),
            "talkback_dropped_frames": int(
                talkback_stats.get("dropped_frames", 0) or 0
            ),
            "talkback_gain_db": float(talkback_stats.get("gain_db", 0.0) or 0.0),
            "talkback_limited_frames": int(
                talkback_stats.get("limited_frames", 0) or 0
            ),
            "talkback_send_errors": int(
                talkback_stats.get("send_errors", 0) or 0
            ),
            "talkback_send_gaps_over_30ms": int(
                talkback_stats.get("send_gaps_over_30ms", 0) or 0
            ),
            "talkback_max_send_gap_ms": float(
                talkback_stats.get("max_send_gap_ms", 0.0) or 0.0
            ),
            "talkback_owner": talkback_stats.get("owner") or "",
            "camera_count": self._camera_count,
            "camera_interface": self._camera_count > 1,
        }
        if self._camera_index is not None:
            attrs["camera_index"] = self._camera_index
            attrs["camera_switch_body"] = f"d:{self._camera_index}"
        if self._station_type:
            attrs["station_type"] = self._station_type
        if self._can_unlock is not None:
            attrs["can_unlock"] = self._can_unlock
        return attrs

    def _lan_rtsp_url(self) -> str:
        entry_data = self.hass.data.get(DOMAIN, {}).get(self._entry_id)
        proxy = entry_data.get("rtsp_proxy") if isinstance(entry_data, dict) else None
        if proxy is None or not getattr(proxy, "running", False):
            return ""
        port = getattr(proxy, "bind_port", None)
        if not port:
            return ""
        host = str(entry_data.get("lan_rtsp_host") or "").strip()
        if not host:
            host = self._ha_lan_host()
        return f"rtsp://{host}:{port}/{self._stream_name}"

    def _lan_rtsp_proxy_running(self) -> bool:
        entry_data = self.hass.data.get(DOMAIN, {}).get(self._entry_id)
        proxy = entry_data.get("rtsp_proxy") if isinstance(entry_data, dict) else None
        return bool(proxy is not None and getattr(proxy, "running", False))

    def _lan_rtsp_proxy_port(self) -> int | None:
        entry_data = self.hass.data.get(DOMAIN, {}).get(self._entry_id)
        proxy = entry_data.get("rtsp_proxy") if isinstance(entry_data, dict) else None
        port = getattr(proxy, "bind_port", None)
        return int(port) if port else None

    def _ha_lan_host(self) -> str:
        for attr in ("internal_url", "external_url"):
            raw = getattr(self.hass.config, attr, None)
            host = urlparse(raw).hostname if raw else ""
            if host and host not in ("0.0.0.0", "::", "localhost", "127.0.0.1"):
                return host
        api = getattr(self.hass.config, "api", None)
        host = getattr(api, "host", None)
        if host and host not in ("0.0.0.0", "::", "localhost", "127.0.0.1"):
            return str(host)
        return "<home-assistant-lan-ip>"

    # ------------------------------------------------------------------ #
    # entity lifecycle                                                   #
    # ------------------------------------------------------------------ #

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._register_camera_service_target()
        self._coordinator.add_state_callback(self._state_callback)
        self._unsub_armed = async_dispatcher_connect(
            self.hass,
            signal_armed_changed(self._entry_id),
            self._on_armed_changed,
        )
        await self._rtsp.start()
        _LOGGER.info(
            "[abb] camera %s: RTSP server ready url=%s stream=%s "
            "camera_index=%s camera_count=%d",
            self._attr_name, self._rtsp.url, self._stream_name,
            self._camera_index if self._camera_index is not None else "default",
            self._camera_count,
        )
        await self._register_with_go2rtc()

    async def async_will_remove_from_hass(self) -> None:
        self._unregister_camera_service_target()
        self._coordinator.remove_state_callback(self._state_callback)
        if self._unsub_armed is not None:
            self._unsub_armed()
            self._unsub_armed = None

        for ws in list(self._ws_clients.values()):
            try:
                await ws.close()
            except Exception:  # noqa: BLE001
                pass
        self._ws_clients.clear()
        self._ws_pending_candidates.clear()

        await self._rtsp.stop()
        await self._coordinator.force_close()
        await self._unregister_from_go2rtc()
        await super().async_will_remove_from_hass()

    def _register_camera_service_target(self) -> None:
        entry_data = self.hass.data.get(DOMAIN, {}).get(self._entry_id)
        if entry_data is None:
            return
        by_entity = entry_data.setdefault("camera_entities_by_entity_id", {})
        by_entity[self.entity_id] = self
        station_id = str(self._door.station_id or "").strip()
        if station_id:
            by_station = entry_data.setdefault("camera_entities_by_station", {})
            cameras = by_station.setdefault(station_id, [])
            if self not in cameras:
                cameras.append(self)

    def _unregister_camera_service_target(self) -> None:
        entry_data = self.hass.data.get(DOMAIN, {}).get(self._entry_id)
        if entry_data is None:
            return
        by_entity = entry_data.get("camera_entities_by_entity_id")
        if isinstance(by_entity, dict):
            by_entity.pop(self.entity_id, None)
        station_id = str(self._door.station_id or "").strip()
        by_station = entry_data.get("camera_entities_by_station")
        if station_id and isinstance(by_station, dict):
            cameras = by_station.get(station_id)
            if isinstance(cameras, list) and self in cameras:
                cameras.remove(self)
                if not cameras:
                    by_station.pop(station_id, None)

    @callback
    def _on_armed_changed(self) -> None:
        if not self._stream_allowed():
            if self._rtsp.session_count or self._coordinator.active:
                _LOGGER.info(
                    "[abb] camera %s: stream no longer permitted, force-closing "
                    "camera_index=%s rtsp_sessions=%d active=%s",
                    self._attr_name,
                    self._camera_index
                    if self._camera_index is not None
                    else "default",
                    self._rtsp.session_count,
                    self._coordinator.active,
                )
                self.hass.async_create_task(self._force_teardown())
        self.async_write_ha_state()

    async def _force_teardown(self) -> None:
        await self._rtsp.stop()
        await self._coordinator.force_close()
        # Restart server so future connections still work.
        await self._rtsp.start()
        await self._register_with_go2rtc()
        self.async_write_ha_state()

    # ------------------------------------------------------------------ #
    # go2rtc registration                                                #
    # ------------------------------------------------------------------ #

    async def _register_with_go2rtc(self) -> None:
        base_url = _go2rtc_url(self.hass)
        if base_url is None:
            _LOGGER.warning(
                "[abb] camera %s: HA-bundled go2rtc not available — WebRTC disabled",
                self._door.name,
            )
            return
        session = _go2rtc_session(self.hass)
        src = self._rtsp.url
        attempts: tuple[tuple[str, dict[str, str]], ...] = (
            ("put", {"name": self._stream_name, "src": src}),
            ("patch", {"name": self._stream_name, "src": src}),
        )
        for method, params in attempts:
            try:
                request = getattr(session, method)
                async with request(
                    urljoin(base_url, "api/streams"),
                    params=params,
                    timeout=_REQUEST_TIMEOUT,
                ) as resp:
                    await resp.read()
                    if resp.status in (
                        HTTPStatus.OK,
                        HTTPStatus.CREATED,
                        HTTPStatus.NO_CONTENT,
                    ):
                        _LOGGER.info(
                            "[abb] camera %s: registered go2rtc stream %s -> %s "
                            "camera_index=%s",
                            self._attr_name, self._stream_name, src,
                            self._camera_index
                            if self._camera_index is not None
                            else "default",
                        )
                        return
            except (ClientError, TimeoutError) as err:
                _LOGGER.debug(
                    "[abb] camera %s: go2rtc %s registration error: %s",
                    self._door.name, method.upper(), err,
                )

    async def _unregister_from_go2rtc(self) -> None:
        base_url = _go2rtc_url(self.hass)
        if base_url is None:
            return
        session = _go2rtc_session(self.hass)
        for params in (
            {"name": self._stream_name},
            {"src": self._stream_name},
        ):
            try:
                async with session.delete(
                    urljoin(base_url, "api/streams"),
                    params=params,
                    timeout=_REQUEST_TIMEOUT,
                ) as resp:
                    await resp.read()
                    if resp.status in (
                        HTTPStatus.OK,
                        HTTPStatus.NO_CONTENT,
                    ):
                        return
            except (ClientError, TimeoutError) as err:
                _LOGGER.debug(
                    "[abb] camera %s: go2rtc DELETE %s failed: %s",
                    self._door.name, params, err,
                )

    # ------------------------------------------------------------------ #
    # RTSP server callbacks                                              #
    # ------------------------------------------------------------------ #

    async def _on_rtsp_describe(self) -> str | None:
        armed_state = get_state(self.hass, self._entry_id)
        _LOGGER.info(
            "[abb] camera %s: DESCRIBE armed=%s target_station=%s "
            "allowed=%s active=%s rtsp_sessions=%d camera_index=%s "
            "camera_count=%d switch_body=%s",
            self._attr_name,
            armed_state.armed,
            armed_state.target_station_id or "any",
            self._stream_allowed(),
            self._coordinator.active,
            self._rtsp.session_count,
            self._camera_index if self._camera_index is not None else "default",
            self._camera_count,
            f"d:{self._camera_index}" if self._camera_index is not None else "none",
        )
        if not self._stream_allowed():
            _LOGGER.info(
                "[abb] camera %s: refusing DESCRIBE (not armed for station) "
                "camera_index=%s station=%s target=%s",
                self._attr_name,
                self._camera_index if self._camera_index is not None else "default",
                self._station_id() or "unknown",
                armed_state.target_station_id or "any",
            )
            return None
        codec = self._coordinator.video_codec or "H264/90000"
        # WebRTC matcher needs a profile-level-id; ABB doesn't include
        # one in its SDP answer (we'd just have packetization-mode), and
        # without it go2rtc 1.9.9 logs "codecs not matched".  42e01f =
        # Constrained Baseline @ Level 3.1 — a safe lowest-common-
        # denominator that essentially all WebRTC clients accept.
        fmtp = (
            self._coordinator.video_fmtp
            or "packetization-mode=1;profile-level-id=42e01f"
        )
        # PCMA is one of the codecs WebRTC keeps in its standard menu
        # (RFC 7874) so browsers offer it alongside Opus — verified
        # locally with go2rtc 1.9.9: it passthroughs PCMA in the
        # WebRTC answer when the browser advertises it (no transcode
        # needed).  We expose it as a separate track here.
        sdp_lines = [
            "v=0",
            "o=- 0 0 IN IP4 127.0.0.1",
            "s=ABB",
            "c=IN IP4 127.0.0.1",
            "t=0 0",
            "a=control:*",
            "m=video 0 RTP/AVP 96",
            f"a=rtpmap:96 {codec}",
            f"a=fmtp:96 {fmtp}",
            "a=control:trackID=0",
            "m=audio 0 RTP/AVP 8",
            "a=rtpmap:8 PCMA/8000",
            "a=control:trackID=1",
            "",
        ]
        _LOGGER.info(
            "[abb] camera %s: DESCRIBE returning SDP codec=%s fmtp=%s "
            "camera_index=%s",
            self._attr_name, codec, fmtp,
            self._camera_index if self._camera_index is not None else "default",
        )
        return "\r\n".join(sdp_lines) + "\r\n"

    async def _on_rtsp_play(self, sess: RtspSession) -> None:
        if not self._stream_allowed():
            _LOGGER.info(
                "[abb] camera %s: refusing PLAY (not armed for station) "
                "camera_index=%s station=%s",
                self._attr_name,
                self._camera_index if self._camera_index is not None else "default",
                self._station_id() or "unknown",
            )
            return

        try:
            attached = await self._coordinator.attach_rtsp_session(sess)
        except Exception as err:  # noqa: BLE001
            _LOGGER.exception(
                "[abb] camera %s: failed to open stream session "
                "camera_index=%s: %s",
                self._attr_name,
                self._camera_index if self._camera_index is not None else "default",
                err,
            )
            return
        if not attached:
            return
        _LOGGER.info(
            "[abb] camera %s: PLAY started, forwarding RTP to RTSP client "
            "camera_index=%s rtsp_sessions=%d stream_clients=%d",
            self._attr_name,
            self._camera_index if self._camera_index is not None else "default",
            self._rtsp.session_count,
            self._coordinator.client_count,
        )
        self.async_write_ha_state()

    async def _on_rtsp_teardown(self, sess: RtspSession) -> None:
        _LOGGER.info(
            "[abb] camera %s: TEARDOWN camera_index=%s remaining_sessions=%d "
            "active=%s",
            self._attr_name,
            self._camera_index if self._camera_index is not None else "default",
            self._rtsp.session_count,
            self._coordinator.active,
        )
        self._coordinator.detach_rtsp_session(sess)
        self.async_write_ha_state()

    # ------------------------------------------------------------------ #
    # stream_source for non-WebRTC consumers                             #
    # ------------------------------------------------------------------ #

    async def stream_source(self) -> str | None:
        if _go2rtc_url(self.hass) is None:
            return None
        # HA's stream/record pipeline does not pass through the WebRTC offer
        # handler, so refresh the volatile go2rtc registration here too.
        # Bundled go2rtc may restart after entity setup and lose its streams.
        await self._register_with_go2rtc()
        return f"rtsp://{GO2RTC_RTSP_HOST}:{GO2RTC_RTSP_PORT}/{self._stream_name}"

    @property
    def talkback_ready(self) -> bool:
        return self._coordinator.talkback_ready

    @property
    def temporary_talkback_active(self) -> bool:
        return self._coordinator.temporary_talkback_active

    @property
    def talkback_stats(self) -> dict[str, Any]:
        return self._coordinator.talkback_stats()

    def talkback_target_score(self) -> tuple[int, int, int]:
        """Sort active/current talkback targets ahead of idle sub-cameras."""
        return (
            0 if self._coordinator.talkback_ready else 1,
            0 if self._coordinator.active else 1,
            0 if self._camera_index is None else 1,
        )

    async def async_talkback_start(
        self,
        talkback_session_id: str = "",
    ) -> dict[str, Any]:
        stats = self._coordinator.start_talkback(talkback_session_id)
        self.async_write_ha_state()
        return stats

    async def async_talkback_stop(
        self,
        talkback_session_id: str = "",
    ) -> dict[str, Any]:
        stats = self._coordinator.stop_talkback(talkback_session_id)
        self.async_write_ha_state()
        return stats

    async def async_talkback_pcm16le(
        self,
        pcm: bytes,
        talkback_session_id: str = "",
    ) -> dict[str, Any]:
        # No per-chunk async_write_ha_state(): the coordinator already writes
        # state on real transitions (talk start/stop, owner claim).  Writing
        # here too would push a full state update on every audio packet.
        return self._coordinator.feed_talkback_pcm16le(
            pcm,
            talkback_session_id,
        )

    async def async_talkback_tone(
        self,
        *,
        duration_ms: int = 1200,
        frequency_hz: int = 880,
        amplitude: float = 0.35,
        talkback_session_id: str = "",
    ) -> dict[str, Any]:
        stats = await self._coordinator.send_talkback_tone(
            duration_ms=duration_ms,
            frequency_hz=frequency_hz,
            amplitude=amplitude,
            session_id=talkback_session_id,
        )
        self.async_write_ha_state()
        return stats

    async def async_talkback_play_audio(
        self,
        pcm: bytes,
        talkback_session_id: str = "",
    ) -> dict[str, Any]:
        """Play decoded PCM audio through this camera's talkback leg."""
        stats = await self._coordinator.send_talkback_pcm16le_audio(
            pcm,
            session_id=talkback_session_id,
        )
        self.async_write_ha_state()
        return stats

    async def async_temporary_talkback_audio(
        self,
        pcm: bytes,
        talkback_session_id: str = "",
    ) -> dict[str, Any]:
        """Play decoded PCM through a new, short-lived intercom call."""
        try:
            return await self._coordinator.send_temporary_talkback_pcm16le_audio(
                pcm,
                session_id=talkback_session_id,
            )
        finally:
            self.async_write_ha_state()

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        snapshot = self._station_screenshot()
        return snapshot.image_data if snapshot else None

    def _station_screenshot(self):
        station_id = str(self._door.station_id or "").strip()
        if not station_id:
            return None
        entry_data = self.hass.data.get(DOMAIN, {}).get(self._entry_id) or {}
        coordinator = entry_data.get("coordinator")
        data = getattr(coordinator, "data", None)
        if data is None:
            return None
        return data.latest_screenshots_by_station.get(station_id)

    def _station_id(self) -> str:
        return str(self._door.station_id or "").strip()

    def _stream_allowed(self) -> bool:
        return is_stream_allowed(self.hass, self._entry_id, self._station_id())

    # ------------------------------------------------------------------ #
    # WebRTC offer / candidate forwarding to go2rtc                      #
    # ------------------------------------------------------------------ #

    async def async_handle_async_webrtc_offer(
        self,
        offer_sdp: str,
        session_id: str,
        send_message: WebRTCSendMessage,
    ) -> None:
        _LOGGER.info(
            "[abb] camera %s: WebRTC offer session_id=%s armed=%s "
            "allowed=%s camera_index=%s stream=%s",
            self._attr_name,
            session_id,
            is_armed(self.hass, self._entry_id),
            self._stream_allowed(),
            self._camera_index if self._camera_index is not None else "default",
            self._stream_name,
        )
        if not self._stream_allowed():
            send_message(
                WebRTCError(
                    code="abb_streaming_disarmed",
                    message=(
                        "ABB Welcome streaming is disarmed. "
                        "Toggle the streaming switch on for this station, "
                        "or wait for an inbound ring."
                    ),
                )
            )
            return

        base_url = _go2rtc_url(self.hass)
        if base_url is None:
            _LOGGER.warning(
                "[abb] camera %s: WebRTC offer failed, go2rtc unavailable "
                "camera_index=%s",
                self._attr_name,
                self._camera_index if self._camera_index is not None else "default",
            )
            send_message(
                WebRTCError(
                    code="go2rtc_unavailable",
                    message="HA-bundled go2rtc is not available",
                )
            )
            return

        # Refresh registration in case it got dropped (HA-managed go2rtc
        # restarts may wipe streams).
        await self._register_with_go2rtc()

        ws = Go2RtcWsClient(
            _go2rtc_session(self.hass),
            base_url.rstrip("/"),
            source=self._stream_name,
        )

        @callback
        def _on_message(message) -> None:
            match message:
                case Go2RTCCandidate():
                    send_message(
                        WebRTCCandidate(RTCIceCandidateInit(message.candidate))
                    )
                case Go2RTCAnswer():
                    send_message(WebRTCAnswer(message.sdp))
                case Go2RTCWsError():
                    send_message(
                        WebRTCError(
                            code="go2rtc_error",
                            message=str(message.error),
                        )
                    )

        ws.subscribe(_on_message)
        self._ws_clients[session_id] = ws

        try:
            config = self.async_get_webrtc_client_configuration()
            await ws.send(
                Go2RTCOffer(offer_sdp, config.configuration.ice_servers)
            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.exception(
                "[abb] camera %s: WebRTC offer forward failed session_id=%s "
                "camera_index=%s: %s",
                self._attr_name,
                session_id,
                self._camera_index if self._camera_index is not None else "default",
                err,
            )
            self._ws_clients.pop(session_id, None)
            try:
                await ws.close()
            except Exception:  # noqa: BLE001
                pass
            send_message(
                WebRTCError(
                    code="go2rtc_offer_failed", message=str(err),
                )
            )
            return

        for c in self._ws_pending_candidates.pop(session_id, []):
            try:
                await ws.send(Go2RTCCandidate(c))
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("[abb] queued candidate forward failed: %s", err)

    async def async_on_webrtc_candidate(
        self, session_id: str, candidate: RTCIceCandidateInit
    ) -> None:
        ws = self._ws_clients.get(session_id)
        if ws is None:
            self._ws_pending_candidates.setdefault(session_id, []).append(
                candidate.candidate
            )
            return
        try:
            await ws.send(Go2RTCCandidate(candidate.candidate))
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("[abb] forward candidate failed: %s", err)

    @callback
    def close_webrtc_session(self, session_id: str) -> None:
        ws = self._ws_clients.pop(session_id, None)
        self._ws_pending_candidates.pop(session_id, None)
        if ws is not None:
            self.hass.async_create_task(ws.close())
