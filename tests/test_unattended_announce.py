"""Focused tests for consumer-free unattended announcement calls."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"
_PACKAGE = "abb_unattended_announce_test"


def _module(name: str, **attributes: object) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__dict__.update(attributes)
    sys.modules[name] = module
    return module


def _install_import_stubs() -> None:
    class _ClientTimeout:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

    _module(
        "aiohttp",
        ClientError=Exception,
        ClientSession=object,
        ClientTimeout=_ClientTimeout,
    )

    go2rtc_client = _module("go2rtc_client")
    go2rtc_client.__path__ = []

    class _WsMessage:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.args = args
            self.kwargs = kwargs

    _module(
        "go2rtc_client.ws",
        Go2RtcWsClient=object,
        WebRTCAnswer=_WsMessage,
        WebRTCCandidate=_WsMessage,
        WebRTCOffer=_WsMessage,
        WsError=_WsMessage,
    )

    homeassistant = _module("homeassistant")
    homeassistant.__path__ = []
    components = _module("homeassistant.components")
    components.__path__ = []

    class _Camera:
        pass

    class _CameraCapabilities:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

    class _Message:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.args = args
            self.kwargs = kwargs

    _module(
        "homeassistant.components.camera",
        Camera=_Camera,
        CameraCapabilities=_CameraCapabilities,
        CameraEntityFeature=types.SimpleNamespace(STREAM=1),
        StreamType=types.SimpleNamespace(WEB_RTC="web_rtc"),
        WebRTCAnswer=_Message,
        WebRTCCandidate=_Message,
        WebRTCError=_Message,
        WebRTCSendMessage=object,
    )
    _module("homeassistant.config_entries", ConfigEntry=object)
    _module(
        "homeassistant.core",
        HomeAssistant=object,
        callback=lambda func: func,
    )
    helpers = _module("homeassistant.helpers")
    helpers.__path__ = []
    _module(
        "homeassistant.helpers.aiohttp_client",
        async_get_clientsession=lambda hass: hass.session,
    )
    _module(
        "homeassistant.helpers.dispatcher",
        async_dispatcher_connect=lambda *_args, **_kwargs: None,
    )
    _module("homeassistant.helpers.entity_platform", AddEntitiesCallback=object)
    _module("webrtc_models", RTCIceCandidateInit=_Message)


def _install_local_stubs() -> None:
    package = types.ModuleType(_PACKAGE)
    package.__path__ = [str(_PKG_DIR)]
    sys.modules[_PACKAGE] = package

    def local(name: str, **attributes: object) -> None:
        _module(f"{_PACKAGE}.{name}", **attributes)

    local(
        "const",
        DOMAIN="abb_welcome",
        GATEWAY_PROFILE_APP_MANAGED="app_managed",
        GO2RTC_RTSP_HOST="127.0.0.1",
        GO2RTC_RTSP_PORT=8554,
        gateway_profile=lambda _data: "legacy",
        talkback_output_gain_db=lambda _data, _options: 0.0,
    )
    local("device", gateway_device_info=lambda _data: {})
    local(
        "intercom_dialer",
        Door=object,
        IntercomDialer=object,
    )
    local("media_pipeline", StreamSession=object)

    class _Logger:
        def __getattr__(self, _name: str):
            return lambda *_args, **_kwargs: None

    local("redaction", get_redacting_logger=lambda _name: _Logger())
    local(
        "rtsp_server",
        AUDIO_RTP_CHANNEL=2,
        VIDEO_RTP_CHANNEL=0,
        RtspServer=object,
        RtspSession=object,
    )
    local(
        "streaming_state",
        get_state=lambda *_args: None,
        is_armed=lambda *_args: False,
        is_pickup_allowed=lambda *_args: False,
        is_stream_allowed=lambda *_args: False,
        signal_armed_changed=lambda *_args: "armed_changed",
    )


def _load_camera() -> types.ModuleType:
    _install_import_stubs()
    _install_local_stubs()
    full_name = f"{_PACKAGE}.camera"
    spec = importlib.util.spec_from_file_location(full_name, _PKG_DIR / "camera.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


camera = _load_camera()


class _FakeStreamSession:
    def __init__(self) -> None:
        self.active = False
        self.calls: list[object] = []

    def set_packet_handlers(self, *, on_video: object, on_audio: object) -> None:
        self.calls.append(("set_packet_handlers", on_video, on_audio))

    async def open(self) -> None:
        self.calls.append("open")
        self.active = True

    async def send_talkback_pcm16le_audio(self, pcm: bytes) -> dict[str, int]:
        self.calls.append(("play", pcm))
        return {"packets": 3}

    async def close(self) -> None:
        self.calls.append("close")
        self.active = False


def _coordinator(
    session: _FakeStreamSession | None = None,
    *,
    peers: list[object] | None = None,
) -> "camera.StationStreamCoordinator":
    coordinator = camera.StationStreamCoordinator.__new__(
        camera.StationStreamCoordinator
    )
    coordinator.session = session or _FakeStreamSession()
    coordinator._stream_lock = asyncio.Lock()
    coordinator._rtsp_play_sessions = []
    coordinator._close_task = None
    coordinator._talkback_owner = ""
    coordinator._temporary_talkback_active = False
    coordinator._temporary_talkback_task = None
    coordinator._peer_coordinators = lambda: peers or []
    coordinator._state_callbacks = []
    return coordinator


def test_temporary_announcement_opens_plays_closes_and_clears_state() -> None:
    async def scenario() -> None:
        session = _FakeStreamSession()
        coordinator = _coordinator(session)
        state_changes: list[tuple[bool, str, object]] = []
        coordinator.add_state_callback(
            lambda: state_changes.append(
                (
                    coordinator.temporary_talkback_active,
                    coordinator.talkback_owner,
                    coordinator._temporary_talkback_task,
                )
            )
        )

        result = await coordinator.send_temporary_talkback_pcm16le_audio(
            b"speech",
            session_id="announcement-owner",
        )

        assert result == {"packets": 3}
        assert session.calls == [
            ("set_packet_handlers", None, None),
            "open",
            ("play", b"speech"),
            "close",
        ]
        assert state_changes[0][0:2] == (True, "announcement-owner")
        assert state_changes[0][2] is asyncio.current_task()
        assert state_changes[-1] == (False, "", None)
        assert coordinator.temporary_talkback_active is False
        assert coordinator.talkback_owner == ""
        assert coordinator._temporary_talkback_task is None

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("occupied_by", "message"),
    [
        ("active_session", "an intercom stream or call is already active"),
        ("rtsp_client", "an RTSP camera stream is already in use"),
        (
            "peer_announcement",
            "another unattended announcement is already in progress",
        ),
    ],
)
def test_temporary_announcement_refuses_busy_group(
    occupied_by: str,
    message: str,
) -> None:
    async def scenario() -> None:
        session = _FakeStreamSession()
        coordinator = _coordinator(session)
        if occupied_by == "active_session":
            session.active = True
        elif occupied_by == "rtsp_client":
            coordinator._rtsp_play_sessions.append(object())
        else:
            peer = _coordinator()
            peer._temporary_talkback_active = True
            coordinator._peer_coordinators = lambda: [peer]

        with pytest.raises(RuntimeError, match=message):
            await coordinator.send_temporary_talkback_pcm16le_audio(b"speech")

        assert session.calls == []
        assert coordinator.temporary_talkback_active is False
        assert coordinator.talkback_owner == ""
        assert coordinator._temporary_talkback_task is None

    asyncio.run(scenario())


def test_temporary_announcement_open_failure_closes_and_clears_state() -> None:
    class _OpenFailureSession(_FakeStreamSession):
        async def open(self) -> None:
            self.calls.append("open")
            self.active = True
            raise OSError("SIP open failed")

    async def scenario() -> None:
        session = _OpenFailureSession()
        coordinator = _coordinator(session)

        with pytest.raises(OSError, match="SIP open failed"):
            await coordinator.send_temporary_talkback_pcm16le_audio(
                b"speech",
                session_id="owner",
            )

        assert session.calls == [
            ("set_packet_handlers", None, None),
            "open",
            "close",
        ]
        assert session.active is False
        assert coordinator.temporary_talkback_active is False
        assert coordinator.talkback_owner == ""
        assert coordinator._temporary_talkback_task is None

    asyncio.run(scenario())


def test_cancelling_temporary_announcement_closes_and_clears_state() -> None:
    class _BlockingPlaybackSession(_FakeStreamSession):
        def __init__(self) -> None:
            super().__init__()
            self.play_started = asyncio.Event()

        async def send_talkback_pcm16le_audio(self, pcm: bytes) -> dict[str, int]:
            self.calls.append(("play", pcm))
            self.play_started.set()
            await asyncio.Future()
            raise AssertionError("unreachable")

    async def scenario() -> None:
        session = _BlockingPlaybackSession()
        coordinator = _coordinator(session)
        task = asyncio.create_task(
            coordinator.send_temporary_talkback_pcm16le_audio(
                b"speech",
                session_id="owner",
            )
        )
        await session.play_started.wait()
        assert coordinator.temporary_talkback_active is True
        assert coordinator.talkback_owner == "owner"

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert session.calls == [
            ("set_packet_handlers", None, None),
            "open",
            ("play", b"speech"),
            "close",
        ]
        assert session.active is False
        assert coordinator.temporary_talkback_active is False
        assert coordinator.talkback_owner == ""
        assert coordinator._temporary_talkback_task is None

    asyncio.run(scenario())


def test_rtsp_attach_is_rejected_and_closed_during_peer_announcement() -> None:
    class _RtspSession:
        session_id = "rtsp-client"

        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    async def scenario() -> None:
        peer = _coordinator()
        peer._temporary_talkback_active = True
        session = _FakeStreamSession()
        coordinator = _coordinator(session, peers=[peer])
        rtsp_session = _RtspSession()

        attached = await coordinator.attach_rtsp_session(rtsp_session)

        assert attached is False
        assert rtsp_session.closed is True
        assert coordinator._rtsp_play_sessions == []
        assert session.calls == [("set_packet_handlers", None, None)]

    asyncio.run(scenario())
