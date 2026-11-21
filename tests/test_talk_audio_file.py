"""Tests for talk_audio_file streaming, WAV validation, allowlist, and call priority."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock
import wave

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


def _ensure_stub_dependencies() -> None:
    """Provide minimal stubs when running outside a full HA test environment."""
    try:
        import cryptography.hazmat.primitives.ciphers  # noqa: F401
    except ModuleNotFoundError:
        crypto = types.ModuleType("cryptography")
        hazmat = types.ModuleType("cryptography.hazmat")
        primitives = types.ModuleType("cryptography.hazmat.primitives")
        ciphers = types.ModuleType("cryptography.hazmat.primitives.ciphers")
        ciphers.Cipher = object
        ciphers.algorithms = types.SimpleNamespace(AES=object)
        ciphers.modes = types.SimpleNamespace(CTR=object)
        sys.modules.setdefault("cryptography", crypto)
        sys.modules.setdefault("cryptography.hazmat", hazmat)
        sys.modules.setdefault("cryptography.hazmat.primitives", primitives)
        sys.modules.setdefault("cryptography.hazmat.primitives.ciphers", ciphers)

    try:
        import aiohttp  # noqa: F401
    except ModuleNotFoundError:
        aiohttp_mod = types.ModuleType("aiohttp")
        aiohttp_mod.ClientError = Exception
        aiohttp_mod.ClientSession = object
        aiohttp_mod.ClientTimeout = lambda **kwargs: kwargs
        sys.modules.setdefault("aiohttp", aiohttp_mod)

    try:
        import go2rtc_client.ws  # noqa: F401
    except ModuleNotFoundError:
        go2rtc = types.ModuleType("go2rtc_client")
        go2rtc_ws = types.ModuleType("go2rtc_client.ws")
        go2rtc_ws.Go2RtcWsClient = object
        go2rtc_ws.WebRTCAnswer = object
        go2rtc_ws.WebRTCCandidate = object
        go2rtc_ws.WebRTCOffer = object
        go2rtc_ws.WsError = Exception
        sys.modules.setdefault("go2rtc_client", go2rtc)
        sys.modules.setdefault("go2rtc_client.ws", go2rtc_ws)

    try:
        import webrtc_models  # noqa: F401
    except ModuleNotFoundError:
        webrtc_mod = types.ModuleType("webrtc_models")
        webrtc_mod.RTCIceCandidateInit = object
        sys.modules.setdefault("webrtc_models", webrtc_mod)

    ha = sys.modules.get("homeassistant")
    if ha is None:
        ha = types.ModuleType("homeassistant")
        sys.modules["homeassistant"] = ha
    if not hasattr(ha, "__path__"):
        ha.__path__ = []

    ha_components = sys.modules.get("homeassistant.components")
    if ha_components is None:
        ha_components = types.ModuleType("homeassistant.components")
        sys.modules["homeassistant.components"] = ha_components
    if not hasattr(ha_components, "__path__"):
        ha_components.__path__ = []

    if "homeassistant.components.camera" not in sys.modules:
        ha_camera = types.ModuleType("homeassistant.components.camera")

        class _Camera:
            pass

        class _CameraEntityFeature:
            STREAM = 1

        ha_camera.Camera = _Camera
        ha_camera.CameraCapabilities = object
        ha_camera.CameraEntityFeature = _CameraEntityFeature
        ha_camera.StreamType = object
        ha_camera.WebRTCAnswer = object
        ha_camera.WebRTCCandidate = object
        ha_camera.WebRTCError = Exception
        ha_camera.WebRTCSendMessage = object
        sys.modules["homeassistant.components.camera"] = ha_camera

    ha_config_entries = sys.modules.get("homeassistant.config_entries")
    if ha_config_entries is None:
        ha_config_entries = types.ModuleType("homeassistant.config_entries")
        sys.modules["homeassistant.config_entries"] = ha_config_entries
    if not hasattr(ha_config_entries, "ConfigEntry"):
        ha_config_entries.ConfigEntry = object

    ha_core = sys.modules.get("homeassistant.core")
    if ha_core is None:
        ha_core = types.ModuleType("homeassistant.core")
        sys.modules["homeassistant.core"] = ha_core
    if not hasattr(ha_core, "HomeAssistant"):
        ha_core.HomeAssistant = object
    if not hasattr(ha_core, "callback"):
        ha_core.callback = lambda fn: fn

    ha_exceptions = sys.modules.get("homeassistant.exceptions")
    if ha_exceptions is None:
        ha_exceptions = types.ModuleType("homeassistant.exceptions")
        sys.modules["homeassistant.exceptions"] = ha_exceptions
    if not hasattr(ha_exceptions, "HomeAssistantError"):

        class _HomeAssistantError(Exception):
            pass

        ha_exceptions.HomeAssistantError = _HomeAssistantError

    ha_helpers = sys.modules.get("homeassistant.helpers")
    if ha_helpers is None:
        ha_helpers = types.ModuleType("homeassistant.helpers")
        sys.modules["homeassistant.helpers"] = ha_helpers
    if not hasattr(ha_helpers, "__path__"):
        ha_helpers.__path__ = []

    for subname, attrs in (
        ("homeassistant.helpers.aiohttp_client", {"async_get_clientsession": lambda hass: None}),
        (
            "homeassistant.helpers.dispatcher",
            {
                "async_dispatcher_connect": lambda *args, **kwargs: (lambda: None),
                "async_dispatcher_send": lambda *args, **kwargs: None,
            },
        ),
        ("homeassistant.helpers.entity_platform", {"AddEntitiesCallback": object}),
        ("homeassistant.helpers.entity_registry", {"async_get": lambda hass: None}),
        ("homeassistant.helpers.device_registry", {"DeviceInfo": dict}),
    ):
        mod = sys.modules.get(subname)
        if mod is None:
            mod = types.ModuleType(subname)
            sys.modules[subname] = mod
        for attr, val in attrs.items():
            if not hasattr(mod, attr):
                setattr(mod, attr, val)


def _load_submodule(name: str) -> types.ModuleType:
    """Load an abb_welcome submodule directly without executing __init__.py."""
    _ensure_stub_dependencies()
    pkg = sys.modules.get("abb_welcome")
    if pkg is None:
        pkg = types.ModuleType("abb_welcome")
        pkg.__path__ = [str(_PKG_DIR)]
        sys.modules["abb_welcome"] = pkg
    full = f"abb_welcome.{name}"
    if full in sys.modules:
        return sys.modules[full]
    spec = importlib.util.spec_from_file_location(full, _PKG_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[full] = module
    spec.loader.exec_module(module)
    return module


def _load_camera_sort_key():
    """Extract _camera_sort_key directly from __init__.py."""
    init_path = _PKG_DIR / "__init__.py"
    source = init_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(init_path))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_camera_sort_key":
            module_ast = ast.Module(body=[node], type_ignores=[])
            namespace: dict[str, object] = {}
            exec(compile(module_ast, str(init_path), "exec"), namespace)
            return namespace["_camera_sort_key"]
    raise AssertionError("_camera_sort_key not found in __init__.py")


def _write_wav(
    path: Path,
    *,
    channels: int = 1,
    sampwidth: int = 2,
    framerate: int = 8000,
    frames: bytes = b"\x01\x02" * 160,
) -> Path:
    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(sampwidth)
        wf.setframerate(framerate)
        wf.writeframes(frames)
    return path


def _write_mulaw_wav(path: Path, payload: bytes = b"\x7f" * 160) -> Path:
    """Write a minimal RIFF/WAVE file with audio format 7 (ITU-T G.711 mu-law)."""
    fmt_chunk = struct.pack("<HHIIHH", 7, 1, 8000, 8000, 1, 8)
    data_chunk = b"data" + struct.pack("<I", len(payload)) + payload
    riff_body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt_chunk)) + fmt_chunk + data_chunk
    path.write_bytes(b"RIFF" + struct.pack("<I", len(riff_body)) + riff_body)
    return path


class _FakeTalkSender:
    def __init__(self, *, active: bool = True, max_queue_frames: int = 10) -> None:
        self.active = active
        self.talking = False
        self.max_queue_frames = max_queue_frames
        self.interval = 0.02
        self.queue_frames = 0
        self.started = 0
        self.stopped = 0
        self.drained = 0
        self.frames: list[bytes] = []

    def start_talk(self) -> None:
        self.started += 1
        self.talking = True

    def feed_pcm16le(self, pcm: bytes) -> None:
        self.frames.append(pcm)

    async def drain(self, timeout: float = 1.0) -> None:
        self.drained += 1

    def stop_talk(self) -> None:
        self.stopped += 1
        self.talking = False

    def stats(self) -> dict[str, object]:
        return {"frames_sent": len(self.frames)}


class TestCameraTargetPriority(unittest.TestCase):
    """Verify active/ready cameras rank ahead of pending-call and idle cameras."""

    def test_talkback_target_score_orders_ready_before_pending_call(self) -> None:
        _load_submodule("intercom_dialer")
        _load_submodule("media_pipeline")
        camera_mod = _load_submodule("camera")
        camera_cls = camera_mod.ABBWelcomeCamera
        sort_key = _load_camera_sort_key()

        def make_camera(
            *,
            pending: bool = False,
            ready: bool = False,
            active: bool = False,
            camera_index: int | None = None,
        ):
            cam = camera_cls.__new__(camera_cls)
            cam._coordinator = types.SimpleNamespace(
                has_pending_call=pending,
                talkback_ready=ready,
                active=active,
            )
            cam._camera_index = camera_index
            return cam

        ready_main = make_camera(pending=False, ready=True, active=True, camera_index=None)
        active_main = make_camera(pending=False, ready=False, active=True, camera_index=None)
        ringing_sub = make_camera(pending=True, ready=False, active=False, camera_index=2)
        idle_main = make_camera(pending=False, ready=False, active=False, camera_index=None)
        idle_sub = make_camera(pending=False, ready=False, active=False, camera_index=1)

        ordered = sorted(
            [idle_sub, idle_main, ringing_sub, active_main, ready_main],
            key=sort_key,
        )
        self.assertEqual(
            ordered,
            [ready_main, active_main, ringing_sub, idle_main, idle_sub],
        )

    def test_camera_sort_key_fallback_orders_ready_before_pending_call(self) -> None:
        sort_key = _load_camera_sort_key()
        ready_fallback = types.SimpleNamespace(
            has_pending_call=False,
            talkback_ready=True,
            _session=types.SimpleNamespace(active=True),
            _camera_index=None,
        )
        ringing_fallback = types.SimpleNamespace(
            has_pending_call=True,
            talkback_ready=False,
            _session=types.SimpleNamespace(active=False),
            _camera_index=1,
        )
        idle_fallback = types.SimpleNamespace(
            has_pending_call=False,
            talkback_ready=False,
            _session=types.SimpleNamespace(active=False),
            _camera_index=None,
        )
        self.assertLess(sort_key(ready_fallback), sort_key(ringing_fallback))
        self.assertLess(sort_key(ringing_fallback), sort_key(idle_fallback))

    def test_has_pending_call_for_station_is_strictly_per_station(self) -> None:
        import time

        sip_mod = _load_submodule("sip_listener")
        listener = sip_mod.SipListener.__new__(sip_mod.SipListener)
        frame = sip_mod._SipFrame(
            start_line="INVITE sip:1001@192.168.1.10 SIP/2.0",
            headers=[("from", "<sip:0001@192.168.1.2>;tag=abc")],
            body=b"",
            raw=b"",
        )
        frame._received_at = time.time()
        listener._open_invites = {"call-1": frame}

        self.assertTrue(listener.has_pending_call_for_station("0001"))
        self.assertFalse(listener.has_pending_call_for_station("0002"))
        self.assertFalse(listener.has_pending_call_for_station(""))


class TestSendTalkbackAudioFile(unittest.IsolatedAsyncioTestCase):
    """Verify WAV validation and RTP frame chunking in StreamSession."""

    def _make_session(self, sender: _FakeTalkSender | None):
        _load_submodule("intercom_dialer")
        mp = _load_submodule("media_pipeline")
        session = mp.StreamSession.__new__(mp.StreamSession)
        session._talk_sender = sender
        return session

    async def test_valid_wav_and_uppercase_extension_stream_frames(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # 400 bytes -> 1 full 320-byte frame + 1 partial 80-byte frame padded to 320 bytes
            pcm = b"\x11\x22" * 200
            wav_path = _write_wav(Path(tmpdir) / "MESSAGE.WAV", frames=pcm)
            sender = _FakeTalkSender()
            session = self._make_session(sender)

            stats = await session.send_talkback_audio_file(str(wav_path))

            self.assertEqual(stats["frames_sent"], 2)
            self.assertEqual(sender.started, 1)
            self.assertEqual(sender.drained, 1)
            self.assertEqual(sender.stopped, 1)
            self.assertEqual(len(sender.frames[0]), 320)
            self.assertEqual(len(sender.frames[1]), 320)
            self.assertEqual(sender.frames[0], pcm[:320])
            self.assertEqual(sender.frames[1], pcm[320:].ljust(320, b"\x00"))

    async def test_rejects_non_wav_extension(self) -> None:
        session = self._make_session(_FakeTalkSender())
        with self.assertRaises(ValueError):
            await session.send_talkback_audio_file("/media/abb_welcome/alert.mp3")

    async def test_rejects_wrong_sample_rate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_wav(Path(tmpdir) / "bad_rate.wav", framerate=44100)
            session = self._make_session(_FakeTalkSender())
            with self.assertRaises(ValueError):
                await session.send_talkback_audio_file(str(wav_path))

    async def test_rejects_stereo_wav(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_wav(Path(tmpdir) / "stereo.wav", channels=2)
            session = self._make_session(_FakeTalkSender())
            with self.assertRaises(ValueError):
                await session.send_talkback_audio_file(str(wav_path))

    async def test_rejects_8bit_wav(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_wav(Path(tmpdir) / "eight_bit.wav", sampwidth=1)
            session = self._make_session(_FakeTalkSender())
            with self.assertRaises(ValueError):
                await session.send_talkback_audio_file(str(wav_path))

    async def test_rejects_empty_wav_frames(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_wav(Path(tmpdir) / "empty_frames.wav", frames=b"")
            session = self._make_session(_FakeTalkSender())
            with self.assertRaises(ValueError):
                await session.send_talkback_audio_file(str(wav_path))

    async def test_rejects_zero_byte_wav_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = Path(tmpdir) / "zero_bytes.wav"
            wav_path.write_bytes(b"")
            session = self._make_session(_FakeTalkSender())
            with self.assertRaises(ValueError):
                await session.send_talkback_audio_file(str(wav_path))

    async def test_rejects_text_file_renamed_to_wav(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = Path(tmpdir) / "not_really.wav"
            wav_path.write_text("hello world", encoding="utf-8")
            session = self._make_session(_FakeTalkSender())
            with self.assertRaises(ValueError):
                await session.send_talkback_audio_file(str(wav_path))

    async def test_rejects_mulaw_compressed_wav(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_mulaw_wav(Path(tmpdir) / "mulaw.wav")
            session = self._make_session(_FakeTalkSender())
            with self.assertRaises(ValueError):
                await session.send_talkback_audio_file(str(wav_path))

    async def test_rejects_missing_file(self) -> None:
        session = self._make_session(_FakeTalkSender())
        with self.assertRaises(FileNotFoundError):
            await session.send_talkback_audio_file("/media/abb_welcome/does_not_exist.wav")

    async def test_rejects_when_talkback_not_ready(self) -> None:
        session = self._make_session(None)
        with self.assertRaises(RuntimeError):
            await session.send_talkback_audio_file("/media/abb_welcome/msg.wav")

        inactive_session = self._make_session(_FakeTalkSender(active=False))
        with self.assertRaises(RuntimeError):
            await inactive_session.send_talkback_audio_file("/media/abb_welcome/msg.wav")

    async def test_interrupted_playback_raises_runtime_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_wav(Path(tmpdir) / "msg.wav", frames=b"\x01\x02" * 320)
            sender = _FakeTalkSender(active=True)

            async def _interrupt_on_drain(timeout: float = 1.0) -> None:
                sender.active = False
                sender.stop_talk()

            sender.drain = _interrupt_on_drain  # type: ignore[method-assign]
            session = self._make_session(sender)

            with self.assertRaises(RuntimeError):
                await session.send_talkback_audio_file(str(wav_path))


class TestCoordinatorTalkbackAudioFile(unittest.IsolatedAsyncioTestCase):
    """Verify unattended auto-open/close and lifecycle safety in StationStreamCoordinator."""

    def _make_coordinator(self, *, initially_active: bool):
        import asyncio

        _load_submodule("intercom_dialer")
        mp = _load_submodule("media_pipeline")
        camera_mod = _load_submodule("camera")

        coord = camera_mod.StationStreamCoordinator.__new__(
            camera_mod.StationStreamCoordinator
        )
        coord._stream_lock = asyncio.Lock()
        coord._rtsp_play_sessions = []
        coord._active_file_playbacks = 0
        coord._close_task = None
        coord._talkback_owner = ""
        coord._state_callbacks = []
        coord.door = types.SimpleNamespace(station_id="0001", address="0001")

        scheduled_closes: list[asyncio.Task] = []

        def _create_bg_task(coro, *, name: str = ""):
            task = asyncio.create_task(coro)
            scheduled_closes.append(task)
            return task

        coord.hass = types.SimpleNamespace(async_create_background_task=_create_bg_task)

        calls: list[str] = []
        sender = _FakeTalkSender(active=initially_active)
        session = types.SimpleNamespace(
            active=initially_active,
            previewing=False,
            load_talkback_wav_frames=mp.StreamSession.load_talkback_wav_frames,
            talkback_stats=lambda: {"active": session.active, "talking": sender.talking},
            set_packet_handlers=lambda **kw: None,
        )

        async def _open() -> None:
            calls.append("open")
            session.active = True
            sender.active = True

        async def _close() -> None:
            calls.append("close")
            session.active = False
            sender.active = False
            sender.stop_talk()

        async def _send_frames(frames: list[bytes], *, duration_s: float):
            calls.append("send")
            return await mp.StreamSession._stream_talkback_frames(
                session, sender, frames, duration_s=duration_s
            )

        session.open = _open
        session.close = _close
        session.send_talkback_audio_frames = _send_frames
        coord.session = session
        return coord, calls, sender, scheduled_closes

    async def test_unattended_call_opens_streams_and_closes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_wav(Path(tmpdir) / "away.wav", frames=b"\x01\x02" * 160)
            coord, calls, sender, scheduled = self._make_coordinator(initially_active=False)

            stats = await coord.send_talkback_audio_file(
                file_path=str(wav_path), session_id="auto-1"
            )

            self.assertEqual(calls, ["open", "send", "close"])
            self.assertEqual(stats["frames_sent"], 1)
            self.assertEqual(len(sender.frames), 1)
            self.assertFalse(coord.session.active)
            self.assertEqual(coord._talkback_owner, "")
            self.assertEqual(scheduled, [])

    async def test_invalid_wav_does_not_open_unattended_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_path = Path(tmpdir) / "bad.wav"
            bad_path.write_text("not a wav", encoding="utf-8")
            coord, calls, _, _ = self._make_coordinator(initially_active=False)

            with self.assertRaises(ValueError):
                await coord.send_talkback_audio_file(file_path=str(bad_path))

            self.assertEqual(calls, [])
            self.assertFalse(coord.session.active)

    async def test_active_stream_with_viewer_is_not_closed_after_playback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_wav(Path(tmpdir) / "msg.wav", frames=b"\x01\x02" * 160)
            coord, calls, _, scheduled = self._make_coordinator(initially_active=True)
            coord._rtsp_play_sessions.append(types.SimpleNamespace(session_id="rtsp-1"))

            stats = await coord.send_talkback_audio_file(
                file_path=str(wav_path), session_id="viewer-1"
            )

            self.assertEqual(calls, ["send"])
            self.assertEqual(stats["frames_sent"], 1)
            self.assertTrue(coord.session.active)
            self.assertEqual(scheduled, [])

    async def test_pending_close_timer_cancelled_during_playback_and_rescheduled_after(self) -> None:
        import asyncio

        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_wav(Path(tmpdir) / "msg.wav", frames=b"\x01\x02" * 160)
            coord, calls, _, scheduled = self._make_coordinator(initially_active=True)
            pending_close = asyncio.create_task(asyncio.sleep(10))
            coord._close_task = pending_close

            stats = await coord.send_talkback_audio_file(file_path=str(wav_path))
            await asyncio.sleep(0)

            self.assertTrue(pending_close.cancelled())
            self.assertEqual(calls, ["send"])
            self.assertEqual(stats["frames_sent"], 1)
            self.assertEqual(len(scheduled), 1)
            scheduled[0].cancel()

    async def test_last_rtsp_viewer_detaching_during_playback_defers_close(self) -> None:
        import asyncio

        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_wav(Path(tmpdir) / "msg.wav", frames=b"\x01\x02" * 160)
            coord, calls, sender, scheduled = self._make_coordinator(initially_active=True)
            rtsp_sess = types.SimpleNamespace(session_id="rtsp-1")
            coord._rtsp_play_sessions.append(rtsp_sess)

            async def _drain_and_detach(timeout: float = 1.0) -> None:
                coord.detach_rtsp_session(rtsp_sess)
                self.assertEqual(scheduled, [])
                self.assertTrue(coord.session.active)
                sender.drained += 1

            sender.drain = _drain_and_detach  # type: ignore[method-assign]

            stats = await coord.send_talkback_audio_file(file_path=str(wav_path))
            self.assertEqual(stats["frames_sent"], 1)
            self.assertEqual(calls, ["send"])
            self.assertEqual(len(scheduled), 1)
            scheduled[0].cancel()

    async def test_force_close_interrupts_playback_with_runtime_error(self) -> None:
        import asyncio

        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_wav(Path(tmpdir) / "msg.wav", frames=b"\x01\x02" * 160)
            coord, calls, sender, _ = self._make_coordinator(initially_active=False)

            async def _force_close_mid_drain(timeout: float = 1.0) -> None:
                await coord.force_close()

            sender.drain = _force_close_mid_drain  # type: ignore[method-assign]

            with self.assertRaises(RuntimeError):
                await coord.send_talkback_audio_file(file_path=str(wav_path))

            self.assertIn("open", calls)
            self.assertIn("close", calls)
            self.assertFalse(coord.session.active)
            self.assertEqual(coord._active_file_playbacks, 0)

    async def test_camera_refuses_talkback_audio_file_when_disarmed(self) -> None:
        _load_submodule("intercom_dialer")
        _load_submodule("media_pipeline")
        camera_mod = _load_submodule("camera")

        cam = camera_mod.ABBWelcomeCamera.__new__(camera_mod.ABBWelcomeCamera)
        called = 0

        async def _send_file(**kwargs):
            nonlocal called
            called += 1
            return {}

        cam._stream_allowed = lambda: False
        cam._coordinator = types.SimpleNamespace(send_talkback_audio_file=_send_file)
        cam.async_write_ha_state = lambda: None

        with self.assertRaises(RuntimeError):
            await cam.async_talkback_audio_file(file_path="/media/abb_welcome/msg.wav")
        self.assertEqual(called, 0)


class TestCameraUnlockButtonAttribute(unittest.TestCase):
    """The Scrypted lock finds a station's door button through its camera."""

    def _unlock_button(self, *, station_id="100000001", can_unlock=None, station_type="1"):
        _load_submodule("intercom_dialer")
        _load_submodule("media_pipeline")
        camera_mod = _load_submodule("camera")
        registered = {
            ("button", camera_mod.DOMAIN, "synthetic-gateway_100000001"): (
                "button.synthetic_front"
            )
        }
        registry = types.SimpleNamespace(
            async_get_entity_id=lambda *key: registered.get(key)
        )
        cam = camera_mod.ABBWelcomeCamera.__new__(camera_mod.ABBWelcomeCamera)
        cam.hass = object()
        cam._door = types.SimpleNamespace(station_id=station_id)
        cam._gateway_uuid = "synthetic-gateway"
        cam._can_unlock = can_unlock
        cam._station_type = station_type
        with mock.patch.object(camera_mod.er, "async_get", lambda hass: registry):
            return cam._unlock_button_entity_id()

    def test_unlockable_station_reports_its_registered_button(self) -> None:
        self.assertEqual(self._unlock_button(), "button.synthetic_front")
        self.assertEqual(self._unlock_button(station_type=""), "button.synthetic_front")

    def test_station_without_a_door_button_reports_none(self) -> None:
        self.assertIsNone(self._unlock_button(can_unlock=False))
        self.assertIsNone(self._unlock_button(station_type="2"))
        self.assertIsNone(self._unlock_button(station_id="100000009"))
        self.assertIsNone(self._unlock_button(station_id=""))


class TestTalkAudioFileAllowlistAndRegistration(unittest.IsolatedAsyncioTestCase):
    """Verify __init__.py service guard and hass.config.is_allowed_path enforcement."""

    def _register_services(self, *, has_service_fn, is_allowed_fn, cameras_fn):
        source = _PKG_DIR / "__init__.py"
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_async_register_services"
        )
        registered: dict[str, object] = {}
        vol = types.SimpleNamespace(
            Schema=lambda value: value,
            Optional=lambda key, **kwargs: key,
            Required=lambda key, **kwargs: key,
            Any=lambda *args: args,
            All=lambda *args: args,
            Coerce=lambda value: value,
            Range=lambda **kwargs: kwargs,
        )

        class _TestHomeAssistantError(Exception):
            pass

        namespace: dict[str, object] = {
            "DOMAIN": "abb_welcome",
            "vol": vol,
            "HomeAssistantError": _TestHomeAssistantError,
            "callback": lambda fn: fn,
            "DEFAULT_MESSAGE_DIAGNOSTICS_SECONDS": 300,
            "MAX_MESSAGE_DIAGNOSTICS_SECONDS": 600,
            "async_register_admin_service": lambda *a, **kw: None,
            "_cameras_for_talk_service": cameras_fn,
            "_LOGGER": types.SimpleNamespace(info=lambda *a, **kw: None),
        }
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id.startswith("SERVICE_")
                for target in node.targets
            ):
                exec(
                    compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"),
                    namespace,
                )
        exec(
            compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"),
            namespace,
        )
        hass = types.SimpleNamespace(
            config=types.SimpleNamespace(is_allowed_path=is_allowed_fn),
            services=types.SimpleNamespace(
                has_service=has_service_fn,
                async_register=lambda domain, name, handler, **kwargs: registered.setdefault(
                    name, handler
                ),
            ),
            data={},
        )
        namespace["_async_register_services"](hass)
        return registered, _TestHomeAssistantError

    async def test_disallowed_path_raises_before_touching_cameras_or_file(self) -> None:
        camera_lookups = 0

        def _cameras_fn(hass, call):
            nonlocal camera_lookups
            camera_lookups += 1
            raise AssertionError("_cameras_for_talk_service should not be called")

        registered, ha_error = self._register_services(
            has_service_fn=lambda domain, name: False,
            is_allowed_fn=lambda path: False,
            cameras_fn=_cameras_fn,
        )
        handler = registered["talk_audio_file"]
        with self.assertRaises(ha_error):
            await handler(types.SimpleNamespace(data={"file_path": "/etc/passwd"}))
        self.assertEqual(camera_lookups, 0)

    async def test_talk_audio_file_has_independent_has_service_guard(self) -> None:
        registered, _ = self._register_services(
            has_service_fn=lambda domain, name: name != "talk_audio_file",
            is_allowed_fn=lambda path: True,
            cameras_fn=lambda hass, call: [],
        )
        self.assertIn("talk_audio_file", registered)
        self.assertNotIn("talk_tone", registered)


if __name__ == "__main__":
    unittest.main()
