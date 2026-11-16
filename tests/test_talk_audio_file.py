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
        self.max_queue_frames = max_queue_frames
        self.interval = 0.02
        self.queue_frames = 0
        self.started = 0
        self.stopped = 0
        self.drained = 0
        self.frames: list[bytes] = []

    def start_talk(self) -> None:
        self.started += 1

    def feed_pcm16le(self, pcm: bytes) -> None:
        self.frames.append(pcm)

    async def drain(self, timeout: float = 1.0) -> None:
        self.drained += 1

    def stop_talk(self) -> None:
        self.stopped += 1

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


class TestCoordinatorTalkbackAudioFile(unittest.IsolatedAsyncioTestCase):
    """Verify unattended auto-open/close behavior in StationStreamCoordinator."""

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
        coord._close_task = None
        coord._talkback_owner = ""
        coord._state_callbacks = []

        calls: list[str] = []
        sender = _FakeTalkSender(active=initially_active)
        session = types.SimpleNamespace(
            active=initially_active,
            load_talkback_wav_frames=mp.StreamSession.load_talkback_wav_frames,
            talkback_stats=lambda: {"active": session.active, "talking": False},
        )

        async def _open() -> None:
            calls.append("open")
            session.active = True
            sender.active = True

        async def _close() -> None:
            calls.append("close")
            session.active = False
            sender.active = False

        async def _send_frames(frames: list[bytes], *, duration_s: float):
            calls.append("send")
            sender.frames.extend(frames)
            return {"frames_sent": len(frames), "duration_s": duration_s}

        session.open = _open
        session.close = _close
        session.send_talkback_audio_frames = _send_frames
        coord.session = session
        return coord, calls, sender

    async def test_unattended_call_opens_streams_and_closes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_wav(Path(tmpdir) / "away.wav", frames=b"\x01\x02" * 160)
            coord, calls, sender = self._make_coordinator(initially_active=False)

            stats = await coord.send_talkback_audio_file(
                file_path=str(wav_path), session_id="auto-1"
            )

            self.assertEqual(calls, ["open", "send", "close"])
            self.assertEqual(stats["frames_sent"], 1)
            self.assertEqual(len(sender.frames), 1)
            self.assertFalse(coord.session.active)
            self.assertEqual(coord._talkback_owner, "")

    async def test_invalid_wav_does_not_open_unattended_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_path = Path(tmpdir) / "bad.wav"
            bad_path.write_text("not a wav", encoding="utf-8")
            coord, calls, _ = self._make_coordinator(initially_active=False)

            with self.assertRaises(ValueError):
                await coord.send_talkback_audio_file(file_path=str(bad_path))

            self.assertEqual(calls, [])
            self.assertFalse(coord.session.active)

    async def test_active_stream_is_not_closed_after_playback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_wav(Path(tmpdir) / "msg.wav", frames=b"\x01\x02" * 160)
            coord, calls, _ = self._make_coordinator(initially_active=True)

            stats = await coord.send_talkback_audio_file(
                file_path=str(wav_path), session_id="viewer-1"
            )

            self.assertEqual(calls, ["send"])
            self.assertEqual(stats["frames_sent"], 1)
            self.assertTrue(coord.session.active)


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
