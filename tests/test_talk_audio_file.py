"""Tests for talk_audio_file streaming, WAV validation, allowlist, and call priority."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
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
        import homeassistant  # noqa: F401
    except ModuleNotFoundError:
        ha = types.ModuleType("homeassistant")
        ha_components = types.ModuleType("homeassistant.components")
        ha_camera = types.ModuleType("homeassistant.components.camera")

        class _Camera:
            pass

        class _CameraEntityFeature:
            STREAM = 1

        ha_camera.Camera = _Camera
        ha_camera.CameraEntityFeature = _CameraEntityFeature

        ha_config_entries = types.ModuleType("homeassistant.config_entries")
        ha_config_entries.ConfigEntry = object

        ha_core = types.ModuleType("homeassistant.core")
        ha_core.HomeAssistant = object
        ha_core.callback = lambda fn: fn

        ha_exceptions = types.ModuleType("homeassistant.exceptions")

        class _HomeAssistantError(Exception):
            pass

        ha_exceptions.HomeAssistantError = _HomeAssistantError

        ha_helpers = types.ModuleType("homeassistant.helpers")
        ha_entity_platform = types.ModuleType("homeassistant.helpers.entity_platform")
        ha_entity_platform.AddEntitiesCallback = object
        ha_device_registry = types.ModuleType("homeassistant.helpers.device_registry")
        ha_device_registry.DeviceInfo = dict

        for name, mod in (
            ("homeassistant", ha),
            ("homeassistant.components", ha_components),
            ("homeassistant.components.camera", ha_camera),
            ("homeassistant.config_entries", ha_config_entries),
            ("homeassistant.core", ha_core),
            ("homeassistant.exceptions", ha_exceptions),
            ("homeassistant.helpers", ha_helpers),
            ("homeassistant.helpers.entity_platform", ha_entity_platform),
            ("homeassistant.helpers.device_registry", ha_device_registry),
        ):
            sys.modules.setdefault(name, mod)


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


def _load_camera_score_class():
    """Load ABBWelcomeCamera (or its scoring methods on Python < 3.10)."""
    try:
        camera_mod = _load_submodule("camera")
        return camera_mod.ABBWelcomeCamera
    except SyntaxError:
        import textwrap

        lines = (_PKG_DIR / "camera.py").read_text(encoding="utf-8").splitlines()
        class_idx = next(
            i for i, line in enumerate(lines) if line.startswith("class ABBWelcomeCamera")
        )
        start = next(
            i
            for i in range(class_idx, len(lines))
            if lines[i].startswith("    def has_pending_call(")
        )
        # Include the @property decorator on the preceding line
        start = max(0, start - 1)
        end = next(
            i
            for i in range(start + 1, len(lines))
            if lines[i].startswith("    async def ")
        )
        snippet = textwrap.dedent("\n".join(lines[start:end]))
        namespace: dict[str, object] = {}
        exec(snippet, namespace)
        return type("ABBWelcomeCamera", (), namespace)


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
    """Verify ringing cameras sort ahead of active/ready/idle cameras."""

    def test_talkback_target_score_prioritizes_pending_call(self) -> None:
        _load_submodule("intercom_dialer")
        _load_submodule("media_pipeline")
        camera_cls = _load_camera_score_class()
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

        ringing_sub = make_camera(pending=True, ready=False, active=False, camera_index=2)
        ready_main = make_camera(pending=False, ready=True, active=True, camera_index=None)
        active_main = make_camera(pending=False, ready=False, active=True, camera_index=None)
        idle_main = make_camera(pending=False, ready=False, active=False, camera_index=None)
        idle_sub = make_camera(pending=False, ready=False, active=False, camera_index=1)

        ordered = sorted(
            [idle_sub, idle_main, active_main, ready_main, ringing_sub],
            key=sort_key,
        )
        self.assertEqual(
            ordered,
            [ringing_sub, ready_main, active_main, idle_main, idle_sub],
        )

    def test_camera_sort_key_fallback_uses_pending_call_first(self) -> None:
        sort_key = _load_camera_sort_key()
        ringing_fallback = types.SimpleNamespace(
            has_pending_call=True,
            talkback_ready=False,
            _session=types.SimpleNamespace(active=False),
            _camera_index=1,
        )
        ready_fallback = types.SimpleNamespace(
            has_pending_call=False,
            talkback_ready=True,
            _session=types.SimpleNamespace(active=True),
            _camera_index=None,
        )
        self.assertLess(sort_key(ringing_fallback), sort_key(ready_fallback))


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

    async def test_rejects_empty_wav(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wav_path = _write_wav(Path(tmpdir) / "empty.wav", frames=b"")
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


class TestTalkAudioFileAllowlist(unittest.TestCase):
    """Verify __init__.py enforces hass.config.is_allowed_path on talk_audio_file."""

    def test_init_enforces_is_allowed_path(self) -> None:
        init_source = (_PKG_DIR / "__init__.py").read_text(encoding="utf-8")
        tree = ast.parse(init_source, filename=str(_PKG_DIR / "__init__.py"))
        found_talk_audio_file = False
        calls_is_allowed_path = False
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "_talk_audio_file":
                found_talk_audio_file = True
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Attribute) and sub.attr == "is_allowed_path":
                        calls_is_allowed_path = True
        self.assertTrue(found_talk_audio_file)
        self.assertTrue(calls_is_allowed_path)


if __name__ == "__main__":
    unittest.main()
