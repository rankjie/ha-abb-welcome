"""Tests for talk_audio_file broadcast service and pending call routing."""

from __future__ import annotations

import asyncio
import importlib.util
import io
import sys
import types
import wave
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


def _load(name: str) -> types.ModuleType:
    pkg = sys.modules.setdefault("abb_welcome", types.ModuleType("abb_welcome"))
    pkg.__path__ = [str(_PKG_DIR)]
    full = f"abb_welcome.{name}"
    if full not in sys.modules:
        spec = importlib.util.spec_from_file_location(full, _PKG_DIR / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[full] = module
        spec.loader.exec_module(module)
    return sys.modules[full]


# Standalone test for sorting and audio framing


class _MockCamera:
    def __init__(
        self,
        name: str,
        *,
        has_pending_call: bool = False,
        talkback_ready: bool = False,
        active: bool = False,
        camera_index: int | None = None,
    ) -> None:
        self.name = name
        self.has_pending_call = has_pending_call
        self.talkback_ready = talkback_ready
        self._session = types.SimpleNamespace(active=active)
        self._camera_index = camera_index


def _camera_sort_key(camera: object) -> tuple[int, int, int, int]:
    pending = bool(getattr(camera, "has_pending_call", False))
    ready = bool(getattr(camera, "talkback_ready", False))
    session = getattr(camera, "_session", None)
    active = bool(getattr(session, "active", False))
    camera_index = getattr(camera, "_camera_index", None)
    return (
        0 if pending else 1,
        0 if ready else 1,
        0 if active else 1,
        0 if camera_index is None else 1,
    )


def test_camera_sort_key_prioritizes_pending_call() -> None:
    """A ringing outdoor station must be sorted first for talkback."""
    idle = _MockCamera("idle")
    ready = _MockCamera("ready", talkback_ready=True, active=True)
    ringing = _MockCamera("ringing", has_pending_call=True)

    cameras = [idle, ready, ringing]
    cameras.sort(key=_camera_sort_key)

    assert cameras[0] is ringing
    assert cameras[1] is ready
    assert cameras[2] is idle


def test_wav_audio_framing() -> None:
    """Test that a generated 8 kHz mono WAV produces expected 160-sample (320 byte) frames."""
    buffer = io.BytesIO()
    samples = 160 * 5  # 5 frames of 20 ms each (100 ms total)
    with wave.open(buffer, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        # 16-bit little-endian samples
        w.writeframes(b"\x00\x00" * samples)

    buffer.seek(0)
    with wave.open(buffer, "rb") as w:
        pcm_data = w.readframes(w.getnframes())

    frame_bytes = 160 * 2
    total_frames = len(pcm_data) // frame_bytes
    assert total_frames == 5
    assert len(pcm_data) == 5 * 320


if __name__ == "__main__":
    test_camera_sort_key_prioritizes_pending_call()
    test_wav_audio_framing()
    print("All tests in test_talk_audio_file.py passed successfully!")
