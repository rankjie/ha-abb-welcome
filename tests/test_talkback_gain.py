"""Talkback fixed-gain and peak-limiter tests."""

from __future__ import annotations

import importlib.util
import math
import struct
import sys
import types
from pathlib import Path

import pytest

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


intercom = _load("intercom_dialer")
media = _load("media_pipeline")


class _FakeTransport:
    def sendto(self, _packet: bytes, _destination: tuple[str, int]) -> None:
        return None

    def close(self) -> None:
        return None


def _sender(gain_db: float) -> object:
    return media._PCMATalkSender(
        _FakeTransport(),
        ("192.0.2.10", 5004),
        talkback_output_gain_db=gain_db,
    )


def test_zero_db_preserves_legacy_encoder_bytes(monkeypatch) -> None:
    sender = _sender(0.0)
    pcm = struct.pack("<160h", *range(-80, 80))

    def _unexpected_limiter(_frame: bytes) -> bytes:
        raise AssertionError("the 0 dB compatibility path must bypass the limiter")

    monkeypatch.setattr(sender, "_apply_gain_and_limiter", _unexpected_limiter)
    sender.start_talk()
    assert sender.feed_pcm16le(pcm) == 1

    with sender._condition:
        queued = list(sender._queued_pcma)
    assert queued == [media._encode_pcm16le_to_pcma(pcm)]
    assert sender.stats()["gain_db"] == 0.0
    assert sender.stats()["limited_frames"] == 0


def test_three_db_boosts_quiet_pcm_before_pcma_encoding() -> None:
    sender = _sender(3.0)
    pcm = struct.pack("<160h", *([1000] * 160))
    expected_sample = round(1000 * (10 ** (3.0 / 20.0)))

    sender.start_talk()
    assert sender.feed_pcm16le(pcm) == 1

    boosted = struct.pack("<160h", *([expected_sample] * 160))
    with sender._condition:
        queued = list(sender._queued_pcma)
    assert expected_sample > 1000
    assert queued == [media._encode_pcm16le_to_pcma(boosted)]
    assert sender.stats()["limited_frames"] == 0


def test_loud_pcm_is_peak_limited_without_a_clipped_plateau() -> None:
    sender = _sender(3.0)
    samples = [30000, 29900, -30000, -29900] * 40

    limited = sender._apply_gain_and_limiter(struct.pack("<160h", *samples))
    output = struct.unpack("<160h", limited)

    assert max(abs(sample) for sample in output) <= 32767
    assert output[0] == 32767
    assert abs(output[1]) < 32767
    assert output[2] == -32767
    assert abs(output[3]) < 32767
    assert sender.stats()["limited_frames"] == 1


def test_limiter_recovers_smoothly_toward_requested_gain() -> None:
    sender = _sender(3.0)
    loud = struct.pack("<160h", *([30000] * 160))
    quiet = struct.pack("<160h", *([1000] * 160))

    sender._apply_gain_and_limiter(loud)
    reduced = sender._applied_gain_factor
    sender._apply_gain_and_limiter(quiet)
    first_recovery = sender._applied_gain_factor
    sender._apply_gain_and_limiter(quiet)
    second_recovery = sender._applied_gain_factor

    assert reduced == pytest.approx(32767 / 30000)
    assert first_recovery == pytest.approx(
        reduced + (sender._requested_gain_factor - reduced) * 0.2
    )
    assert reduced < first_recovery < second_recovery < math.pow(10, 3 / 20)
    assert sender.stats()["limited_frames"] == 3


def test_stream_session_reports_configured_gain_before_media_is_open() -> None:
    session = media.StreamSession(
        dialer=object(),
        door=intercom.Door("door", "address"),
        gateway_host="192.0.2.10",
        talkback_output_gain_db=2.0,
    )

    assert session.talkback_stats() == {
        "active": False,
        "talking": False,
        "gain_db": 2.0,
        "limited_frames": 0,
    }
