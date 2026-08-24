"""Tests for the native ring-clip recorder: RTP depacketizing and mp4 remux."""

from __future__ import annotations

import asyncio
import importlib.util
import struct
import sys
import types
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


def _install_homeassistant_stubs() -> None:
    """Install a minimal homeassistant.components.ffmpeg stub for finalize()."""
    homeassistant = sys.modules.setdefault(
        "homeassistant", types.ModuleType("homeassistant")
    )
    homeassistant.__path__ = []
    components = sys.modules.setdefault(
        "homeassistant.components", types.ModuleType("homeassistant.components")
    )
    components.__path__ = []
    ffmpeg = types.ModuleType("homeassistant.components.ffmpeg")
    ffmpeg.get_ffmpeg_manager = lambda hass: hass.ffmpeg
    sys.modules[ffmpeg.__name__] = ffmpeg


def _load(name: str) -> types.ModuleType:
    pkg = types.ModuleType("abb_welcome")
    pkg.__path__ = [str(_PKG_DIR)]
    sys.modules.setdefault("abb_welcome", pkg)
    full = f"abb_welcome.{name}"
    if full not in sys.modules:
        spec = importlib.util.spec_from_file_location(full, _PKG_DIR / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[full] = module
        spec.loader.exec_module(module)
    return sys.modules[full]


_install_homeassistant_stubs()
media = _load("media_pipeline")
ring_clip = _load("ring_clip")


def _rtp(seq: int, payload: bytes, *, pt: int = 96) -> bytes:
    """Build a minimal RTP/H.264 packet: fixed 12-byte header + payload."""
    return (
        struct.pack("!BBHII", 0x80, pt & 0x7F, seq & 0xFFFF, 0, 0xCAFEBABE) + payload
    )


def _rtcp_packet() -> bytes:
    """Build a minimal RTCP-shaped packet (V=2, PT within 192-223)."""
    return struct.pack("!BBH", 0x80, 200, 0)


# --------------------------------------------------------------------------- #
# H264Depacketizer
# --------------------------------------------------------------------------- #


def test_single_nal_passthrough() -> None:
    depacketizer = ring_clip.H264Depacketizer()
    nal = b"\x65" + b"idr-payload"

    assert depacketizer.push(_rtp(1, nal)) == [nal]
    assert depacketizer.packets == 1
    assert depacketizer.nals_out == 1


def test_stap_a_reassembly_yields_member_nals_in_order() -> None:
    depacketizer = ring_clip.H264Depacketizer()
    sps = b"\x67SPSDATA"
    pps = b"\x68PPSDATA"
    payload = (
        bytes([0x78])
        + struct.pack("!H", len(sps))
        + sps
        + struct.pack("!H", len(pps))
        + pps
    )

    assert depacketizer.push(_rtp(1, payload)) == [sps, pps]
    assert depacketizer.nals_out == 2


def test_stap_a_with_truncated_member_size_drops_whole_packet() -> None:
    depacketizer = ring_clip.H264Depacketizer()
    sps = b"\x67SPS"
    # Declares a member larger than the bytes actually present.
    payload = bytes([0x78]) + struct.pack("!H", len(sps) + 10) + sps

    assert depacketizer.push(_rtp(1, payload)) == []


def test_fu_a_reassembles_start_middle_end_fragments() -> None:
    depacketizer = ring_clip.H264Depacketizer()
    indicator = 0x7C  # F=0, NRI=3, type=28 (FU-A)
    part1, part2, part3 = b"AAAA", b"BBBB", b"CCCC"
    start = bytes([indicator, 0x85]) + part1  # S=1, original type=5 (IDR)
    middle = bytes([indicator, 0x05]) + part2
    end = bytes([indicator, 0x45]) + part3  # E=1

    assert depacketizer.push(_rtp(1, start)) == []
    assert depacketizer.push(_rtp(2, middle)) == []
    reassembled = depacketizer.push(_rtp(3, end))

    # Reconstructed header = FU indicator's F/NRI bits | original NAL type.
    assert reassembled == [bytes([0x65]) + part1 + part2 + part3]
    assert depacketizer.nals_out == 1


def test_fu_a_end_fragment_without_start_yields_nothing() -> None:
    depacketizer = ring_clip.H264Depacketizer()
    orphan_end = bytes([0x7C, 0x45]) + b"orphan"

    assert depacketizer.push(_rtp(1, orphan_end)) == []


def test_rtcp_is_checked_first_and_dropped() -> None:
    depacketizer = ring_clip.H264Depacketizer()
    rtcp_packet = _rtcp_packet()
    assert media._is_rtcp_packet(rtcp_packet) is True

    assert depacketizer.push(rtcp_packet) == []
    assert depacketizer.rtcp_dropped == 1
    assert depacketizer.packets == 0
    # A single RTCP packet in between must not perturb RTP sequence tracking.
    assert depacketizer.push(_rtp(1, b"\x65a")) == [b"\x65a"]
    assert depacketizer.push(_rtp(2, b"\x65b")) == [b"\x65b"]
    assert depacketizer.seq_gaps == 0


def test_sequence_gap_discards_fu_a_and_waits_for_sps_or_idr() -> None:
    depacketizer = ring_clip.H264Depacketizer()

    # seq=1: baseline single-NAL frame establishes the sequence.
    frame1 = b"\x61" + b"frame1"
    assert depacketizer.push(_rtp(1, frame1)) == [frame1]

    # seq=2: start of an FU-A that will never complete before the gap.
    assert depacketizer.push(_rtp(2, bytes([0x7C, 0x85]) + b"partial")) == []

    # seq=4 skips 3 -> gap. The in-progress FU-A is discarded and this
    # non-keyframe single-NAL is suppressed until a fresh SPS/IDR arrives.
    non_key = b"\x61" + b"frame_after_gap"
    assert depacketizer.push(_rtp(4, non_key)) == []
    assert depacketizer.seq_gaps == 1
    assert depacketizer.dropped_while_resyncing == 1

    # The orphaned FU-A end fragment (its start was discarded) yields nothing.
    assert depacketizer.push(_rtp(5, bytes([0x7C, 0x45]) + b"orphan")) == []

    # seq=6: a fresh IDR ends the resync window and is itself emitted.
    idr = b"\x65" + b"keyframe"
    assert depacketizer.push(_rtp(6, idr)) == [idr]

    # seq=7: normal output resumes.
    normal = b"\x61" + b"frame_after_keyframe"
    assert depacketizer.push(_rtp(7, normal)) == [normal]
    assert depacketizer.nals_out == 3  # frame1, idr, normal (the rest were dropped)


# --------------------------------------------------------------------------- #
# RingClipWriter framing
# --------------------------------------------------------------------------- #


class _Config:
    def __init__(self, *, allowed: bool = True) -> None:
        self._allowed = allowed

    def is_allowed_path(self, _path: str) -> bool:
        return self._allowed


class _Hass:
    def __init__(
        self, *, allowed: bool = True, ffmpeg_binary: str = "/configured/ffmpeg"
    ) -> None:
        self.config = _Config(allowed=allowed)
        self.ffmpeg = types.SimpleNamespace(binary=ffmpeg_binary)


class _FakeProcess:
    def __init__(self, *, returncode: int = 0, stderr: bytes = b"") -> None:
        self.returncode: int | None = None
        self._returncode_to_set = returncode
        self._stderr = stderr
        self.killed = False

    async def communicate(self) -> tuple[bytes | None, bytes]:
        self.returncode = self._returncode_to_set
        return None, self._stderr

    async def wait(self) -> int:
        self.returncode = self._returncode_to_set
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self._returncode_to_set = -9


def test_writer_enforces_is_allowed_path(tmp_path: Path) -> None:
    hass = _Hass(allowed=False)
    with pytest.raises(PermissionError):
        ring_clip.RingClipWriter(hass, tmp_path, "clip")
    assert list(tmp_path.iterdir()) == []


def test_writer_frames_nals_to_annex_b_file(tmp_path: Path) -> None:
    hass = _Hass()
    writer = ring_clip.RingClipWriter(hass, tmp_path, "clip")
    assert writer.path == tmp_path / "clip.h264"
    assert writer.path.exists()

    writer.on_video(_rtp(1, b"\x67SPS"))
    writer.on_video(_rtp(2, b"\x68PPS"))
    writer.on_video(_rtp(3, b"\x65KEYFRAME"))
    writer.on_audio(b"ignored-audio-should-not-raise")
    writer.close()

    expected = (
        b"\x00\x00\x00\x01\x67SPS"
        b"\x00\x00\x00\x01\x68PPS"
        b"\x00\x00\x00\x01\x65KEYFRAME"
    )
    assert writer.path.read_bytes() == expected
    assert writer.nals == 3
    assert writer.frames == 1  # only the IDR slice is a coded picture
    assert writer.bytes_written == len(expected)
    assert writer.first_wall_time is not None
    assert writer.last_wall_time is not None
    assert writer.elapsed_s >= 0.0


def test_writer_close_is_idempotent_and_stops_accepting_packets(
    tmp_path: Path,
) -> None:
    hass = _Hass()
    writer = ring_clip.RingClipWriter(hass, tmp_path, "clip")
    writer.on_video(_rtp(1, b"\x65X"))
    writer.close()
    writer.close()  # must not raise

    size_before = writer.path.stat().st_size
    writer.on_video(_rtp(2, b"\x65Y"))
    assert writer.path.stat().st_size == size_before
    assert writer.nals == 1


# --------------------------------------------------------------------------- #
# RingClipWriter.finalize (ffmpeg remux)
# --------------------------------------------------------------------------- #


def test_finalize_computes_fps_writes_mp4_and_removes_h264(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    times = iter([100.0, 100.5, 101.0])
    monkeypatch.setattr(ring_clip.time, "time", lambda: next(times))

    hass = _Hass()
    writer = ring_clip.RingClipWriter(hass, tmp_path, "clip")
    writer.on_video(_rtp(1, b"\x67SPS"))  # t=100.0, not a coded picture
    writer.on_video(_rtp(2, b"\x65IDR"))  # t=100.5, frame 1
    writer.on_video(_rtp(3, b"\x61P"))  # t=101.0, frame 2

    captured: dict[str, object] = {}
    process = _FakeProcess(returncode=0)

    async def _spawn(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        Path(args[-1]).write_bytes(b"fake-mp4-bytes")
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)
    result = asyncio.run(writer.finalize())

    assert result.ok is True
    assert result.output_path == tmp_path / "clip.mp4"
    assert result.output_path.read_bytes() == b"fake-mp4-bytes"
    assert not writer.path.exists()  # .h264 removed on success
    assert result.nals == 3
    assert result.frames == 2
    assert result.segments == 1
    assert result.duration_s == pytest.approx(1.0)
    assert result.started_at == pytest.approx(100.0)
    assert result.fps == 2  # round(2 frames / 1.0s)

    args = captured["args"]
    assert args[0] == "/configured/ffmpeg"
    assert args[1:5] == ("-hide_banner", "-loglevel", "error", "-nostdin")
    assert args[args.index("-r") + 1] == "2"
    assert args[args.index("-i") + 1] == str(writer.path)
    assert args[-1] == str(tmp_path / "clip.mp4")


def test_finalize_keeps_h264_and_reports_failure_on_ffmpeg_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hass = _Hass()
    writer = ring_clip.RingClipWriter(hass, tmp_path, "clip")
    writer.on_video(_rtp(1, b"\x65IDR"))

    process = _FakeProcess(returncode=1, stderr=b"decoder error: bad stream")

    async def _spawn(*_args, **_kwargs):
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)
    result = asyncio.run(writer.finalize())

    assert result.ok is False
    assert "decoder error: bad stream" in result.error
    assert writer.path.exists()  # kept on failure
    assert result.output_path == writer.path
    assert not (tmp_path / "clip.mp4").exists()


def test_finalize_short_circuits_without_spawning_ffmpeg_when_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hass = _Hass()
    writer = ring_clip.RingClipWriter(hass, tmp_path, "clip")

    async def _spawn(*_args, **_kwargs):
        raise AssertionError("ffmpeg must not be spawned with zero NALs captured")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)
    result = asyncio.run(writer.finalize())

    assert result.ok is False
    assert result.error == "no video captured"
    assert result.nals == 0


def test_finalize_concatenates_multi_segment_and_removes_both_h264(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hass = _Hass()
    writer1 = ring_clip.RingClipWriter(hass, tmp_path, "clip")
    writer1.on_video(_rtp(1, b"\x67SPS"))
    writer1.on_video(_rtp(2, b"\x65IDR1"))
    writer1.close()

    writer2 = ring_clip.RingClipWriter(hass, tmp_path, "clip.part2")
    writer2.on_video(_rtp(1, b"\x67SPS"))
    writer2.on_video(_rtp(2, b"\x65IDR2"))
    writer2.close()

    expected_concat = writer1.path.read_bytes() + writer2.path.read_bytes()

    captured: dict[str, object] = {}
    process = _FakeProcess(returncode=0)

    async def _spawn(*args, **_kwargs):
        captured["args"] = args
        captured["input_at_spawn_time"] = Path(args[args.index("-i") + 1]).read_bytes()
        Path(args[-1]).write_bytes(b"fake-mp4-bytes")
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)
    result = asyncio.run(writer1.finalize(extra_segments=[writer2]))

    assert result.ok is True
    assert result.segments == 2
    assert result.nals == 4
    assert result.frames == 2
    assert captured["input_at_spawn_time"] == expected_concat
    assert not writer1.path.exists()
    assert not writer2.path.exists()


def test_finalize_is_cancellable_and_kills_the_ffmpeg_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hass = _Hass()
    writer = ring_clip.RingClipWriter(hass, tmp_path, "clip")
    writer.on_video(_rtp(1, b"\x65IDR"))

    process = _FakeProcess(returncode=0)
    blocked = asyncio.Event()

    async def _communicate():
        blocked.set()
        await asyncio.Event().wait()  # never resolves on its own

    process.communicate = _communicate  # type: ignore[method-assign]

    async def _spawn(*_args, **_kwargs):
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)

    async def _run_and_cancel() -> None:
        task = asyncio.create_task(writer.finalize())
        await blocked.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(_run_and_cancel())
    assert process.killed
