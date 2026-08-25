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

    async def async_add_executor_job(self, func, *args):
        return func(*args)


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


def test_writer_frames_nals_to_annex_b_buffer(tmp_path: Path) -> None:
    hass = _Hass()
    writer = ring_clip.RingClipWriter(hass, tmp_path, "clip")
    assert writer.path == tmp_path / "clip.h264"
    # Nothing touches disk until finalize(): on_video only buffers in RAM.
    assert not writer.path.exists()

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
    assert bytes(writer._buffer) == expected
    assert not writer.path.exists()  # still nothing on disk after close()
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

    size_before = len(writer._buffer)
    writer.on_video(_rtp(2, b"\x65Y"))
    assert len(writer._buffer) == size_before
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

    # Segments are buffered in memory (never written per-segment to disk),
    # so the expected concatenation is built from the same known bytes,
    # not read back from either writer's (nonexistent, pre-finalize) path.
    expected_concat = (
        b"\x00\x00\x00\x01\x67SPS"
        b"\x00\x00\x00\x01\x65IDR1"
        b"\x00\x00\x00\x01\x67SPS"
        b"\x00\x00\x00\x01\x65IDR2"
    )

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


def test_finalize_drops_empty_segment_and_leaves_no_stray_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A continuation re-dial that captured zero video must vanish cleanly.

    This is what used to leave a 0-byte ``clip.part2.h264`` behind on the
    live system: the segment file was created eagerly on construction and
    then never cleaned up because finalize() never actually ran. With
    in-memory buffering an empty segment never touches disk in the first
    place, and finalize() drops it from the concat entirely.
    """
    hass = _Hass()
    writer1 = ring_clip.RingClipWriter(hass, tmp_path, "clip")
    writer1.on_video(_rtp(1, b"\x67SPS"))
    writer1.on_video(_rtp(2, b"\x65IDR1"))
    writer1.close()

    # A continuation writer that never received any video (e.g. the
    # re-dial was BYE'd before the first RTP packet arrived).
    writer2 = ring_clip.RingClipWriter(hass, tmp_path, "clip.part2")
    writer2.close()
    assert not writer2.path.exists()

    process = _FakeProcess(returncode=0)

    async def _spawn(*args, **_kwargs):
        Path(args[-1]).write_bytes(b"fake-mp4-bytes")
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)
    result = asyncio.run(writer1.finalize(extra_segments=[writer2]))

    assert result.ok is True
    assert result.segments == 1  # the empty continuation is dropped
    assert result.nals == 2
    assert result.frames == 1
    assert not writer2.path.exists()  # never created, not just cleaned up
    assert not writer1.path.exists()  # removed after a successful remux


def test_finalize_clamps_fps_to_sane_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A degenerate frames/elapsed ratio must not reach ffmpeg's -r as-is."""
    # 21 packets spread over 0.1s: round(21 / 0.1) = 210fps raw.
    times = iter([100.0 + i * 0.005 for i in range(21)])
    monkeypatch.setattr(ring_clip.time, "time", lambda: next(times))

    hass = _Hass()
    writer = ring_clip.RingClipWriter(hass, tmp_path, "clip")
    for seq in range(1, 22):
        writer.on_video(_rtp(seq, bytes([0x65, seq])))

    captured: dict[str, object] = {}
    process = _FakeProcess(returncode=0)

    async def _spawn(*args, **_kwargs):
        captured["args"] = args
        Path(args[-1]).write_bytes(b"fake-mp4-bytes")
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)
    result = asyncio.run(writer.finalize())

    assert result.ok is True
    assert result.frames == 21
    assert result.duration_s == pytest.approx(0.1)
    assert result.fps == 30  # clamped down from round(21 / 0.1) == 210
    args = captured["args"]
    assert args[args.index("-r") + 1] == "30"


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


# --------------------------------------------------------------------------- #
# _capture_ring_clip (custom_components/abb_welcome/__init__.py)
#
# Loaded under its own synthetic package name (not "abb_welcome", which the
# RingClipWriter tests above already own) with just enough of a
# homeassistant/sibling-module stub surface to import it. const/redaction/
# ring_clip are aliased to the exact same real modules used above (so
# RingClipWriter/RingClipResult are the identical classes); everything
# __init__.py imports that only exists to talk to real Home Assistant, or
# to camera.py's heavier go2rtc-backed stream coordinator, is a bare stub —
# none of it sits on _capture_ring_clip's execution path once a fake
# per-station coordinator is supplied directly.
# --------------------------------------------------------------------------- #

_INIT_PACKAGE = "abb_welcome_capture_test"


def _install_capture_homeassistant_stubs() -> None:
    _install_homeassistant_stubs()  # homeassistant(.components(.ffmpeg))

    def module(name: str, **attributes: object) -> types.ModuleType:
        mod = sys.modules.get(name) or types.ModuleType(name)
        mod.__dict__.update(attributes)
        sys.modules[name] = mod
        return mod

    module("homeassistant.helpers").__path__ = []
    module(
        "homeassistant.components.tts",
        generate_media_source_id=lambda *_a, **_k: "",
    )
    module("homeassistant.config_entries", ConfigEntry=object)
    module(
        "homeassistant.const",
        Platform=types.SimpleNamespace(
            BINARY_SENSOR="binary_sensor",
            BUTTON="button",
            CAMERA="camera",
            IMAGE="image",
            EVENT="event",
            SENSOR="sensor",
            SWITCH="switch",
        ),
    )
    module(
        "homeassistant.core",
        HomeAssistant=object,
        ServiceCall=object,
        callback=lambda func: func,
    )

    class _HomeAssistantError(Exception):
        pass

    module("homeassistant.exceptions", HomeAssistantError=_HomeAssistantError)
    module("homeassistant.helpers.event", async_track_time_interval=lambda *_a, **_k: None)
    module("homeassistant.helpers.selector", MediaSelector=object)
    module("homeassistant.helpers.start", async_at_start=lambda *_a, **_k: None)
    module(
        "homeassistant.helpers.dispatcher",
        async_dispatcher_send=lambda *_a, **_k: None,
    )
    module("voluptuous")


def _load_capture_module() -> types.ModuleType:
    _install_capture_homeassistant_stubs()

    package = types.ModuleType(_INIT_PACKAGE)
    package.__path__ = [str(_PKG_DIR)]
    sys.modules[_INIT_PACKAGE] = package

    # Real, pure-Python siblings: reuse the exact modules already loaded
    # above so RingClipWriter/RingClipResult stay the same classes.
    sys.modules[f"{_INIT_PACKAGE}.const"] = _load("const")
    sys.modules[f"{_INIT_PACKAGE}.redaction"] = _load("redaction")
    sys.modules[f"{_INIT_PACKAGE}.text"] = _load("text")
    sys.modules[f"{_INIT_PACKAGE}.ring_clip"] = ring_clip

    def fake(name: str, **attributes: object) -> None:
        mod = types.ModuleType(f"{_INIT_PACKAGE}.{name}")
        mod.__dict__.update(attributes)
        sys.modules[mod.__name__] = mod

    # Siblings only ever touched by setup/service-registration code paths
    # _capture_ring_clip itself never runs (async_setup_entry, the SIP
    # listener, the other services) — bare placeholders are enough.
    fake("coordinator", ABBWelcomeCoordinator=object)
    fake("rtsp_proxy", RtspTcpProxy=object)
    fake("sip_client", SIPClient=object)
    fake("sip_listener", IncomingCall=object, SipListener=object)
    fake(
        "streaming_state",
        ARM_REASON_MANUAL="manual",
        ARM_REASON_RING="ring",
        MANUAL_ARM_SECONDS=60,
        RING_ARM_SECONDS=60,
        arm=lambda *_a, **_k: None,
        disarm=lambda *_a, **_k: None,
        is_pickup_allowed=lambda *_a, **_k: True,
        set_pickup_allowed=lambda *_a, **_k: None,
    )
    fake("talkback_audio", async_prepare_talkback_audio=lambda *_a, **_k: None)
    # _capture_ring_clip's only use of camera.py is this lazily-imported
    # key helper; the real one is heavier (go2rtc/WebRTC-dependent).
    fake("camera", _safe_key=lambda station_id: station_id)

    full_name = f"{_INIT_PACKAGE}.integration"
    # submodule_search_locations=None forces this to load as a regular
    # submodule of _INIT_PACKAGE rather than as a nested package: without
    # it, importlib.util treats the file as a package purely because it
    # is literally named __init__.py, and every `from .sibling import X`
    # below resolves one level too deep (abb_welcome_capture_test.
    # integration.sibling instead of abb_welcome_capture_test.sibling).
    spec = importlib.util.spec_from_file_location(
        full_name, _PKG_DIR / "__init__.py", submodule_search_locations=None
    )
    assert spec is not None and spec.loader is not None
    module_obj = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module_obj
    spec.loader.exec_module(module_obj)
    return module_obj


capture = _load_capture_module()
_CaptureHomeAssistantError = sys.modules["homeassistant.exceptions"].HomeAssistantError


class _FakeConfigEntry:
    def __init__(self, *, entry_id: str = "entry1", options: dict | None = None) -> None:
        self.entry_id = entry_id
        self.options = options or {}


class _EventBus:
    def __init__(self) -> None:
        self.fired: list[tuple[str, dict]] = []

    def async_fire(self, event_type: str, event_data: dict) -> None:
        self.fired.append((event_type, event_data))


class _CaptureConfig:
    def __init__(self, config_dir: Path) -> None:
        self._config_dir = config_dir

    def path(self, *parts: str) -> str:
        return str(Path(self._config_dir, *parts))

    def is_allowed_path(self, _path: str) -> bool:
        return True


class _CaptureHass:
    def __init__(self, entry_data: dict, *, config_dir: Path) -> None:
        self.data = {capture.DOMAIN: {"entry1": entry_data}}
        self.config = _CaptureConfig(config_dir)
        self.bus = _EventBus()
        self.ffmpeg = types.SimpleNamespace(binary="/configured/ffmpeg")

    async def async_add_executor_job(self, func, *args):
        return func(*args)


class _FakeStationCoordinator:
    """Stand-in for camera.StationStreamCoordinator: drives one packet sink."""

    def __init__(
        self,
        *,
        packets: list[bytes] | None = None,
        open_error: Exception | None = None,
    ) -> None:
        self._packets = packets or []
        self._open_error = open_error
        self._sink = None
        self._call_ended_callbacks: list = []
        self.opened = False

    def add_packet_sink(self, sink: object) -> None:
        self._sink = sink

    def remove_packet_sink(self, sink: object) -> None:
        if self._sink is sink:
            self._sink = None

    def add_call_ended_callback(self, callback: object) -> None:
        self._call_ended_callbacks.append(callback)

    def remove_call_ended_callback(self, callback: object) -> None:
        if callback in self._call_ended_callbacks:
            self._call_ended_callbacks.remove(callback)

    async def async_open_for_ring(self) -> None:
        self.opened = True
        if self._sink is not None:
            for packet in self._packets:
                self._sink.on_video(packet)
        if self._open_error is not None:
            raise self._open_error
        for call_ended_callback in list(self._call_ended_callbacks):
            call_ended_callback("call-id", "bye")


def _patch_ffmpeg_success(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _FakeProcess(returncode=0)

    async def _spawn(*args, **_kwargs):
        Path(args[-1]).write_bytes(b"fake-mp4-bytes")
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)


def _entry_data(coordinator: _FakeStationCoordinator, station_id: str) -> dict:
    return {"stream_coordinators": {(station_id, 0): coordinator}}


def test_capture_ring_clip_happy_path_fires_event_and_clears_in_flight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_ffmpeg_success(monkeypatch)
    coordinator = _FakeStationCoordinator(packets=[_rtp(1, b"\x65IDR")])
    entry_data = _entry_data(coordinator, "station1")
    hass = _CaptureHass(entry_data, config_dir=tmp_path / "config")
    entry = _FakeConfigEntry(
        options={capture.CONF_RING_CLIP_DIR: str(tmp_path / "clips")}
    )

    asyncio.run(capture._capture_ring_clip(hass, entry, "station1"))

    assert coordinator.opened is True
    assert len(hass.bus.fired) == 1
    event_type, payload = hass.bus.fired[0]
    assert event_type == capture.EVENT_RING_CLIP
    assert payload["ok"] is True
    assert payload["frames"] == 1
    # The in-flight marker must not outlive a completed capture.
    assert entry_data["ring_clip_in_flight_stations"] == set()


def test_capture_ring_clip_fires_event_even_when_body_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DEFECT 2: an unexpected exception must not swallow the clip.

    Video already captured before the exception (here, during the same
    async_open_for_ring call that then raises) must still be finalized
    and reported — silence is worse than a reported failure.
    """
    _patch_ffmpeg_success(monkeypatch)
    coordinator = _FakeStationCoordinator(
        packets=[_rtp(1, b"\x65IDR")],
        open_error=RuntimeError("SIP dial blew up"),
    )
    entry_data = _entry_data(coordinator, "station1")
    hass = _CaptureHass(entry_data, config_dir=tmp_path / "config")
    entry = _FakeConfigEntry(
        options={capture.CONF_RING_CLIP_DIR: str(tmp_path / "clips")}
    )

    # Must not raise: the exception is logged, not propagated.
    asyncio.run(capture._capture_ring_clip(hass, entry, "station1"))

    assert len(hass.bus.fired) == 1
    event_type, payload = hass.bus.fired[0]
    assert event_type == capture.EVENT_RING_CLIP
    # The IDR captured before the raise still made it into the clip.
    assert payload["ok"] is True
    assert payload["frames"] == 1
    assert entry_data["ring_clip_in_flight_stations"] == set()


def test_capture_ring_clip_reports_no_video_when_body_raises_immediately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same as above but zero video precedes the raise: event still fires."""
    _patch_ffmpeg_success(monkeypatch)
    coordinator = _FakeStationCoordinator(open_error=RuntimeError("no answer"))
    entry_data = _entry_data(coordinator, "station1")
    hass = _CaptureHass(entry_data, config_dir=tmp_path / "config")
    entry = _FakeConfigEntry(
        options={capture.CONF_RING_CLIP_DIR: str(tmp_path / "clips")}
    )

    asyncio.run(capture._capture_ring_clip(hass, entry, "station1"))

    assert len(hass.bus.fired) == 1
    event_type, payload = hass.bus.fired[0]
    assert event_type == capture.EVENT_RING_CLIP
    assert payload["ok"] is False
    assert entry_data["ring_clip_in_flight_stations"] == set()


def test_capture_ring_clip_ring_reason_skips_when_station_already_capturing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DEFECT 4: a second _on_ring for the same station must not race it."""
    _patch_ffmpeg_success(monkeypatch)
    coordinator = _FakeStationCoordinator(packets=[_rtp(1, b"\x65IDR")])
    entry_data = _entry_data(coordinator, "station1")
    entry_data["ring_clip_in_flight_stations"] = {"station1"}
    hass = _CaptureHass(entry_data, config_dir=tmp_path / "config")
    entry = _FakeConfigEntry(
        options={capture.CONF_RING_CLIP_DIR: str(tmp_path / "clips")}
    )

    asyncio.run(capture._capture_ring_clip(hass, entry, "station1", reason="ring"))

    # Skipped entirely: no second capture, no event, marker left as-is
    # for whichever capture actually owns it.
    assert coordinator.opened is False
    assert hass.bus.fired == []
    assert entry_data["ring_clip_in_flight_stations"] == {"station1"}


def test_capture_ring_clip_service_reason_raises_when_station_already_capturing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DEFECT 4: the record_clip service must not silently corrupt a run."""
    _patch_ffmpeg_success(monkeypatch)
    coordinator = _FakeStationCoordinator(packets=[_rtp(1, b"\x65IDR")])
    entry_data = _entry_data(coordinator, "station1")
    entry_data["ring_clip_in_flight_stations"] = {"station1"}
    hass = _CaptureHass(entry_data, config_dir=tmp_path / "config")
    entry = _FakeConfigEntry(
        options={capture.CONF_RING_CLIP_DIR: str(tmp_path / "clips")}
    )

    with pytest.raises(_CaptureHomeAssistantError):
        asyncio.run(
            capture._capture_ring_clip(hass, entry, "station1", reason="service")
        )

    assert coordinator.opened is False
    assert hass.bus.fired == []
    assert entry_data["ring_clip_in_flight_stations"] == {"station1"}


def test_capture_ring_clip_service_reason_allowed_for_a_different_station(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard is per-station: a busy station must not block another."""
    _patch_ffmpeg_success(monkeypatch)
    busy_coordinator = _FakeStationCoordinator(packets=[_rtp(1, b"\x65IDR")])
    free_coordinator = _FakeStationCoordinator(packets=[_rtp(1, b"\x65IDR")])
    entry_data = {
        "stream_coordinators": {
            ("station1", 0): busy_coordinator,
            ("station2", 0): free_coordinator,
        },
        "ring_clip_in_flight_stations": {"station1"},
    }
    hass = _CaptureHass(entry_data, config_dir=tmp_path / "config")
    entry = _FakeConfigEntry(
        options={capture.CONF_RING_CLIP_DIR: str(tmp_path / "clips")}
    )

    asyncio.run(
        capture._capture_ring_clip(hass, entry, "station2", reason="service")
    )

    assert free_coordinator.opened is True
    assert len(hass.bus.fired) == 1
    assert hass.bus.fired[0][1]["ok"] is True
    # The other station's marker is untouched by station2's capture.
    assert entry_data["ring_clip_in_flight_stations"] == {"station1"}
