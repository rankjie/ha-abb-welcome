"""Pure tests for safe video negotiation and RFC 6184 diagnostics."""

from __future__ import annotations

import importlib.util
import struct
import sys
import types
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


def _load_media_pipeline() -> types.ModuleType:
    """Load the media helpers without importing Home Assistant."""
    pkg = types.ModuleType("abb_welcome")
    pkg.__path__ = [str(_PKG_DIR)]
    sys.modules.setdefault("abb_welcome", pkg)

    for name in ("intercom_dialer", "media_pipeline"):
        full = f"abb_welcome.{name}"
        if full in sys.modules:
            continue
        spec = importlib.util.spec_from_file_location(full, _PKG_DIR / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[full] = module
        spec.loader.exec_module(module)
    return sys.modules["abb_welcome.media_pipeline"]


mp = _load_media_pipeline()


def _rtp(payload: bytes) -> bytes:
    return struct.pack("!BBHII", 0x80, 102, 1, 9000, 1234) + payload


def _rtp_with_csrc_extension_and_padding(payload: bytes) -> bytes:
    """Build RTP that exercises every variable-length header component."""
    header = struct.pack("!BBHII", 0xB1, 102, 1, 9000, 1234)
    csrc = struct.pack("!I", 5678)
    extension = struct.pack("!HHI", 0xBEDE, 1, 0x11223344)
    padding = b"\x00\x00\x00\x04"
    return header + csrc + extension + payload + padding


def _stap_a(*members: bytes) -> bytes:
    return bytes((0x78,)) + b"".join(
        struct.pack("!H", len(member)) + member for member in members
    )


def test_video_format_uses_h264_payload_type_when_not_first() -> None:
    selected = mp._select_video_format(
        [96, 102],
        {96: "JPEG/90000", 102: "H264/90000"},
        {96: "jpeg-only", 102: "profile-level-id=42e01f;sprop-parameter-sets=x,y"},
    )

    assert selected is not None
    assert selected.payload_type == 102
    assert selected.codec == "H264/90000"
    assert selected.fmtp == "profile-level-id=42e01f;sprop-parameter-sets=x,y"
    assert selected.is_h264 is True
    assert selected.has_sprop_parameter_sets is True


def test_video_format_falls_back_to_first_payload_type() -> None:
    selected = mp._select_video_format(
        [97, 98],
        {97: "VP8/90000", 98: "JPEG/90000"},
        {97: "fallback-metadata"},
    )

    assert selected is not None
    assert selected.payload_type == 97
    assert selected.codec == "VP8/90000"
    assert selected.fmtp == "fallback-metadata"
    assert selected.is_h264 is False
    assert mp._select_video_format([], {}, {}) is None


def test_h264_parser_recognizes_single_stap_a_and_fu_a_metadata() -> None:
    assert mp._h264_nal_metadata(_rtp(b"\x67\x01")).nal_types == (7,)

    stap = mp._h264_nal_metadata(_rtp(_stap_a(b"\x67\x01", b"\x68\x02", b"\x65\x03")))
    assert stap.valid is True
    assert stap.packetization_type == 24
    assert stap.nal_types == (7, 8, 5)

    fu_start = mp._h264_nal_metadata(_rtp(b"\x7c\x85\x01"))
    fu_member = mp._h264_nal_metadata(_rtp(b"\x7c\x05\x02"))
    assert (fu_start.packetization_type, fu_start.nal_types, fu_start.fu_start) == (
        28,
        (5,),
        True,
    )
    assert (fu_member.packetization_type, fu_member.nal_types, fu_member.fu_start) == (
        28,
        (5,),
        False,
    )


def test_h264_parser_honors_csrc_extension_and_padding() -> None:
    metadata = mp._h264_nal_metadata(
        _rtp_with_csrc_extension_and_padding(_stap_a(b"\x67\x01", b"\x68\x02"))
    )

    assert metadata.valid is True
    assert metadata.packetization_type == 24
    assert metadata.nal_types == (7, 8)


def test_h264_counters_cover_nal_types_and_malformed_packets() -> None:
    counters = mp._H264NalCounters()
    packets = (
        _rtp(b"\x67\x01"),
        _rtp(b"\x68\x02"),
        _rtp(b"\x65\x03"),
        _rtp(b"\x61\x04"),
        _rtp(_stap_a(b"\x67", b"\x68", b"\x65")),
        _rtp(b"\x7c\x85\x01"),
        _rtp(b"\x7c\x05\x02"),
        _rtp(b"\x79\x00"),
        _rtp(b"\x78\x00\x04\x67"),
    )
    for packet in packets:
        counters.observe(packet)

    assert counters.sps == 2
    assert counters.pps == 2
    assert counters.idr == 4
    assert counters.stap_a == 1
    assert counters.fu_a == 2
    assert counters.fu_a_starts == 1
    assert counters.other == 2
    assert counters.invalid == 1
    assert all(
        not isinstance(value, bytes | bytearray) for value in vars(counters).values()
    )


def test_h264_parser_rejects_missing_or_malformed_metadata() -> None:
    malformed = (
        b"too short",
        _rtp(b""),
        _rtp(b"\x78"),
        _rtp(b"\x7c"),
        _rtp(b"\x7c\x20"),
    )

    assert all(not mp._h264_nal_metadata(packet).valid for packet in malformed)


def test_h264_other_counter_preserves_aggregate_and_splits_known_types() -> None:
    counters = mp._H264NalCounters()

    for nal_type in (1, 2, 3, 4, 6, 9, 25, 26, 27, 29):
        counters.observe(_rtp(bytes((0x60 | nal_type, 0x00))))

    assert counters.other == 10
    assert (
        counters.type_1,
        counters.type_2,
        counters.type_3,
        counters.type_4,
        counters.type_6,
        counters.type_9,
        counters.type_25,
        counters.type_26,
        counters.type_27,
        counters.type_29,
    ) == (1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
