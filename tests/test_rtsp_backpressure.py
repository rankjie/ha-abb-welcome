"""Behavior tests for the RTSP interleaved-write backpressure valve.

``RtspSession.push_rtp`` must shed packets once the transport write buffer is
backed up past the cap, so a stalled go2rtc/ffmpeg consumer cannot grow the
buffer without bound — while still writing normally on a healthy connection.
"""

from __future__ import annotations

import importlib.util
import struct
import sys
import types
from pathlib import Path

_PKG_DIR = (
    Path(__file__).resolve().parent.parent
    / "custom_components" / "abb_welcome"
)

pkg = types.ModuleType("abb_welcome")
pkg.__path__ = [str(_PKG_DIR)]
sys.modules.setdefault("abb_welcome", pkg)
_spec = importlib.util.spec_from_file_location(
    "abb_welcome.rtsp_server", _PKG_DIR / "rtsp_server.py"
)
rtsp_server = importlib.util.module_from_spec(_spec)
# Register before exec so dataclass annotation resolution can find the module.
sys.modules["abb_welcome.rtsp_server"] = rtsp_server
_spec.loader.exec_module(rtsp_server)


class _FakeTransport:
    def __init__(self, buffered: int) -> None:
        self._buffered = buffered

    def get_write_buffer_size(self) -> int:
        return self._buffered


class _FakeWriter:
    def __init__(self, buffered: int = 0, closing: bool = False) -> None:
        self.transport = _FakeTransport(buffered)
        self._closing = closing
        self.written: list[bytes] = []

    def is_closing(self) -> bool:
        return self._closing

    def write(self, data: bytes) -> None:
        self.written.append(data)


def _session(writer: _FakeWriter) -> "rtsp_server.RtspSession":
    return rtsp_server.RtspSession(session_id="test", writer=writer, write_lock=object())


def test_healthy_connection_writes_framed_packet() -> None:
    writer = _FakeWriter(buffered=0)
    sess = _session(writer)
    payload = b"\xde\xad\xbe\xef"
    assert sess.push_rtp(rtsp_server.VIDEO_RTP_CHANNEL, payload) is True
    assert len(writer.written) == 1
    framed = writer.written[0]
    # $ <channel> <BE16 length> <payload>
    marker, channel, length = struct.unpack("!cBH", framed[:4])
    assert marker == b"$"
    assert channel == rtsp_server.VIDEO_RTP_CHANNEL
    assert length == len(payload)
    assert framed[4:] == payload
    assert sess.overflow_drops == 0


def test_backpressure_drops_without_writing() -> None:
    writer = _FakeWriter(buffered=rtsp_server._MAX_WRITE_BUFFER_BYTES + 1)
    sess = _session(writer)
    # Many packets while the consumer is stalled: all dropped, none buffered.
    for _ in range(500):
        assert sess.push_rtp(rtsp_server.AUDIO_RTP_CHANNEL, b"\x01\x02") is True
    assert writer.written == []
    assert sess.overflow_drops == 500


def test_recovers_after_consumer_drains() -> None:
    writer = _FakeWriter(buffered=rtsp_server._MAX_WRITE_BUFFER_BYTES + 1)
    sess = _session(writer)
    sess.push_rtp(rtsp_server.VIDEO_RTP_CHANNEL, b"\x00")
    assert sess.overflow_drops == 1
    # Consumer catches up -> buffer drops back to healthy -> writes resume.
    writer.transport._buffered = 0
    assert sess.push_rtp(rtsp_server.VIDEO_RTP_CHANNEL, b"\x00") is True
    assert len(writer.written) == 1


def test_closing_and_oversized_packets_rejected() -> None:
    closing = _session(_FakeWriter(closing=True))
    assert closing.push_rtp(rtsp_server.VIDEO_RTP_CHANNEL, b"x") is False

    big = _session(_FakeWriter())
    assert big.push_rtp(rtsp_server.VIDEO_RTP_CHANNEL, b"x" * (0xFFFF + 1)) is False


if __name__ == "__main__":
    test_healthy_connection_writes_framed_packet()
    test_backpressure_drops_without_writing()
    test_recovers_after_consumer_drains()
    test_closing_and_oversized_packets_rejected()
    print(f"OK  cap={rtsp_server._MAX_WRITE_BUFFER_BYTES} bytes")
