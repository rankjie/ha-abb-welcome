"""Pure and loopback tests for RTP/RTCP negotiation and routing."""

from __future__ import annotations

import importlib.util
import socket
import sys
import types
from pathlib import Path
from typing import ClassVar

import pytest

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


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


intercom = _load("intercom_dialer")
media = _load("media_pipeline")
sip_listener = _load("sip_listener")


def test_parse_sdp_rtcp_attributes() -> None:
    parsed = intercom.parse_sdp(
        "v=0\r\n"
        "c=IN IP4 192.0.2.10\r\n"
        "m=video 5004 RTP/AVPF 102\r\n"
        "a=rtpmap:102 H264/90000\r\n"
        "a=rtcp:6000 IN IP4 192.0.2.11\r\n"
        "m=audio 5006 RTP/AVP 8\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        "a=rtcp-mux\r\n"
    )

    video, audio = parsed.medias
    assert (video.rtcp_port, video.rtcp_ip, video.rtcp_mux) == (
        6000,
        "192.0.2.11",
        False,
    )
    assert (audio.rtcp_port, audio.rtcp_ip, audio.rtcp_mux) == (None, "", True)


def test_parse_sdp_ignores_invalid_rtcp_port() -> None:
    media_desc = intercom.parse_sdp(
        "c=IN IP4 192.0.2.10\r\nm=video 5004 RTP/AVP 102\r\na=rtcp:0\r\n"
    ).medias[0]

    assert media_desc.rtcp_port is None
    assert media_desc.rtcp_ip == ""


def test_remote_rtcp_endpoint_resolution() -> None:
    explicit = intercom.MediaDescription(
        media="video",
        port=5004,
        proto="RTP/AVPF",
        connection_ip="192.0.2.10",
        rtcp_port=6000,
        rtcp_ip="192.0.2.11",
    )
    implicit = intercom.MediaDescription(
        media="video",
        port=5004,
        proto="RTP/AVPF",
        connection_ip="192.0.2.10",
    )
    muxed = intercom.MediaDescription(
        media="video",
        port=5004,
        proto="RTP/AVPF",
        connection_ip="192.0.2.10",
        rtcp_port=6000,
        rtcp_ip="192.0.2.11",
        rtcp_mux=True,
    )

    assert media._remote_media_endpoints(explicit) == media._RemoteMediaEndpoints(
        ("192.0.2.10", 5004),
        ("192.0.2.11", 6000),
        False,
        True,
    )
    assert media._remote_media_endpoints(implicit) == media._RemoteMediaEndpoints(
        ("192.0.2.10", 5004),
        ("192.0.2.10", 5005),
        False,
        False,
    )
    assert media._remote_media_endpoints(muxed) == media._RemoteMediaEndpoints(
        ("192.0.2.10", 5004),
        ("192.0.2.10", 5004),
        True,
        True,
    )


def test_rtcp_mux_selects_rtp_transport() -> None:
    rtp_transport = object()
    rtcp_transport = object()

    assert (
        media._select_rtcp_transport(True, rtp_transport, rtcp_transport)
        is rtp_transport
    )
    assert (
        media._select_rtcp_transport(False, rtp_transport, rtcp_transport)
        is rtcp_transport
    )


def test_pli_decision_stops_only_after_sps_pps_and_idr() -> None:
    counters = media._H264NalCounters()
    assert media._should_request_h264_keyframe(None) is True
    assert media._should_request_h264_keyframe(counters) is True
    counters.sps = 1
    counters.pps = 1
    assert media._should_request_h264_keyframe(counters) is True
    counters.idr = 1
    assert media._should_request_h264_keyframe(counters) is False


def test_fir_packet_matches_rfc_5104_layout() -> None:
    assert media._build_rtcp_fir(0xCAFEBABE, 0x11223344, 0x7F) == (
        b"\x84\xce\x00\x04"
        b"\xca\xfe\xba\xbe"
        b"\x00\x00\x00\x00"
        b"\x11\x22\x33\x44"
        b"\x7f\x00\x00\x00"
    )


class _FakeTransport:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, packet: bytes, destination: tuple[str, int]) -> None:
        self.sent.append((packet, destination))


def test_pli_is_rate_limited_and_uses_negotiated_rtcp_route() -> None:
    session = media.StreamSession(
        dialer=object(),
        door=intercom.Door("door", "address"),
        gateway_host="192.0.2.10",
    )
    session._video_proto = media._RTPProtocol(lambda _packet: None, None, None)
    session._video_proto.media_ssrc = 1234
    session._video_proto.h264_nals = media._H264NalCounters()
    session._endpoints = media._MediaEndpoints(
        None,
        media._RemoteMediaEndpoints(
            ("192.0.2.10", 5004),
            ("192.0.2.11", 6000),
            False,
            True,
        ),
    )
    rtp_transport = _FakeTransport()
    rtcp_transport = _FakeTransport()
    session._video_transport = rtp_transport
    session._video_rtcp_transport = rtcp_transport

    assert session._send_video_pli_if_due(10.0) is True
    assert session._send_video_pli_if_due(10.5) is False
    assert session._send_video_pli_if_due(11.0) is True
    assert len(rtp_transport.sent) == 0
    assert [destination for _packet, destination in rtcp_transport.sent] == [
        ("192.0.2.11", 6000),
        ("192.0.2.11", 6000),
        ("192.0.2.11", 6000),
        ("192.0.2.11", 6000),
    ]
    assert [packet[0] for packet, _destination in rtcp_transport.sent] == [
        0x81,
        0x84,
        0x81,
        0x84,
    ]
    assert [rtcp_transport.sent[index][0][16] for index in (1, 3)] == [0, 1]
    assert session._pli_requests_sent == 2
    assert session._fir_requests_sent == 2

    session._video_proto.h264_nals.sps = 1
    session._video_proto.h264_nals.pps = 1
    session._video_proto.h264_nals.idr = 1
    assert session._send_video_pli_if_due(12.0) is False

    session._video_proto.h264_nals = media._H264NalCounters()
    session._fir_sequence = 255
    assert session._send_video_pli_if_due(13.0) is True
    assert session._send_video_pli_if_due(14.0) is True
    assert [rtcp_transport.sent[index][0][16] for index in (5, 7)] == [255, 0]
    assert session._fir_sequence == 1


def test_muxed_feedback_uses_rtp_transport_and_muxed_rtcp_is_not_forwarded() -> None:
    forwarded: list[bytes] = []
    protocol = media._RTPProtocol(
        forwarded.append,
        None,
        None,
        drop_muxed_rtcp=True,
    )
    receiver_report = media._build_rtcp_rr(1, 2, 3)

    assert media._is_rtcp_packet(receiver_report) is True
    assert media._is_rtcp_packet(b"\x80\x66\x00\x01") is False
    protocol.datagram_received(receiver_report, ("192.0.2.10", 5004))
    assert protocol.rtcp_packets == 1
    assert protocol.packets == 0
    assert forwarded == []


class _FakeSocket:
    bound_ports: ClassVar[set[int]] = set()
    created: ClassVar[list[_FakeSocket]] = []
    ephemeral_port = 40001

    def __init__(self, family: int, kind: int) -> None:
        assert family == socket.AF_INET
        assert kind == socket.SOCK_DGRAM
        self.port = 0
        self.blocking = True
        self.closed = False
        self.created.append(self)

    def bind(self, address: tuple[str, int]) -> None:
        port = address[1] or self.ephemeral_port
        if port in self.bound_ports:
            raise OSError("occupied")
        self.bound_ports.add(port)
        self.port = port

    def getsockname(self) -> tuple[str, int]:
        return ("127.0.0.1", self.port)

    def setblocking(self, blocking: bool) -> None:
        self.blocking = blocking

    def getblocking(self) -> bool:
        return self.blocking

    def close(self) -> None:
        self.closed = True
        self.bound_ports.discard(self.port)


@pytest.mark.parametrize("ephemeral_port", (40000, 40001))
def test_udp_pair_owns_adjacent_even_and_odd_ports(
    monkeypatch: pytest.MonkeyPatch,
    ephemeral_port: int,
) -> None:
    _FakeSocket.bound_ports.clear()
    _FakeSocket.created.clear()
    monkeypatch.setattr(_FakeSocket, "ephemeral_port", ephemeral_port)
    monkeypatch.setattr(media.socket, "socket", _FakeSocket)

    rtp_sock, rtcp_sock = media._alloc_udp_pair("127.0.0.1")

    assert rtp_sock.getsockname()[1] == 40000
    assert rtcp_sock.getsockname()[1] == 40001
    assert rtp_sock.getblocking() is False
    assert rtcp_sock.getblocking() is False
    rtp_sock.close()
    rtcp_sock.close()


def test_udp_pair_retries_are_bounded_and_cleaned_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingPartnerSocket(_FakeSocket):
        created: ClassVar[list[FailingPartnerSocket]] = []

        def bind(self, address: tuple[str, int]) -> None:
            if address[1] != 0:
                raise OSError("partner unavailable")
            super().bind(address)

    _FakeSocket.bound_ports.clear()
    FailingPartnerSocket.created.clear()
    monkeypatch.setattr(media.socket, "socket", FailingPartnerSocket)

    with pytest.raises(OSError, match="adjacent UDP RTP/RTCP"):
        media._alloc_udp_pair("127.0.0.1", attempts=2)

    assert len(FailingPartnerSocket.created) == 4
    assert all(sock.closed for sock in FailingPartnerSocket.created)


def test_incoming_answer_echoes_rtcp_mux() -> None:
    offer = intercom.parse_sdp(
        "v=0\r\n"
        "c=IN IP4 192.0.2.10\r\n"
        "m=audio 5004 RTP/AVP 8\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        "a=rtcp-mux\r\n"
        "m=video 5006 RTP/AVPF 102\r\n"
        "a=rtpmap:102 H264/90000\r\n"
        "a=rtcp-mux\r\n"
    )

    answer = sip_listener._build_answer_sdp(
        offer,
        username="client",
        media_ip="192.0.2.20",
        audio_port=6000,
        video_port=6002,
    )

    assert answer.count("a=rtcp-mux") == 2
