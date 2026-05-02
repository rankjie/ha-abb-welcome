"""On-demand RTP receiver + RTSP publisher for ABB streaming.

The integration's job:

* SIP-dial the outdoor station when a downstream WebRTC consumer asks
  for the stream
* receive the gateway's RTP/AVP (H.264 video + PCMA audio) on UDP
* push each packet onto an RTSP control connection to HA's bundled
  go2rtc — TCP-interleaved, so video/audio framing is preserved and
  there's no extra muxing latency or "green frame" recovery problem

Closing the pipeline tears everything down: cancel keepalives, BYE
the SIP call, TEARDOWN the RTSP session.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from collections.abc import Callable
from dataclasses import dataclass

from .intercom_dialer import CallState, Door, IntercomDialer

_LOGGER = logging.getLogger(__name__)

_KEEPALIVE_INTERVAL = 1.0
_RTCP_INTERVAL = 5.0


def _build_rtp_keepalive(seq: int) -> bytes:
    return struct.pack("!BBHII", 0x80, 0, seq & 0xFFFF, 0, 0xCAFEBABE)


def _build_rtcp_pli(reporter: int, media: int) -> bytes:
    return struct.pack("!BBHII", 0x81, 206, 2, reporter, media)


def _build_rtcp_rr(reporter: int, source: int, last_seq: int) -> bytes:
    return struct.pack(
        "!BBH IIIIIII",
        0x81, 201, 7,
        reporter & 0xFFFFFFFF,
        source & 0xFFFFFFFF,
        0,
        last_seq & 0xFFFFFFFF,
        0, 0, 0,
    )


def best_local_ip_for(host: str) -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((host, 9))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def _alloc_udp(bind_ip: str) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind_ip, 0))
    s.setblocking(False)
    return s


class _RTPProtocol(asyncio.DatagramProtocol):
    """Receive gateway RTP, optionally rewrite PT, hand off to publisher.

    PT rewriting matters because the ABB gateway negotiates one PT in
    SDP but emits a different PT on the wire.  When we ANNOUNCE our
    SDP to go2rtc we pick a single PT; rewriting incoming packets to
    match keeps go2rtc happy.
    """

    def __init__(
        self,
        on_packet: Callable[[bytes], None],
        rewrite_pt: int | None,
        on_first_packet: Callable[[bytes], None] | None,
        label: str = "rtp",
    ) -> None:
        self._on_packet = on_packet
        self._rewrite_pt = rewrite_pt
        self._on_first_packet = on_first_packet
        self.label = label
        self.transport: asyncio.DatagramTransport | None = None
        self.packets = 0
        self.bytes_received = 0
        self.last_seq = 0
        self.media_ssrc = 0
        self.payload_types: dict[int, int] = {}
        self._rewrites = 0

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.packets += 1
        self.bytes_received += len(data)
        if len(data) >= 12:
            pt = data[1] & 0x7F
            self.payload_types[pt] = self.payload_types.get(pt, 0) + 1
            self.last_seq = struct.unpack_from("!H", data, 2)[0]
            if self.media_ssrc == 0:
                self.media_ssrc = struct.unpack_from("!I", data, 8)[0]
            if self._rewrite_pt is not None and pt != self._rewrite_pt:
                marker = data[1] & 0x80
                data = (
                    bytes((data[0], marker | (self._rewrite_pt & 0x7F)))
                    + data[2:]
                )
                self._rewrites += 1
        if self.packets == 1 and self._on_first_packet is not None:
            try:
                self._on_first_packet(data)
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("on_first_packet handler raised: %s", err)
        try:
            self._on_packet(data)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("on_packet handler raised: %s", err)

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("RTP datagram error: %s", exc)


@dataclass
class _MediaEndpoints:
    audio: tuple[str, int] | None
    video: tuple[str, int] | None


class StreamSession:
    """One SIP call + RTP receivers + RTSP publisher to go2rtc.

    Responsibilities:

    * dial the gateway, advertise our UDP ports
    * receive video/audio RTP on those ports
    * forward each packet over an RTSP/TCP-interleaved connection to
      go2rtc (which then serves it as ``rtsp://...`` to its consumers
      and via its WebRTC pipeline to the browser)
    """

    VIDEO_SDP_PT = 96
    AUDIO_SDP_PT = 8  # PCMA static PT — no rewrite needed.

    def __init__(
        self,
        *,
        dialer: IntercomDialer,
        door: Door,
        gateway_host: str,
        on_video_packet: Callable[[bytes], None] | None = None,
        on_audio_packet: Callable[[bytes], None] | None = None,
    ) -> None:
        self._dialer = dialer
        self._door = door
        self._gateway_host = gateway_host
        self._on_video_packet = on_video_packet
        self._on_audio_packet = on_audio_packet

        self._media_ip = ""
        self._video_sock: socket.socket | None = None
        self._audio_sock: socket.socket | None = None
        self._video_proto: _RTPProtocol | None = None
        self._audio_proto: _RTPProtocol | None = None
        self._video_transport: asyncio.DatagramTransport | None = None
        self._audio_transport: asyncio.DatagramTransport | None = None
        self._call: CallState | None = None
        self._endpoints = _MediaEndpoints(None, None)
        self._video_codec = "H264/90000"
        self._video_fmtp: str | None = None

        self._stop = asyncio.Event()
        self._keepalive_task: asyncio.Task | None = None
        self._rtcp_task: asyncio.Task | None = None
        self._stats_task: asyncio.Task | None = None

    @property
    def active(self) -> bool:
        return self._call is not None

    @property
    def video_codec(self) -> str:
        return self._video_codec

    @property
    def video_fmtp(self) -> str | None:
        return self._video_fmtp

    def set_packet_handlers(
        self,
        on_video: Callable[[bytes], None] | None,
        on_audio: Callable[[bytes], None] | None,
    ) -> None:
        """Replace the per-packet RTP handlers (used by the RTSP server)."""
        self._on_video_packet = on_video
        self._on_audio_packet = on_audio

    async def open(self) -> None:
        """Dial gateway and start receiving RTP."""
        loop = asyncio.get_running_loop()

        self._media_ip = best_local_ip_for(self._gateway_host)
        self._video_sock = _alloc_udp(self._media_ip)
        self._audio_sock = _alloc_udp(self._media_ip)
        offer_audio_port = self._audio_sock.getsockname()[1]
        offer_video_port = self._video_sock.getsockname()[1]

        _LOGGER.info(
            "[abb] media: dialing gateway for door=%s media_ip=%s "
            "audio_port=%d video_port=%d",
            self._door.name, self._media_ip,
            offer_audio_port, offer_video_port,
        )

        call = await self._dialer.dial(
            self._door,
            audio_port=offer_audio_port,
            video_port=offer_video_port,
        )
        self._call = call

        for m in call.answer.medias:
            if m.media == "audio" and m.connection_ip and m.port:
                self._endpoints = _MediaEndpoints(
                    audio=(m.connection_ip, m.port),
                    video=self._endpoints.video,
                )
            elif m.media == "video" and m.connection_ip and m.port:
                self._endpoints = _MediaEndpoints(
                    audio=self._endpoints.audio,
                    video=(m.connection_ip, m.port),
                )
                if m.payload_types:
                    pt = m.payload_types[0]
                    self._video_codec = m.rtpmap.get(pt, self._video_codec)
                    self._video_fmtp = m.fmtp.get(pt)

        def _video_first(data: bytes) -> None:
            _LOGGER.info(
                "[abb] media: first video RTP packet for %s (%d bytes)",
                self._door.name, len(data),
            )
            if self._endpoints.video and self._video_transport:
                ssrc = (
                    struct.unpack_from("!I", data, 8)[0]
                    if len(data) >= 12 else 0
                )
                try:
                    self._video_transport.sendto(
                        _build_rtcp_pli(0xCAFEBABE, ssrc),
                        self._endpoints.video,
                    )
                except OSError:
                    pass

        def _on_video(packet: bytes) -> None:
            cb = self._on_video_packet
            if cb is not None:
                cb(packet)

        def _on_audio(packet: bytes) -> None:
            cb = self._on_audio_packet
            if cb is not None:
                cb(packet)

        self._video_proto = _RTPProtocol(
            on_packet=_on_video,
            rewrite_pt=self.VIDEO_SDP_PT,
            on_first_packet=_video_first,
            label="video",
        )
        self._video_transport, _ = await loop.create_datagram_endpoint(
            lambda: self._video_proto, sock=self._video_sock
        )

        self._audio_proto = _RTPProtocol(
            on_packet=_on_audio,
            rewrite_pt=None,
            on_first_packet=None,
            label="audio",
        )
        self._audio_transport, _ = await loop.create_datagram_endpoint(
            lambda: self._audio_proto, sock=self._audio_sock
        )

        if self._endpoints.audio:
            await self._punch(self._audio_transport, self._endpoints.audio)
        if self._endpoints.video:
            await self._punch(self._video_transport, self._endpoints.video)

        self._stop.clear()
        self._keepalive_task = asyncio.create_task(
            self._keepalive_loop(),
            name=f"abb_keepalive_{self._door.station_id}",
        )
        self._rtcp_task = asyncio.create_task(
            self._rtcp_loop(),
            name=f"abb_rtcp_{self._door.station_id}",
        )
        self._stats_task = asyncio.create_task(
            self._stats_loop(),
            name=f"abb_stats_{self._door.station_id}",
        )

    async def close(self) -> None:
        _LOGGER.info(
            "[abb] media: closing stream for %s "
            "(video_pkts=%d audio_pkts=%d rewrites=%d)",
            self._door.name,
            self._video_proto.packets if self._video_proto else 0,
            self._audio_proto.packets if self._audio_proto else 0,
            self._video_proto._rewrites if self._video_proto else 0,
        )
        self._stop.set()
        for t in (self._keepalive_task, self._rtcp_task, self._stats_task):
            if t is not None:
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
        self._keepalive_task = self._rtcp_task = self._stats_task = None

        for tr in (self._video_transport, self._audio_transport):
            if tr is not None:
                tr.close()
        self._video_transport = self._audio_transport = None
        self._video_sock = self._audio_sock = None
        self._video_proto = self._audio_proto = None

        if self._call is not None:
            try:
                await self._dialer.hangup()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("[abb] media: hangup failed: %s", err)
            self._call = None

        self._endpoints = _MediaEndpoints(None, None)

    async def _punch(
        self, transport: asyncio.DatagramTransport, dest: tuple[str, int]
    ) -> None:
        for i in range(6):
            try:
                transport.sendto(_build_rtp_keepalive(i), dest)
            except OSError:
                break

    async def _keepalive_loop(self) -> None:
        seq = 6
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=_KEEPALIVE_INTERVAL)
                return
            except asyncio.TimeoutError:
                pass
            for transport, dest in (
                (self._audio_transport, self._endpoints.audio),
                (self._video_transport, self._endpoints.video),
            ):
                if transport is None or dest is None:
                    continue
                try:
                    transport.sendto(_build_rtp_keepalive(seq), dest)
                except OSError:
                    pass
                seq = (seq + 1) & 0xFFFF

    async def _rtcp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=_RTCP_INTERVAL)
                return
            except asyncio.TimeoutError:
                pass
            vp = self._video_proto
            if (
                vp is None
                or self._video_transport is None
                or self._endpoints.video is None
                or vp.media_ssrc == 0
            ):
                continue
            try:
                self._video_transport.sendto(
                    _build_rtcp_rr(0xCAFEBABE, vp.media_ssrc, vp.last_seq),
                    self._endpoints.video,
                )
            except OSError:
                pass

    async def _stats_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=10.0)
                return
            except asyncio.TimeoutError:
                pass
            vp = self._video_proto
            ap = self._audio_proto
            _LOGGER.info(
                "[abb] media stats %s: video pkts=%d pts=%s rewrites=%d "
                "audio pkts=%d",
                self._door.name,
                vp.packets if vp else 0,
                dict(vp.payload_types) if vp else {},
                vp._rewrites if vp else 0,
                ap.packets if ap else 0,
            )
