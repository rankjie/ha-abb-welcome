"""Per-call media pipeline: RTP receiver + FFmpeg subprocess.

Wires up:
  - a UDP socket bound on the host's IP that receives RTP from the gateway
  - a forwarding loop that re-emits each datagram to a loopback port
  - an ``ffmpeg`` subprocess that reads RTP from the loopback port via an
    SDP file and outputs MPEG-TS on a localhost TCP listen socket

The TCP MPEG-TS endpoint is what HA's ``stream`` component consumes via
PyAV — works out of the box, no HLS coordination on our side.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import warnings
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

_KEEPALIVE_INTERVAL = 1.0   # seconds, RTP keepalive towards gateway
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
        0,
        0,
        0,
    )


def best_local_ip_for(host: str) -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((host, 9))
        return probe.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        probe.close()


def _alloc_udp(bind_ip: str) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind_ip, 0))
    s.setblocking(True)  # asyncio create_datagram_endpoint sets it non-blocking
    return s


def _alloc_tcp_loopback() -> tuple[socket.socket, int]:
    """Bind a TCP listen socket on 127.0.0.1, return (sock, port).

    FFmpeg can't ask us for the port — we have to pre-bind, take the port
    number, then *close* the socket and pass the same port to ffmpeg via
    the ``tcp://...?listen`` URL (ffmpeg will re-bind).  Tiny race window
    on the port between our close and ffmpeg's bind, but in practice fine
    for localhost.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return s, port


@dataclass
class PipelineHandle:
    """What's exposed to the caller after :func:`MediaPipeline.start`."""

    stream_url: str
    audio_socket: socket.socket
    video_socket: socket.socket
    media_ip: str
    audio_port: int
    video_port: int


class _RTPProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        forward_to: tuple[str, int] | None,
        on_first_packet: Callable[[bytes, tuple[str, int]], None] | None,
    ) -> None:
        self.forward_to = forward_to
        self.on_first_packet = on_first_packet
        self.transport: asyncio.DatagramTransport | None = None
        self.packets = 0
        self.last_seq = 0
        self.media_ssrc = 0

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.packets += 1
        if len(data) >= 12:
            self.last_seq = struct.unpack_from("!H", data, 2)[0]
            if self.media_ssrc == 0:
                self.media_ssrc = struct.unpack_from("!I", data, 8)[0]
        if self.packets == 1 and self.on_first_packet is not None:
            self.on_first_packet(data, addr)
        if self.forward_to is not None and self.transport is not None:
            try:
                self.transport.sendto(data, self.forward_to)
            except OSError as err:
                _LOGGER.debug("RTP forward sendto failed: %s", err)

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("RTP datagram error: %s", exc)


class MediaPipeline:
    """One-shot RTP-receive + FFmpeg-MPEG-TS-out pipeline for a single call."""

    def __init__(
        self,
        gateway_host: str,
        ffmpeg_binary: str = "ffmpeg",
    ) -> None:
        self.gateway_host = gateway_host
        self.ffmpeg_binary = ffmpeg_binary
        self._media_ip: str = ""
        self._video_sock: socket.socket | None = None
        self._audio_sock: socket.socket | None = None
        self._video_proto: _RTPProtocol | None = None
        self._audio_proto: _RTPProtocol | None = None
        self._video_transport: asyncio.DatagramTransport | None = None
        self._audio_transport: asyncio.DatagramTransport | None = None
        self._ffmpeg: asyncio.subprocess.Process | None = None
        self._stderr_task: asyncio.Task | None = None
        self._keepalive_task: asyncio.Task | None = None
        self._rtcp_task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._gw_audio: tuple[str, int] | None = None
        self._gw_video: tuple[str, int] | None = None
        self._sdp_path: Path | None = None
        self._tcp_port: int = 0

    async def setup(self) -> tuple[socket.socket, socket.socket]:
        """Allocate the UDP receive sockets and pick a media IP.

        Call before issuing the SIP INVITE — the caller passes the bound
        ports into the SDP offer.
        """
        self._media_ip = best_local_ip_for(self.gateway_host)
        if self._media_ip == "0.0.0.0":
            self._media_ip = "127.0.0.1"
        self._audio_sock = _alloc_udp(self._media_ip)
        self._video_sock = _alloc_udp(self._media_ip)
        return self._audio_sock, self._video_sock

    async def start(
        self, gw_audio: tuple[str, int] | None, gw_video: tuple[str, int] | None
    ) -> str:
        """Start RTP listeners + ffmpeg.  Returns the ``tcp://...`` URL.

        ``gw_audio`` / ``gw_video`` come from the gateway's SDP answer —
        we punch the UDM stateful firewall by sending a few RTP keepalives
        out, then keep doing so periodically.
        """
        if self._video_sock is None or self._audio_sock is None:
            raise RuntimeError("call setup() before start()")
        self._gw_audio = gw_audio
        self._gw_video = gw_video

        loop = asyncio.get_running_loop()

        ingest_port = await self._pick_loopback_udp_port()

        # Bring up datagram endpoints.  Audio is dropped (we don't need it
        # right now) but kept for keepalive purposes.
        self._audio_proto = _RTPProtocol(forward_to=None, on_first_packet=None)
        self._audio_transport, _ = await loop.create_datagram_endpoint(
            lambda: self._audio_proto, sock=self._audio_sock
        )

        def _video_first(data: bytes, addr: tuple[str, int]) -> None:
            _LOGGER.info(
                "[abb] media: first video packet from %s (%d bytes)",
                addr, len(data),
            )
            # Send PLI to encourage a fresh keyframe.
            if self._gw_video is not None and self._video_transport is not None:
                ssrc = (
                    struct.unpack_from("!I", data, 8)[0] if len(data) >= 12 else 0
                )
                try:
                    self._video_transport.sendto(
                        _build_rtcp_pli(0xCAFEBABE, ssrc), self._gw_video
                    )
                except OSError:
                    pass

        self._video_proto = _RTPProtocol(
            forward_to=("127.0.0.1", ingest_port),
            on_first_packet=_video_first,
        )
        self._video_transport, _ = await loop.create_datagram_endpoint(
            lambda: self._video_proto, sock=self._video_sock
        )

        # Punch the firewall pinhole + start periodic keepalive / RTCP.
        if self._gw_audio is not None:
            await self._punch(self._audio_transport, self._gw_audio)
        if self._gw_video is not None:
            await self._punch(self._video_transport, self._gw_video)

        self._stop.clear()
        self._keepalive_task = asyncio.create_task(
            self._keepalive_loop(), name="abb_pipeline_keepalive"
        )
        self._rtcp_task = asyncio.create_task(
            self._rtcp_loop(), name="abb_pipeline_rtcp"
        )

        # Spin up FFmpeg.
        self._sdp_path = Path("/tmp") / f"abb_pipeline_{ingest_port}.sdp"
        sdp_text = (
            "v=0\r\n"
            "o=- 0 0 IN IP4 127.0.0.1\r\n"
            "s=ABB\r\n"
            "c=IN IP4 127.0.0.1\r\n"
            "t=0 0\r\n"
            f"m=video {ingest_port} RTP/AVP 102\r\n"
            "a=rtpmap:102 H264/90000\r\n"
        )
        sdp_path = self._sdp_path
        await loop.run_in_executor(None, sdp_path.write_text, sdp_text)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        self._tcp_port = sock.getsockname()[1]
        sock.close()

        cmd = [
            self.ffmpeg_binary,
            "-loglevel", "warning",
            "-protocol_whitelist", "file,udp,rtp,tcp",
            "-fflags", "nobuffer+genpts",
            "-flags", "low_delay",
            "-i", str(self._sdp_path),
            "-c:v", "copy",
            "-an",
            "-f", "mpegts",
            f"tcp://127.0.0.1:{self._tcp_port}?listen=1&listen_timeout=10000",
        ]
        _LOGGER.info("[abb] media: starting ffmpeg: %s", " ".join(cmd))
        self._ffmpeg = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        self._stderr_task = asyncio.create_task(
            self._drain_stderr(), name="abb_pipeline_stderr"
        )
        return f"tcp://127.0.0.1:{self._tcp_port}"

    async def stop(self) -> None:
        self._stop.set()
        for t in (self._keepalive_task, self._rtcp_task, self._stderr_task):
            if t is not None:
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
        self._keepalive_task = None
        self._rtcp_task = None
        self._stderr_task = None

        if self._ffmpeg is not None and self._ffmpeg.returncode is None:
            try:
                self._ffmpeg.terminate()
                try:
                    await asyncio.wait_for(self._ffmpeg.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    self._ffmpeg.kill()
                    await self._ffmpeg.wait()
            except ProcessLookupError:
                pass
        self._ffmpeg = None

        for tr in (self._video_transport, self._audio_transport):
            if tr is not None:
                tr.close()
        self._video_transport = None
        self._audio_transport = None
        self._video_sock = None
        self._audio_sock = None

        if self._sdp_path is not None:
            sdp_path = self._sdp_path
            try:
                await asyncio.get_running_loop().run_in_executor(
                    None, lambda: sdp_path.unlink(missing_ok=True)
                )
            except OSError:
                pass
            self._sdp_path = None

    async def _pick_loopback_udp_port(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

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
                (self._audio_transport, self._gw_audio),
                (self._video_transport, self._gw_video),
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
            if self._video_proto is not None and self._gw_video is not None and self._video_transport is not None:
                if self._video_proto.media_ssrc != 0:
                    try:
                        self._video_transport.sendto(
                            _build_rtcp_rr(
                                0xCAFEBABE,
                                self._video_proto.media_ssrc,
                                self._video_proto.last_seq,
                            ),
                            self._gw_video,
                        )
                    except OSError:
                        pass

    async def _drain_stderr(self) -> None:
        if self._ffmpeg is None or self._ffmpeg.stderr is None:
            return
        while True:
            line = await self._ffmpeg.stderr.readline()
            if not line:
                return
            text = line.decode(errors="replace").rstrip()
            if text:
                _LOGGER.info("[abb][ffmpeg] %s", text)

    @property
    def media_ip(self) -> str:
        return self._media_ip

    @property
    def stream_url(self) -> str:
        return f"tcp://127.0.0.1:{self._tcp_port}"

    @property
    def video_proto(self) -> _RTPProtocol | None:
        return self._video_proto
