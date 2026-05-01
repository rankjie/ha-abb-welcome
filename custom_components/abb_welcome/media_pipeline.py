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
        label: str = "rtp",
        rewrite_pt: int | None = None,
    ) -> None:
        self.forward_to = forward_to
        self.on_first_packet = on_first_packet
        self.label = label
        # The ABB gateway negotiates one PT in SDP (e.g. 102) but sends
        # the actual RTP packets with a different PT (e.g. 96).  ffmpeg's
        # demuxer uses the SDP rtpmap to look up codec, so a mismatch
        # silently drops every packet.  Rewriting the incoming PT to
        # whatever we declared in the ffmpeg SDP fixes it.
        self.rewrite_pt = rewrite_pt
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
            if self.rewrite_pt is not None and pt != self.rewrite_pt:
                marker = data[1] & 0x80
                rewritten = bytes((data[0], marker | (self.rewrite_pt & 0x7F))) + data[2:]
                data = rewritten
                self._rewrites += 1
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
        # Python-side TCP server that fronts ffmpeg's MPEG-TS stdout.  This
        # eliminates the race where HA's stream worker would try to connect
        # before ffmpeg had reached its own ``listen()``: ``start_server``
        # only resolves once the listening socket is up.
        self._ts_server: asyncio.base_events.Server | None = None
        self._ts_clients: set[asyncio.StreamWriter] = set()
        self._ts_pump_task: asyncio.Task | None = None
        self._stats_task: asyncio.Task | None = None
        self._ffmpeg_watch_task: asyncio.Task | None = None
        self._ts_bytes_forwarded: int = 0
        self._first_ts_chunk_logged = False

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
        self,
        gw_audio: tuple[str, int] | None,
        gw_video: tuple[str, int] | None,
        *,
        video_pt: int | None = None,
        video_codec: str | None = None,
        video_fmtp: str | None = None,
    ) -> str:
        """Start RTP listeners + ffmpeg.  Returns the ``tcp://...`` URL.

        ``gw_audio`` / ``gw_video`` come from the gateway's SDP answer —
        we punch the UDM stateful firewall by sending a few RTP keepalives
        out, then keep doing so periodically.

        ``video_pt`` / ``video_codec`` / ``video_fmtp`` are taken
        verbatim from the gateway's SDP answer.  We mirror them into the
        SDP we hand to ffmpeg so depacketization (especially H.264
        sprop-parameter-sets / packetization-mode) matches what's on the
        wire.
        """
        if self._video_sock is None or self._audio_sock is None:
            raise RuntimeError("call setup() before start()")
        self._gw_audio = gw_audio
        self._gw_video = gw_video

        loop = asyncio.get_running_loop()

        ingest_port = await self._pick_loopback_udp_port()

        # Bring up datagram endpoints.  Audio is dropped (we don't need it
        # right now) but kept for keepalive purposes.
        self._audio_proto = _RTPProtocol(
            forward_to=None, on_first_packet=None, label="audio"
        )
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

        # SDP-declared PT we'll force on outbound (loopback) RTP so it
        # always matches the ffmpeg-side SDP regardless of what the
        # gateway's wire encoding actually is.
        sdp_pt = video_pt if video_pt is not None else 96
        self._video_proto = _RTPProtocol(
            forward_to=("127.0.0.1", ingest_port),
            on_first_packet=_video_first,
            label="video",
            rewrite_pt=sdp_pt,
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
        # PT/codec/fmtp must match what the gateway is actually sending,
        # which is what we just parsed from its SDP answer.  If
        # mismatched, ffmpeg silently discards every packet and HA's
        # stream worker times out with "Invalid data found".
        pt = video_pt if video_pt is not None else 96
        codec = video_codec or "H264/90000"
        sdp_lines = [
            "v=0",
            "o=- 0 0 IN IP4 127.0.0.1",
            "s=ABB",
            "c=IN IP4 127.0.0.1",
            "t=0 0",
            f"m=video {ingest_port} RTP/AVP {pt}",
            f"a=rtpmap:{pt} {codec}",
        ]
        if video_fmtp:
            sdp_lines.append(f"a=fmtp:{pt} {video_fmtp}")
        sdp_lines.append("")
        sdp_text = "\r\n".join(sdp_lines) + "\r\n"
        _LOGGER.info(
            "[abb] media: SDP for ffmpeg uses pt=%d codec=%s fmtp=%s "
            "ingest_port=%d",
            pt, codec, video_fmtp, ingest_port,
        )
        sdp_path = self._sdp_path
        await loop.run_in_executor(None, sdp_path.write_text, sdp_text)

        # Bring up our TCP server FIRST so HA can connect at any time.
        self._ts_server = await asyncio.start_server(
            self._handle_ts_client, "127.0.0.1", 0
        )
        self._tcp_port = self._ts_server.sockets[0].getsockname()[1]

        cmd = [
            self.ffmpeg_binary,
            "-loglevel", "warning",
            "-protocol_whitelist", "file,udp,rtp",
            "-fflags", "nobuffer+genpts",
            "-flags", "low_delay",
            "-i", str(self._sdp_path),
            "-c:v", "copy",
            "-an",
            "-f", "mpegts",
            "pipe:1",
        ]
        _LOGGER.info("[abb] media: starting ffmpeg: %s", " ".join(cmd))
        self._ffmpeg = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._stderr_task = asyncio.create_task(
            self._drain_stderr(), name="abb_pipeline_stderr"
        )
        self._ts_pump_task = asyncio.create_task(
            self._pump_ts(), name="abb_pipeline_ts_pump"
        )
        self._stats_task = asyncio.create_task(
            self._stats_loop(), name="abb_pipeline_stats"
        )
        self._ffmpeg_watch_task = asyncio.create_task(
            self._watch_ffmpeg(), name="abb_pipeline_ffmpeg_watch"
        )
        _LOGGER.info(
            "[abb] media: pipeline ready — gw_video=%s gw_audio=%s "
            "ingest=127.0.0.1:%d ts_url=tcp://127.0.0.1:%d",
            self._gw_video, self._gw_audio, ingest_port, self._tcp_port,
        )
        return f"tcp://127.0.0.1:{self._tcp_port}"

    async def _handle_ts_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        _LOGGER.info("[abb] media: HA stream client connected from %s", peer)
        self._ts_clients.add(writer)
        try:
            # MPEG-TS over TCP is one-way; the client doesn't send anything.
            # We just block on read so we notice EOF when HA disconnects.
            while not self._stop.is_set():
                data = await reader.read(1024)
                if not data:
                    return
        except (ConnectionResetError, ConnectionAbortedError):
            return
        finally:
            self._ts_clients.discard(writer)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _pump_ts(self) -> None:
        """Forward ffmpeg stdout chunks to every connected TS client."""
        if self._ffmpeg is None or self._ffmpeg.stdout is None:
            return
        try:
            while True:
                chunk = await self._ffmpeg.stdout.read(65536)
                if not chunk:
                    _LOGGER.warning(
                        "[abb] media: ffmpeg stdout EOF after %d bytes forwarded",
                        self._ts_bytes_forwarded,
                    )
                    return
                if not self._first_ts_chunk_logged:
                    self._first_ts_chunk_logged = True
                    head = chunk[:8].hex()
                    _LOGGER.info(
                        "[abb] media: first MPEG-TS chunk from ffmpeg "
                        "(%d bytes, head=%s, sync=0x%02x)",
                        len(chunk), head, chunk[0] if chunk else 0,
                    )
                self._ts_bytes_forwarded += len(chunk)
                # Snapshot to avoid mutation during iteration.
                stale: list[asyncio.StreamWriter] = []
                for w in list(self._ts_clients):
                    try:
                        w.write(chunk)
                        await w.drain()
                    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                        stale.append(w)
                    except Exception as err:  # noqa: BLE001
                        _LOGGER.debug("[abb] ts client write failed: %s", err)
                        stale.append(w)
                for w in stale:
                    self._ts_clients.discard(w)
                    try:
                        w.close()
                    except Exception:  # noqa: BLE001
                        pass
        except asyncio.CancelledError:
            return

    async def _stats_loop(self) -> None:
        """Log RTP + ffmpeg stats every 5 seconds while running."""
        try:
            while not self._stop.is_set():
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=5.0)
                    return
                except asyncio.TimeoutError:
                    pass
                vp = self._video_proto
                ap = self._audio_proto
                _LOGGER.info(
                    "[abb] media stats: video pkts=%d bytes=%d pts=%s ssrc=0x%x | "
                    "audio pkts=%d | ts_forwarded=%d clients=%d",
                    vp.packets if vp else 0,
                    vp.bytes_received if vp else 0,
                    dict(vp.payload_types) if vp else {},
                    vp.media_ssrc if vp else 0,
                    ap.packets if ap else 0,
                    self._ts_bytes_forwarded,
                    len(self._ts_clients),
                )
        except asyncio.CancelledError:
            return

    async def _watch_ffmpeg(self) -> None:
        """If ffmpeg dies before we tear down, surface the exit code."""
        if self._ffmpeg is None:
            return
        try:
            rc = await self._ffmpeg.wait()
        except asyncio.CancelledError:
            return
        if not self._stop.is_set():
            _LOGGER.error(
                "[abb] media: ffmpeg exited unexpectedly with code %s "
                "(ts_forwarded=%d, video_pkts=%d)",
                rc,
                self._ts_bytes_forwarded,
                self._video_proto.packets if self._video_proto else 0,
            )

    async def stop(self) -> None:
        self._stop.set()
        for t in (
            self._keepalive_task,
            self._rtcp_task,
            self._stderr_task,
            self._ts_pump_task,
        ):
            if t is not None:
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
        self._keepalive_task = None
        self._rtcp_task = None
        self._stderr_task = None
        self._ts_pump_task = None

        # Tear down TS server + any connected HA stream workers.
        for w in list(self._ts_clients):
            try:
                w.close()
            except Exception:  # noqa: BLE001
                pass
        self._ts_clients.clear()
        if self._ts_server is not None:
            self._ts_server.close()
            try:
                await self._ts_server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._ts_server = None

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
