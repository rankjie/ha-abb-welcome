"""Minimal RTSP server that go2rtc can pull from.

Architecture (one server per camera):

* the camera entity binds an :class:`RtspServer` on a stable, random
  127.0.0.1 port at entity-add and registers
  ``rtsp://127.0.0.1:<port>/`` as the producer URL with HA-bundled
  go2rtc
* go2rtc — when a downstream WebRTC consumer asks for the stream —
  opens a TCP connection to that port and runs the standard RTSP
  pull dance: OPTIONS, DESCRIBE, SETUP (×N), PLAY
* on PLAY we ask the camera entity for an "open session" callback,
  which dials the SIP gateway and starts forwarding RTP packets back
  through the same TCP socket using interleaved framing
  (``$ <ch> <BE16 len> <payload>``)
* TEARDOWN / connection close → we hangup the gateway

Because we're the *server* (and go2rtc is the *client*), there's no
publisher/consumer split or self-loop in go2rtc — the standard
``rtsp://`` source path works as designed.

Channel allocation:

* video RTP  → channel 0
* video RTCP → channel 1
* audio RTP  → channel 2
* audio RTCP → channel 3
"""

from __future__ import annotations

import asyncio
import logging
import re
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final

_LOGGER = logging.getLogger(__name__)

VIDEO_RTP_CHANNEL: Final = 0
VIDEO_RTCP_CHANNEL: Final = 1
AUDIO_RTP_CHANNEL: Final = 2
AUDIO_RTCP_CHANNEL: Final = 3

_USER_AGENT = "ABB-Welcome-HA-RTSP-Server/1.0"


@dataclass
class RtspSession:
    """Per-client state passed back to the camera entity."""

    session_id: str
    writer: asyncio.StreamWriter
    write_lock: asyncio.Lock
    has_video: bool = False
    has_audio: bool = False
    playing: bool = False

    def push_rtp(self, channel: int, rtp_data: bytes) -> bool:
        """Frame + send one RTP packet on the established TCP connection."""
        if self.writer.is_closing():
            return False
        if len(rtp_data) > 0xFFFF:
            return False
        header = struct.pack("!cBH", b"$", channel, len(rtp_data))
        try:
            self.writer.write(header + rtp_data)
        except (BrokenPipeError, ConnectionResetError, OSError) as err:
            _LOGGER.debug("[abb-rtsp] interleaved write failed: %s", err)
            return False
        return True


class RtspServer:
    """One per-camera RTSP server (TCP, control + interleaved RTP)."""

    def __init__(
        self,
        *,
        host: str,
        on_describe: Callable[[], Awaitable[str | None]],
        on_play: Callable[[RtspSession], Awaitable[None]],
        on_teardown: Callable[[RtspSession], Awaitable[None]],
    ) -> None:
        self._host = host
        self._on_describe = on_describe
        self._on_play = on_play
        self._on_teardown = on_teardown
        self._server: asyncio.base_events.Server | None = None
        self._port: int = 0
        self._next_session = 1
        self._sessions: dict[str, RtspSession] = {}

    @property
    def port(self) -> int:
        return self._port

    @property
    def url(self) -> str:
        return f"rtsp://{self._host}:{self._port}/"

    @property
    def session_count(self) -> int:
        return len(self._sessions)

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection, self._host, 0
        )
        self._port = self._server.sockets[0].getsockname()[1]
        _LOGGER.info("[abb-rtsp] listening on %s", self.url)

    async def stop(self) -> None:
        for sess in list(self._sessions.values()):
            try:
                sess.writer.close()
            except Exception:  # noqa: BLE001
                pass
        self._sessions.clear()
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._server = None

    # ------------------------------------------------------------------ #

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        _LOGGER.info("[abb-rtsp] %s connected", peer)
        write_lock = asyncio.Lock()
        session_id: str | None = None
        try:
            while True:
                request = await self._read_request(reader)
                if request is None:
                    break
                method, url, headers, body = request
                cseq = headers.get("cseq", "0")
                _LOGGER.debug(
                    "[abb-rtsp] %s %s %s (CSeq=%s)",
                    peer, method, url, cseq,
                )

                if method == "OPTIONS":
                    await self._send_response(
                        writer, write_lock, 200, "OK",
                        {"CSeq": cseq, "Public": "OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN, GET_PARAMETER"},
                    )
                    continue

                if method == "DESCRIBE":
                    sdp = await self._on_describe()
                    if sdp is None:
                        await self._send_response(
                            writer, write_lock, 503, "Service Unavailable",
                            {"CSeq": cseq},
                        )
                        continue
                    base = url if url.endswith("/") else url + "/"
                    _LOGGER.info(
                        "[abb-rtsp] DESCRIBE response (CSeq=%s, base=%s):\n%s",
                        cseq, base, sdp.replace("\r\n", "\n"),
                    )
                    await self._send_response(
                        writer, write_lock, 200, "OK",
                        {
                            "CSeq": cseq,
                            "Content-Type": "application/sdp",
                            "Content-Base": base,
                        },
                        body=sdp.encode("utf-8"),
                    )
                    continue

                if method == "SETUP":
                    transport = headers.get("transport", "")
                    if "RTP/AVP/TCP" not in transport:
                        # We only support TCP-interleaved transport.
                        await self._send_response(
                            writer, write_lock, 461, "Unsupported Transport",
                            {"CSeq": cseq},
                        )
                        continue
                    interleaved = self._parse_interleaved(transport)
                    if session_id is None:
                        session_id = f"{self._next_session:08x}"
                        self._next_session += 1
                        sess = RtspSession(
                            session_id=session_id,
                            writer=writer,
                            write_lock=write_lock,
                        )
                        self._sessions[session_id] = sess
                    else:
                        sess = self._sessions[session_id]
                    if interleaved == (VIDEO_RTP_CHANNEL, VIDEO_RTCP_CHANNEL):
                        sess.has_video = True
                    elif interleaved == (AUDIO_RTP_CHANNEL, AUDIO_RTCP_CHANNEL):
                        sess.has_audio = True
                    else:
                        # Map to whichever track we haven't bound yet —
                        # makes us forgiving when go2rtc picks its own
                        # channels.
                        if not sess.has_video:
                            sess.has_video = True
                        elif not sess.has_audio:
                            sess.has_audio = True
                    transport_resp = transport.split(";", 1)[0] + ";unicast;" + (
                        f"interleaved={interleaved[0]}-{interleaved[1]}"
                        if interleaved
                        else "interleaved=0-1"
                    )
                    await self._send_response(
                        writer, write_lock, 200, "OK",
                        {
                            "CSeq": cseq,
                            "Transport": transport_resp,
                            "Session": f"{session_id};timeout=60",
                        },
                    )
                    continue

                if method == "PLAY":
                    if session_id is None or session_id not in self._sessions:
                        await self._send_response(
                            writer, write_lock, 454, "Session Not Found",
                            {"CSeq": cseq},
                        )
                        continue
                    sess = self._sessions[session_id]
                    sess.playing = True
                    await self._send_response(
                        writer, write_lock, 200, "OK",
                        {"CSeq": cseq, "Session": session_id},
                    )
                    try:
                        await self._on_play(sess)
                    except Exception as err:  # noqa: BLE001
                        _LOGGER.exception(
                            "[abb-rtsp] on_play raised: %s", err
                        )
                    continue

                if method == "TEARDOWN":
                    await self._send_response(
                        writer, write_lock, 200, "OK",
                        {"CSeq": cseq, "Session": session_id or ""},
                    )
                    break

                if method == "GET_PARAMETER":
                    await self._send_response(
                        writer, write_lock, 200, "OK",
                        {"CSeq": cseq, "Session": session_id or ""},
                    )
                    continue

                await self._send_response(
                    writer, write_lock, 501, "Not Implemented",
                    {"CSeq": cseq},
                )
        except (asyncio.IncompleteReadError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception as err:  # noqa: BLE001
            _LOGGER.exception("[abb-rtsp] connection error: %s", err)
        finally:
            sess = self._sessions.pop(session_id, None) if session_id else None
            if sess is not None:
                try:
                    await self._on_teardown(sess)
                except Exception as err:  # noqa: BLE001
                    _LOGGER.debug("[abb-rtsp] on_teardown raised: %s", err)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            _LOGGER.info("[abb-rtsp] %s disconnected", peer)

    @staticmethod
    def _parse_interleaved(transport: str) -> tuple[int, int] | None:
        m = re.search(r"interleaved=(\d+)-(\d+)", transport)
        if not m:
            return None
        return int(m.group(1)), int(m.group(2))

    @staticmethod
    async def _read_request(
        reader: asyncio.StreamReader,
    ) -> tuple[str, str, dict[str, str], bytes] | None:
        head = bytearray()
        while True:
            line = await reader.readline()
            if not line:
                if not head:
                    return None
                raise asyncio.IncompleteReadError(bytes(head), None)
            head.extend(line)
            if line in (b"\r\n", b"\n"):
                break
        text = head.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        request_line = lines[0]
        parts = request_line.split(" ", 2)
        if len(parts) < 3:
            return None
        method, url = parts[0].upper(), parts[1]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        cl = int(headers.get("content-length", "0"))
        body = await reader.readexactly(cl) if cl else b""
        return method, url, headers, body

    @staticmethod
    async def _send_response(
        writer: asyncio.StreamWriter,
        lock: asyncio.Lock,
        code: int,
        reason: str,
        headers: dict[str, str],
        body: bytes = b"",
    ) -> None:
        lines = [f"RTSP/1.0 {code} {reason}"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append(f"Server: {_USER_AGENT}")
        if body:
            lines.append(f"Content-Length: {len(body)}")
        lines.append("")
        lines.append("")
        payload = "\r\n".join(lines).encode("utf-8") + body
        async with lock:
            try:
                writer.write(payload)
                await writer.drain()
            except (BrokenPipeError, ConnectionResetError, OSError) as err:
                _LOGGER.debug("[abb-rtsp] response send failed: %s", err)
                raise
