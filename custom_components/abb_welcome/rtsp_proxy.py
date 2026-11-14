"""Small RTSP proxy that exposes this integration's go2rtc streams to the LAN."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from urllib.parse import urlsplit

from .redaction import get_redacting_logger

_LOGGER = get_redacting_logger(__name__)

# Playback only: ANNOUNCE and RECORD would let a LAN client publish into go2rtc.
_PLAYBACK_METHODS = frozenset(
    {
        "OPTIONS",
        "DESCRIBE",
        "SETUP",
        "PLAY",
        "PAUSE",
        "TEARDOWN",
        "GET_PARAMETER",
        "SET_PARAMETER",
    }
)
_MAX_HEADER_BYTES = 16 * 1024
_MAX_BODY_BYTES = 64 * 1024


class _RequestRejected(Exception):
    """A client request that must not reach go2rtc."""

    def __init__(self, status: int, reason: str, cseq: str = "") -> None:
        super().__init__(f"{status} {reason}")
        self.status = status
        self.reason = reason
        self.cseq = cseq


def requested_stream(uri: str) -> str | None:
    """Return the go2rtc stream name an RTSP request URI addresses.

    The stream is the first path segment; SETUP appends a track suffix such as
    ``/trackID=0``.  Returns None when the URI names no stream.
    """
    path = urlsplit(uri).path
    if not path.startswith("/"):
        return None
    segments = path[1:].split("/")
    if not segments[0] or ".." in segments:
        return None
    return segments[0]


class RtspTcpProxy:
    """Serve this integration's streams from HA's localhost-only go2rtc.

    go2rtc's RTSP listener has no credentials and carries every camera stream
    in Home Assistant, so requests are forwarded only for allowed stream names.
    """

    def __init__(
        self,
        *,
        bind_host: str,
        bind_port: int,
        target_host: str,
        target_port: int,
    ) -> None:
        self._bind_host = bind_host
        self._bind_port = bind_port
        self._target_host = target_host
        self._target_port = target_port
        self._server: asyncio.base_events.Server | None = None
        self._connections: set[asyncio.Task[None]] = set()
        self._last_error = ""
        self._allowed_streams: set[str] = set()

    def allow_stream(self, name: str) -> None:
        """Let LAN clients play the go2rtc stream ``name``."""
        self._allowed_streams.add(name)

    def disallow_stream(self, name: str) -> None:
        self._allowed_streams.discard(name)

    @property
    def bind_port(self) -> int:
        return self._bind_port

    @property
    def bind_host(self) -> str:
        return self._bind_host

    @property
    def last_error(self) -> str:
        return self._last_error

    @property
    def target_url(self) -> str:
        return f"rtsp://{self._target_host}:{self._target_port}/"

    @property
    def running(self) -> bool:
        return self._server is not None

    async def start(self) -> bool:
        if self._server is not None:
            return True
        try:
            self._server = await asyncio.start_server(
                self._handle_connection,
                self._bind_host,
                self._bind_port,
                reuse_port=False,
            )
        except OSError as err:
            self._last_error = str(err)
            _LOGGER.error(
                "[abb-rtsp-proxy] failed to listen on %s:%d -> %s:%d: %s",
                self._bind_host,
                self._bind_port,
                self._target_host,
                self._target_port,
                err,
            )
            return False

        self._last_error = ""
        sockets = ", ".join(
            str(sock.getsockname()) for sock in self._server.sockets or ()
        )
        _LOGGER.info(
            "[abb-rtsp-proxy] listening on %s -> %s:%d",
            sockets or f"{self._bind_host}:{self._bind_port}",
            self._target_host,
            self._target_port,
        )
        return True

    async def stop(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            with suppress(Exception):
                await server.wait_closed()

        tasks = list(self._connections)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._connections.clear()

    async def _handle_connection(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._connections.add(task)

        peer = client_writer.get_extra_info("peername")
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self._target_host,
                self._target_port,
            )
            _LOGGER.info("[abb-rtsp-proxy] %s connected", peer)

            to_upstream = asyncio.create_task(
                self._forward_requests(
                    client_reader, upstream_writer, client_writer, peer
                )
            )
            to_client = asyncio.create_task(
                self._pipe(upstream_reader, client_writer)
            )
            done, pending = await asyncio.wait(
                {to_upstream, to_client},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for item in pending:
                item.cancel()
            await asyncio.gather(*done, *pending, return_exceptions=True)
        except asyncio.CancelledError:
            raise
        except OSError as err:
            _LOGGER.info("[abb-rtsp-proxy] %s connection failed: %s", peer, err)
        finally:
            self._close_writer(client_writer)
            if upstream_writer is not None:
                self._close_writer(upstream_writer)
            if task is not None:
                self._connections.discard(task)
            _LOGGER.info("[abb-rtsp-proxy] %s disconnected", peer)

    async def _forward_requests(
        self,
        reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        client_writer: asyncio.StreamWriter,
        peer: object,
    ) -> None:
        """Forward client messages until EOF or the first rejected request."""
        try:
            while not upstream_writer.is_closing():
                message = await self._read_client_message(reader)
                if message is None:
                    return
                upstream_writer.write(message)
                await upstream_writer.drain()
        except _RequestRejected as err:
            _LOGGER.warning(
                "[abb-rtsp-proxy] %s request rejected with %d %s",
                peer, err.status, err.reason,
            )
            cseq = f"CSeq: {err.cseq}\r\n" if err.cseq else ""
            client_writer.write(
                f"RTSP/1.0 {err.status} {err.reason}\r\n{cseq}\r\n".encode("ascii")
            )
            await client_writer.drain()

    async def _read_client_message(self, reader: asyncio.StreamReader) -> bytes | None:
        """Return the next client message to forward, or None at EOF."""
        try:
            first = await reader.readexactly(1)
            while first in b"\r\n":
                first = await reader.readexactly(1)
            if first == b"$":
                # Interleaved frame: channel byte, 16-bit length, payload.
                header = await reader.readexactly(3)
                payload = await reader.readexactly(int.from_bytes(header[1:], "big"))
                return first + header + payload
            try:
                head = first + await reader.readuntil(b"\r\n\r\n")
            except asyncio.LimitOverrunError as err:
                raise _RequestRejected(400, "Bad Request") from err
            if len(head) > _MAX_HEADER_BYTES:
                raise _RequestRejected(400, "Bad Request")
            body_length = self._check_message_head(head)
            return head + await reader.readexactly(body_length)
        except asyncio.IncompleteReadError:
            return None

    def _check_message_head(self, head: bytes) -> int:
        """Validate one request or response head and return its body length."""
        try:
            lines = head.decode("ascii").split("\r\n")
        except UnicodeDecodeError as err:
            raise _RequestRejected(400, "Bad Request") from err
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()
        cseq = headers.get("cseq", "")
        if not cseq.isdigit():
            cseq = ""

        length_value = headers.get("content-length", "0")
        if not length_value.isdigit() or int(length_value) > _MAX_BODY_BYTES:
            raise _RequestRejected(400, "Bad Request", cseq)

        # A response to a request go2rtc sent to the client.
        if lines[0].startswith("RTSP/"):
            return int(length_value)

        parts = lines[0].split(" ")
        if len(parts) != 3 or not parts[2].startswith("RTSP/"):
            raise _RequestRejected(400, "Bad Request", cseq)
        method, uri = parts[0], parts[1]
        if method not in _PLAYBACK_METHODS:
            raise _RequestRejected(405, "Method Not Allowed", cseq)
        if uri == "*" and method == "OPTIONS":
            return int(length_value)
        if requested_stream(uri) not in self._allowed_streams:
            raise _RequestRejected(404, "Not Found", cseq)
        return int(length_value)

    async def _pipe(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        while not writer.is_closing():
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()

    @staticmethod
    def _close_writer(writer: asyncio.StreamWriter) -> None:
        with suppress(Exception):
            writer.close()
