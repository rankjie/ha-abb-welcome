"""Small TCP proxy that exposes HA-bundled go2rtc RTSP to LAN consumers."""

from __future__ import annotations

import asyncio
from contextlib import suppress

from .redaction import get_redacting_logger

_LOGGER = get_redacting_logger(__name__)


class RtspTcpProxy:
    """Forward one LAN RTSP port to HA's localhost-only go2rtc listener."""

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
                self._pipe(client_reader, upstream_writer)
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
