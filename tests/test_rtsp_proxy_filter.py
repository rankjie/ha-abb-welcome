"""The LAN RTSP proxy must serve only this integration's streams, for playback."""

from __future__ import annotations

import asyncio
import importlib.util
import socket
import sys
import types
from pathlib import Path

import pytest

_PKG_DIR = (
    Path(__file__).resolve().parent.parent
    / "custom_components" / "abb_welcome"
)

pkg = types.ModuleType("abb_welcome")
pkg.__path__ = [str(_PKG_DIR)]
sys.modules.setdefault("abb_welcome", pkg)


def _load(name: str) -> types.ModuleType:
    full = f"abb_welcome.{name}"
    if full not in sys.modules:
        spec = importlib.util.spec_from_file_location(full, _PKG_DIR / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[full] = module
        spec.loader.exec_module(module)
    return sys.modules[full]


rtsp_proxy = _load("rtsp_proxy")

ALLOWED = "abb_100000001"
OTHER = "generic_frontdoor_cam"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _request(method: str, uri: str, cseq: int = 1, body: bytes = b"") -> bytes:
    length = f"Content-Length: {len(body)}\r\n" if body else ""
    return f"{method} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n{length}\r\n".encode() + body


def _exchange(*messages: bytes) -> tuple[bytes, bytes]:
    """Send ``messages`` through the proxy; return (upstream saw, client got).

    The fake go2rtc answers every chunk it receives with ``UP`` so a reply
    from upstream is distinguishable from one the proxy generated.
    """

    async def _run() -> tuple[bytes, bytes]:
        seen = bytearray()

        async def _upstream(reader, writer) -> None:
            while data := await reader.read(65536):
                seen.extend(data)
                writer.write(b"UP")
                await writer.drain()
            writer.close()

        upstream = await asyncio.start_server(_upstream, "127.0.0.1", 0)
        proxy = rtsp_proxy.RtspTcpProxy(
            bind_host="127.0.0.1",
            bind_port=_free_port(),
            target_host="127.0.0.1",
            target_port=upstream.sockets[0].getsockname()[1],
        )
        proxy.allow_stream(ALLOWED)
        assert await proxy.start()
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", proxy.bind_port
            )
            for message in messages:
                writer.write(message)
                await writer.drain()
                await asyncio.sleep(0.05)
            writer.write_eof()
            received = await asyncio.wait_for(reader.read(), timeout=5)
            writer.close()
            return bytes(seen), received
        finally:
            await proxy.stop()
            upstream.close()
            await upstream.wait_closed()

    return asyncio.run(_run())


@pytest.mark.parametrize(
    "uri",
    [
        f"rtsp://192.168.1.10:18556/{ALLOWED}",
        f"rtsp://192.168.1.10:18556/{ALLOWED}?video&audio",
        f"rtsp://192.168.1.10:18556/{ALLOWED}/trackID=0",
        f"/{ALLOWED}",
    ],
)
def test_playback_of_an_allowed_stream_is_forwarded_unchanged(uri):
    describe = _request("DESCRIBE", uri)
    seen, received = _exchange(describe)
    assert seen == describe
    assert received == b"UP"


@pytest.mark.parametrize(
    "uri",
    [
        f"rtsp://192.168.1.10:18556/{OTHER}",
        f"rtsp://192.168.1.10:18556/{OTHER}/trackID=0",
        f"rtsp://192.168.1.10:18556/{ALLOWED}_2",
        f"rtsp://192.168.1.10:18556/{ALLOWED}/../{OTHER}",
        f"rtsp://192.168.1.10:18556//{OTHER}",
        f"rtsp://192.168.1.10:18556/?src={OTHER}",
        "rtsp://192.168.1.10:18556/",
        "*",
    ],
)
def test_other_streams_never_reach_go2rtc(uri):
    seen, received = _exchange(_request("DESCRIBE", uri, cseq=7))
    assert seen == b""
    assert received == b"RTSP/1.0 404 Not Found\r\nCSeq: 7\r\n\r\n"


@pytest.mark.parametrize("method", ["ANNOUNCE", "RECORD", "GET", "describe"])
def test_publishing_and_unknown_methods_are_refused(method):
    request = _request(method, f"rtsp://h/{ALLOWED}", cseq=3, body=b"v=0\r\n")
    seen, received = _exchange(request)
    assert seen == b""
    assert received == b"RTSP/1.0 405 Method Not Allowed\r\nCSeq: 3\r\n\r\n"


def test_a_later_request_for_another_stream_ends_the_connection():
    allowed = _request("DESCRIBE", f"rtsp://h/{ALLOWED}", cseq=1)
    seen, received = _exchange(
        allowed, _request("DESCRIBE", f"rtsp://h/{OTHER}", cseq=2)
    )
    assert seen == allowed
    assert received == b"UP" + b"RTSP/1.0 404 Not Found\r\nCSeq: 2\r\n\r\n"


def test_a_request_hidden_in_a_message_body_is_not_parsed_as_a_request():
    hidden = _request("ANNOUNCE", f"rtsp://h/{OTHER}")
    carrier = _request("SET_PARAMETER", f"rtsp://h/{ALLOWED}", body=hidden)
    seen, _ = _exchange(carrier)
    assert seen == carrier


def test_interleaved_frames_and_keepalive_requests_pass_through():
    frame = b"$\x01\x00\x08" + b"RTCPDATA"
    # A payload that looks like a request must stay opaque frame data.
    disguised = _request("DESCRIBE", f"rtsp://h/{OTHER}")
    disguised_frame = b"$\x01" + len(disguised).to_bytes(2, "big") + disguised
    options = _request("OPTIONS", "*", cseq=4)
    response = b"RTSP/1.0 200 OK\r\nCSeq: 9\r\n\r\n"
    stream = frame + disguised_frame + options + response
    seen, _ = _exchange(stream)
    assert seen == stream


def test_requests_split_across_tcp_segments_are_reassembled():
    describe = _request("DESCRIBE", f"rtsp://h/{ALLOWED}")
    seen, _ = _exchange(describe[:9], describe[9:30], describe[30:])
    assert seen == describe


@pytest.mark.parametrize(
    "raw",
    [
        b"NONSENSE\r\n\r\n",
        f"DESCRIBE rtsp://h/{ALLOWED} RTSP/1.0\r\nContent-Length: -1\r\n\r\n".encode(),
        f"DESCRIBE rtsp://h/{ALLOWED} RTSP/1.0\r\nContent-Length: 999999\r\n\r\n".encode(),
        b"DESCRIBE rtsp://h/" + b"a" * 70000 + b" RTSP/1.0\r\n\r\n",
    ],
)
def test_malformed_requests_are_refused(raw):
    seen, received = _exchange(raw)
    assert seen == b""
    assert received.startswith(b"RTSP/1.0 400 Bad Request\r\n")


def test_a_removed_stream_is_no_longer_served():
    proxy = rtsp_proxy.RtspTcpProxy(
        bind_host="127.0.0.1", bind_port=0, target_host="127.0.0.1", target_port=0
    )
    proxy.allow_stream(ALLOWED)
    head = _request("DESCRIBE", f"rtsp://h/{ALLOWED}")
    assert proxy._check_message_head(head) == 0
    proxy.disallow_stream(ALLOWED)
    with pytest.raises(rtsp_proxy._RequestRejected, match="404"):
        proxy._check_message_head(head)
