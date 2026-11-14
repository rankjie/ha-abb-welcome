"""SIP listener dialog-routing response tests."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import time
import types
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


def _load(name: str) -> types.ModuleType:
    pkg = sys.modules.setdefault("abb_welcome", types.ModuleType("abb_welcome"))
    pkg.__path__ = [str(_PKG_DIR)]
    full = f"abb_welcome.{name}"
    if full not in sys.modules:
        spec = importlib.util.spec_from_file_location(full, _PKG_DIR / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[full] = module
        spec.loader.exec_module(module)
    return sys.modules[full]


sip_listener = _load("sip_listener")


class _Writer:
    def __init__(self) -> None:
        self.data = b""

    def write(self, data: bytes) -> None:
        self.data += data

    async def drain(self) -> None:
        return None


def _request(method: str = "INVITE"):
    headers = [
        ("Via", "SIP/2.0/TLS proxy.invalid;branch=first"),
        ("Record-Route", "<sip:first.invalid;lr>"),
        ("record-route", "<sip:second.invalid;lr>"),
        ("From", "<sip:door@example.invalid>;tag=remote"),
        ("To", "<sip:ha@example.invalid>"),
        ("Call-ID", "dialog-routing-test"),
        ("CSeq", f"1 {method}"),
    ]
    return sip_listener._SipFrame(
        start_line=f"{method} sip:ha@example.invalid SIP/2.0",
        headers=headers,
        body=b"",
        raw=b"",
    )


def _respond(frame, code: int, reason: str) -> str:
    listener = sip_listener.SipListener(
        "gateway.invalid", "ha", "secret", "example.invalid"
    )
    writer = _Writer()
    asyncio.run(listener._respond(writer, frame, code, reason))
    return writer.data.decode("utf-8")


@pytest.mark.parametrize(
    ("code", "reason"), ((200, "OK"), (183, "Session Progress"))
)
def test_dialog_forming_invite_response_copies_record_routes_in_wire_order(
    code: int, reason: str
) -> None:
    response = _respond(_request(), code, reason)

    first = "Record-Route: <sip:first.invalid;lr>"
    second = "Record-Route: <sip:second.invalid;lr>"
    assert response.count("Record-Route:") == 2
    assert response.index(first) < response.index(second)
    assert response.index("Via:") < response.index(first) < response.index("From:")


@pytest.mark.parametrize(
    ("frame", "code", "reason"),
    (
        (_request(), 100, "Trying"),
        (_request("OPTIONS"), 200, "OK"),
    ),
)
def test_record_routes_are_not_copied_outside_invite_dialog_responses(
    frame, code: int, reason: str
) -> None:
    assert "Record-Route:" not in _respond(frame, code, reason)


def test_answering_sends_early_media_then_200_in_one_dialog() -> None:
    sdp = (
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n"
        "t=0 0\r\nm=audio 50690 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"
        "m=video 50668 RTP/AVP 102\r\na=rtpmap:102 H264/90000\r\n"
    )
    frame = _request()
    frame.body = sdp.encode()
    frame._received_at = time.time()

    async def answer() -> str:
        listener = sip_listener.SipListener(
            "gateway.invalid", "ha", "secret", "example.invalid"
        )
        writer = _Writer()
        writer.is_closing = lambda: False
        listener._writer = writer
        listener._open_invites["dialog-routing-test"] = frame
        task = asyncio.ensure_future(
            listener.accept_pending_call(
                station_id="",
                media_ip="192.0.2.2",
                audio_port=40000,
                video_port=40002,
            )
        )
        await asyncio.sleep(0)
        listener._accepted_dialogs["dialog-routing-test"].ack_event.set()
        assert await task is not None
        return writer.data.decode("utf-8")

    wire = asyncio.run(answer())
    progress, ok = wire.split("SIP/2.0 200 OK")
    assert progress.startswith("SIP/2.0 183 Session Progress")
    to_tags = [
        line.split(";tag=")[1]
        for line in wire.splitlines()
        if line.startswith("To:")
    ]
    assert len(to_tags) == 2 and to_tags[0] == to_tags[1]
    for response in (progress, ok):
        assert "m=audio 40000 RTP/AVP 8" in response
        assert "m=video 40002 RTP/AVP 102" in response
        assert response.count("Record-Route:") == 2


def test_register_wait_dispatches_requests_and_matches_exact_response() -> None:
    listener = sip_listener.SipListener(
        "gateway.invalid", "ha", "secret", "example.invalid"
    )
    incoming = _request()
    frames = [
        incoming,
        sip_listener._SipFrame(
            start_line="SIP/2.0 200 OK",
            headers=[("Call-ID", "other"), ("CSeq", "7 REGISTER")],
            body=b"",
            raw=b"",
        ),
        sip_listener._SipFrame(
            start_line="SIP/2.0 180 Ringing",
            headers=[("Call-ID", "register"), ("CSeq", "7 REGISTER")],
            body=b"",
            raw=b"",
        ),
        sip_listener._SipFrame(
            start_line="SIP/2.0 200 OK",
            headers=[("Call-ID", "register"), ("CSeq", "7 REGISTER")],
            body=b"",
            raw=b"",
        ),
    ]
    dispatched = []

    async def read_frame(_reader):
        return frames.pop(0)

    async def dispatch(frame, _writer, _local_ip, _local_port):
        dispatched.append(frame)

    listener._read_frame = read_frame
    listener._dispatch = dispatch
    listener._emit_frame = lambda *_args: None

    async def run():
        return await listener._read_final_response(
            None,
            call_id="register",
            cseq_number=7,
            cseq_method="REGISTER",
            writer=_Writer(),
            local_ip="192.0.2.20",
            local_port=40000,
        )

    result = asyncio.run(run())

    assert dispatched == [incoming]
    assert result.status_code == 200
    assert sip_listener._header(result.headers, "Call-ID") == "register"
    assert sip_listener._header(result.headers, "CSeq") == "7 REGISTER"
    assert frames == []
