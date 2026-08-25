"""SIP response correlation tests for the synchronous unlock client."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


def _load(name: str) -> types.ModuleType:
    package = sys.modules.setdefault("abb_sip_correlation_test", types.ModuleType("abb_sip_correlation_test"))
    package.__path__ = [str(_PKG_DIR)]
    full_name = f"abb_sip_correlation_test.{name}"
    if full_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(full_name, _PKG_DIR / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[full_name] = module
        spec.loader.exec_module(module)
    return sys.modules[full_name]


_load("redaction")
sip_client = _load("sip_client")


def _response(
    status: int,
    *,
    call_id: str,
    cseq: str,
) -> object:
    return sip_client.SipFrame(
        start_line=f"SIP/2.0 {status} Response",
        headers=[("Call-ID", call_id), ("CSeq", cseq)],
        body=b"",
    )


def test_final_response_requires_exact_call_id_and_cseq() -> None:
    frames = [
        sip_client.SipFrame(
            start_line="INVITE sip:ha@example.invalid SIP/2.0",
            headers=[("Call-ID", "ring"), ("CSeq", "1 INVITE")],
            body=b"",
        ),
        _response(200, call_id="other", cseq="1 MESSAGE"),
        _response(200, call_id="unlock", cseq="2 MESSAGE"),
        _response(180, call_id="unlock", cseq="1 MESSAGE"),
        _response(200, call_id="unlock", cseq="1 MESSAGE"),
    ]

    class Frames(sip_client.SipStream):
        def __init__(self) -> None:
            pass

        def recv_frame(self):
            return frames.pop(0)

    result = Frames().recv_final_response(
        call_id="unlock",
        cseq_number=1,
        cseq_method="MESSAGE",
    )

    assert result.status_code() == 200
    assert result.header("Call-ID") == "unlock"
    assert result.header("CSeq") == "1 MESSAGE"
    assert frames == []


def test_matching_response_preserves_invite_provisional_response() -> None:
    frames = [
        sip_client.SipFrame(
            start_line="INVITE sip:ha@example.invalid SIP/2.0",
            headers=[("Call-ID", "ring"), ("CSeq", "1 INVITE")],
            body=b"",
        ),
        _response(183, call_id="outbound", cseq="2 INVITE"),
        _response(200, call_id="outbound", cseq="2 INVITE"),
    ]

    class Frames:
        def recv_frame(self):
            return frames.pop(0)

    result = sip_client.SipStream.recv_response(
        Frames(),
        call_id="outbound",
        cseq_number=2,
        cseq_method="INVITE",
    )

    assert result.status_code() == 183
    assert len(frames) == 1


def test_plain_message_correlates_initial_and_authenticated_responses() -> None:
    challenge = _response(407, call_id="placeholder", cseq="1 MESSAGE")
    challenge.headers.append(
        (
            "Proxy-Authenticate",
            'Digest realm="welcome", nonce="nonce", algorithm=MD5, qop="auth"',
        )
    )

    class Socket:
        def __init__(self) -> None:
            self.sent: list[bytes] = []

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

    class Stream:
        def __init__(self) -> None:
            self.sock = Socket()
            self.calls: list[tuple[str, int, str]] = []

        def recv_final_response(
            self,
            *,
            call_id: str,
            cseq_number: int,
            cseq_method: str,
        ):
            self.calls.append((call_id, cseq_number, cseq_method))
            if len(self.calls) == 1:
                challenge.headers[0] = ("Call-ID", call_id)
                return challenge
            return _response(200, call_id=call_id, cseq="2 MESSAGE")

    stream = Stream()
    gateway = sip_client.GatewayConfig(
        sip_domain="example.invalid",
        gw_host="192.0.2.10",
        gw_port=5060,
        transport="tcp",
    )

    response = sip_client._send_plain_message(
        stream,
        "192.0.2.20",
        40000,
        gateway,
        "ha",
        "secret",
        "sip:door@example.invalid",
        "1",
    )

    call_id = stream.calls[0][0]
    assert stream.calls == [
        (call_id, 1, "MESSAGE"),
        (call_id, 2, "MESSAGE"),
    ]
    assert response.status_code() == 200
    assert len(stream.sock.sent) == 2


def test_register_correlates_its_response() -> None:
    class Socket:
        def sendall(self, _data: bytes) -> None:
            return None

    class Stream:
        def __init__(self) -> None:
            self.sock = Socket()
            self.call: tuple[str, int, str] | None = None

        def recv_final_response(
            self,
            *,
            call_id: str,
            cseq_number: int,
            cseq_method: str,
        ):
            self.call = (call_id, cseq_number, cseq_method)
            return _response(200, call_id=call_id, cseq="1 REGISTER")

    stream = Stream()
    gateway = sip_client.GatewayConfig(
        sip_domain="example.invalid",
        gw_host="192.0.2.10",
        gw_port=5060,
        transport="tcp",
    )

    sip_client._register_client(
        stream,
        "192.0.2.20",
        40000,
        gateway,
        "ha",
        "secret",
    )

    assert stream.call is not None
    assert stream.call[1:] == (1, "REGISTER")
