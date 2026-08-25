"""SIP listener dialog-routing response tests."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
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


def test_invite_200_copies_all_record_routes_in_wire_order() -> None:
    response = _respond(_request(), 200, "OK")

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
def test_record_routes_are_not_copied_outside_invite_2xx(
    frame, code: int, reason: str
) -> None:
    assert "Record-Route:" not in _respond(frame, code, reason)
