"""The dialer withholds calls right after the gateway ended or refused one."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"
_PACKAGE = "abb_dial_holdoff_test"


def _load(name: str) -> types.ModuleType:
    package = sys.modules.setdefault(_PACKAGE, types.ModuleType(_PACKAGE))
    package.__path__ = [str(_PKG_DIR)]
    full_name = f"{_PACKAGE}.{name}"
    if full_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            full_name, _PKG_DIR / f"{name}.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[full_name] = module
        spec.loader.exec_module(module)
    return sys.modules[full_name]


_load("redaction")
intercom = _load("intercom_dialer")

DOOR = intercom.Door("Door", "sip:100000001@example.invalid", station_id="100000001")


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


class _Gateway:
    """Writer stand-in that answers every INVITE with one status."""

    def __init__(self, dialer, status: str) -> None:
        self._dialer = dialer
        self.status = status
        self.invites = 0

    def write(self, data: bytes) -> None:
        head = data.decode().split("\r\n\r\n", 1)[0].split("\r\n")
        if not head[0].startswith("INVITE "):
            return
        self.invites += 1
        headers = dict(line.split(": ", 1) for line in head[1:])
        self._dialer._inbound_queue.put_nowait(
            intercom.SipFrame(
                start_line=f"SIP/2.0 {self.status}",
                headers=[
                    ("Call-ID", headers["Call-ID"]),
                    ("CSeq", headers["CSeq"]),
                    ("To", headers["To"] + ";tag=remote"),
                    ("Contact", "<sip:100000001@192.0.2.10:5061>"),
                ],
                body=b"",
                raw=b"",
            )
        )

    async def drain(self) -> None:
        return None

    def is_closing(self) -> bool:
        return False


@pytest.fixture
def clock(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(intercom.time, "monotonic", clock.monotonic)
    return clock


def _dialer(status: str = "200 OK"):
    dialer = intercom.IntercomDialer(
        "192.0.2.10", "synthetic-user", "synthetic-password", "example.invalid"
    )
    dialer._local_ip, dialer._local_port = "192.0.2.20", 40000
    dialer._registered = True
    dialer._reader_task = types.SimpleNamespace(done=lambda: False)
    gateway = _Gateway(dialer, status)
    dialer._writer = gateway
    return dialer, gateway


async def _dial(dialer):
    return await dialer.dial(DOOR, audio_port=6000, video_port=6002)


def _gateway_hangs_up(dialer, call) -> None:
    dialer._finish_call(call.call_id, "remote_bye")


def test_reconnects_after_a_gateway_hangup_send_no_invite_until_the_holdoff_ends(
    clock,
):
    async def scenario():
        dialer, gateway = _dialer()
        call = await _dial(dialer)
        clock.now += 60
        _gateway_hangs_up(dialer, call)

        for elapsed in (0.1, 1.0, 2.9):
            clock.now = 1060 + elapsed
            with pytest.raises(intercom.GatewayBusyError, match="retry in"):
                await _dial(dialer)
        assert gateway.invites == 1

        clock.now = 1060 + intercom.DIAL_HOLDOFF_INITIAL
        await _dial(dialer)
        assert gateway.invites == 2

    asyncio.run(scenario())


def test_holdoff_doubles_while_calls_keep_failing_and_is_capped(clock):
    async def scenario():
        dialer, gateway = _dialer("486 Busy Here")
        waits = []
        for _ in range(5):
            with pytest.raises(RuntimeError, match="INVITE rejected"):
                await _dial(dialer)
            waits.append(dialer._dial_not_before - clock.now)
            with pytest.raises(intercom.GatewayBusyError):
                await _dial(dialer)
            clock.now = dialer._dial_not_before
        assert waits == [3.0, 6.0, 12.0, 15.0, 15.0]
        assert gateway.invites == 5

    asyncio.run(scenario())


def test_a_call_cut_short_by_the_gateway_counts_as_another_failure(clock):
    async def scenario():
        dialer, _ = _dialer()
        call = await _dial(dialer)
        clock.now += 60
        _gateway_hangs_up(dialer, call)
        clock.now += intercom.DIAL_HOLDOFF_INITIAL

        call = await _dial(dialer)
        clock.now += 1
        _gateway_hangs_up(dialer, call)
        assert dialer._dial_not_before - clock.now == 6.0

    asyncio.run(scenario())


def test_a_call_that_stayed_up_restarts_the_holdoff(clock):
    async def scenario():
        dialer, gateway = _dialer("486 Busy Here")
        for _ in range(3):
            with pytest.raises(RuntimeError, match="INVITE rejected"):
                await _dial(dialer)
            clock.now = dialer._dial_not_before

        gateway.status = "200 OK"
        call = await _dial(dialer)
        clock.now += intercom.DIAL_HOLDOFF_RESET_AFTER
        _gateway_hangs_up(dialer, call)
        assert dialer._dial_not_before - clock.now == intercom.DIAL_HOLDOFF_INITIAL

    asyncio.run(scenario())


def test_hanging_up_locally_does_not_delay_the_next_call(clock):
    async def scenario():
        dialer, gateway = _dialer()
        call = await _dial(dialer)
        dialer._finish_call(call.call_id, "local_bye")
        await _dial(dialer)
        assert gateway.invites == 2

    asyncio.run(scenario())
