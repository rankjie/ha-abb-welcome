"""The relay probe answers one ring from several contacts and counts media."""

from __future__ import annotations

import asyncio
import importlib.util
import re
import socket
import sys
import types
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"
_PACKAGE = "abb_relay_probe_test"
package = types.ModuleType(_PACKAGE)
package.__path__ = [str(_PKG_DIR)]
sys.modules[_PACKAGE] = package


def _load(name):
    full_name = f"{_PACKAGE}.{name}"
    spec = importlib.util.spec_from_file_location(full_name, _PKG_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


for _name in ("const", "redaction", "intercom_dialer", "sip_listener"):
    _load(_name)
probe = _load("relay_probe")

_MEDIAS = ["audio", "video", "video", "video", "video"]
_OFFER = (
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
    "m=audio 50644 RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\n"
    + "".join(
        f"m=video {port} RTP/AVP 102\r\na=rtpmap:102 H264/90000\r\n"
        f"a=fmtp:102 max-fr=30;max-width={width};max-height={height}\r\n"
        for port, width, height in (
            (50646, 352, 288),
            (50648, 640, 480),
            (50650, 1024, 600),
            (50652, 1280, 720),
        )
    )
)


def _taken(answer):
    return [index for index, accepted in enumerate(answer.accept) if accepted]


def test_same_size_tests_put_every_probe_on_the_first_video_line():
    short = probe.plan_answers(probe.TEST_SAME_SHORT, _MEDIAS, 3)
    full = probe.plan_answers(probe.TEST_SAME_FULL, _MEDIAS, 3)
    assert [_taken(answer) for answer in short] == [[0, 1]] * 3
    assert [_taken(answer) for answer in full] == [[0, 1]] * 3
    assert not any(answer.list_rejected for answer in short)
    assert all(answer.list_rejected for answer in full)


def test_one_size_each_cycles_through_the_offered_sizes():
    answers = probe.plan_answers(probe.TEST_SPREAD, _MEDIAS, 6)
    assert [_taken(answer) for answer in answers] == [
        [0, 1], [0, 2], [0, 3], [0, 4], [0, 1], [0, 2],
    ]


def test_no_audio_test_takes_only_the_video_line():
    (answer,) = probe.plan_answers(probe.TEST_VIDEO_ONLY, _MEDIAS, 1)
    assert _taken(answer) == [1]
    assert answer.list_rejected


def test_an_offer_without_video_is_refused():
    with pytest.raises(ValueError):
        probe.plan_answers(probe.TEST_SPREAD, ["audio"], 2)


def test_rejected_lines_are_listed_with_port_zero_or_left_out():
    offer_lines = [("audio", "RTP/AVP", "8 101"), ("video", "RTP/AVP", "102"), ("video", "RTP/AVP", "102")]
    kwargs = {"username": "ha", "media_ip": "192.0.2.2"}
    full = probe.build_answer_sdp(offer_lines, [40000, 0, 40002], list_rejected=True, **kwargs)
    short = probe.build_answer_sdp(offer_lines, [40000, 40002, 0], list_rejected=False, **kwargs)
    assert [line for line in full.splitlines() if line.startswith("m=")] == [
        "m=audio 40000 RTP/AVP 8 101",
        "m=video 0 RTP/AVP 102",
        "m=video 40002 RTP/AVP 102",
    ]
    assert [line for line in short.splitlines() if line.startswith("m=")] == [
        "m=audio 40000 RTP/AVP 8 101",
        "m=video 40002 RTP/AVP 102",
    ]


class _FakeGateway:
    """Accepts REGISTER, rings every contact and serves media to the first two."""

    def __init__(self):
        self.writers = []
        self.answers = {}
        self.registered = asyncio.Event()
        self.expected = 0

    async def handle(self, reader, writer):
        number = len(self.writers)
        self.writers.append(writer)
        while True:
            try:
                head = (await reader.readuntil(b"\r\n\r\n")).decode()
            except (asyncio.IncompleteReadError, ConnectionError):
                return
            length = int(re.search(r"Content-Length: (\d+)", head).group(1))
            body = (await reader.readexactly(length)).decode() if length else ""
            start = head.split("\r\n")[0]
            if start.startswith("REGISTER"):
                echo = "\r\n".join(
                    line for line in head.split("\r\n")[1:]
                    if line.split(":")[0] in ("Via", "From", "To", "Call-ID", "CSeq")
                )
                writer.write(f"SIP/2.0 200 OK\r\n{echo}\r\nContent-Length: 0\r\n\r\n".encode())
                if len(self.writers) == self.expected:
                    self.registered.set()
            elif start.startswith("SIP/2.0 183"):
                self.answers[number] = body

    def ring(self):
        for number, writer in enumerate(self.writers):
            writer.write(
                (
                    "INVITE sip:ha@example.invalid SIP/2.0\r\n"
                    f"Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bK-{number}\r\n"
                    "From: <sip:100000001@example.invalid>;tag=caller\r\n"
                    "To: <sip:ha@example.invalid>\r\n"
                    "Call-ID: ring-1\r\nCSeq: 1 INVITE\r\n"
                    "Content-Type: application/sdp\r\n"
                    f"Content-Length: {len(_OFFER)}\r\n\r\n{_OFFER}"
                ).encode()
            )

    def cancel(self):
        for number, writer in enumerate(self.writers):
            writer.write(
                (
                    "CANCEL sip:ha@example.invalid SIP/2.0\r\n"
                    f"Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bK-{number}\r\n"
                    "From: <sip:100000001@example.invalid>;tag=caller\r\n"
                    "To: <sip:ha@example.invalid>\r\n"
                    "Call-ID: ring-1\r\nCSeq: 1 CANCEL\r\nContent-Length: 0\r\n\r\n"
                ).encode()
            )


def test_report_shows_which_probes_the_gateway_served(monkeypatch):
    monkeypatch.setattr(probe, "FIRST_ANSWER_SECONDS", 0.05)
    monkeypatch.setattr(probe, "ANSWER_INTERVAL_SECONDS", 0.05)

    async def scenario():
        gateway = _FakeGateway()
        gateway.expected = 3
        server = await asyncio.start_server(gateway.handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        run = asyncio.create_task(
            probe.RelayProbe(
                "127.0.0.1", "ha", "secret", "example.invalid",
                test=probe.TEST_SAME_FULL, probes=3, wait=5, port=port, transport="tcp",
            ).run()
        )
        await asyncio.wait_for(gateway.registered.wait(), 5)
        gateway.ring()
        while len(gateway.answers) < 3:
            await asyncio.sleep(0.02)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for number in (0, 1):
            ports = [int(p) for p in re.findall(r"m=\w+ (\d+)", gateway.answers[number])]
            assert [bool(p) for p in ports] == [True, True, False, False, False]
            for _ in range(4):
                sender.sendto(b"\x80" + bytes(20), ("127.0.0.1", ports[1]))
        sender.close()
        await asyncio.sleep(0.1)
        gateway.cancel()
        report = await asyncio.wait_for(run, 10)
        server.close()
        return report

    report = asyncio.run(scenario())
    rows = [line for line in report.splitlines() if re.match(r"\| \d", line)]
    assert "Offered: audio, 352x288, 640x480, 1024x600, 1280x720" in report
    assert [row.split("|")[5].strip() for row in rows] == [
        "audio 0, 352x288 4",
        "audio 0, 352x288 4",
        "audio 0, 352x288 0",
    ]
    assert all(row.split("|")[3].strip() == "5" for row in rows)


def test_no_ring_is_reported(monkeypatch):
    async def scenario():
        gateway = _FakeGateway()
        server = await asyncio.start_server(gateway.handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        report = await probe.RelayProbe(
            "127.0.0.1", "ha", "secret", "example.invalid",
            test=probe.TEST_SPREAD, probes=1, wait=0.2, port=port, transport="tcp",
        ).run()
        server.close()
        return report

    assert "no ring arrived" in asyncio.run(scenario())
