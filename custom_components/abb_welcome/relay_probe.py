"""Measure how many devices the gateway serves early media for one ring.

The gateway relays a ringing station's audio and video to every device that
answers with early media, up to a limit we cannot read from outside (#52).
This probe registers extra contacts for the integration's own SIP account,
waits for one ring, answers it from each contact in turn and counts the
packets each one receives. The report shows where the gateway stops serving.

The probe only answers with 183. It never accepts the call, so the indoor
panel and the apps keep ringing.
"""

from __future__ import annotations

import asyncio
import re
import socket
import time
import uuid
from dataclasses import dataclass, field

from .intercom_dialer import USER_AGENT, parse_sdp
from .redaction import get_redacting_logger
from .sip_listener import (
    _build_ssl_context,
    _digest_response,
    _offered_video_size,
    _parse_challenge,
)

_LOGGER = get_redacting_logger(__name__)

# Each test changes one thing about the answers, so comparing two reports
# shows whether the gateway counts devices, lines, or lines per size.
TEST_SAME_SHORT = "same_size_short_answer"
TEST_SAME_FULL = "same_size_full_answer"
TEST_SPREAD = "one_size_each"
TEST_VIDEO_ONLY = "same_size_no_audio"
TESTS = (TEST_SAME_SHORT, TEST_SAME_FULL, TEST_SPREAD, TEST_VIDEO_ONLY)

DEFAULT_PROBES = 8
MAX_PROBES = 12
DEFAULT_WAIT_SECONDS = 300
MAX_WAIT_SECONDS = 900
FIRST_ANSWER_SECONDS = 1.5
ANSWER_INTERVAL_SECONDS = 2.5
# A ring that is never cancelled is reported after this long.
RING_LIMIT_SECONDS = 75
_REGISTER_EXPIRES = 120
_REGISTER_REFRESH = 60


@dataclass(frozen=True)
class ProbeAnswer:
    """Which offered lines one probe takes, and how it lists the rest."""

    accept: tuple[bool, ...]
    # False leaves rejected lines out of the answer, as the integration did
    # before v1.8.0-dev22. True lists them with port 0, as the SDP rules say.
    list_rejected: bool


def plan_answers(test: str, medias: list[str], probes: int) -> list[ProbeAnswer]:
    """Return the answer of each probe for an offer with these media kinds."""
    videos = [index for index, media in enumerate(medias) if media == "video"]
    audios = [index for index, media in enumerate(medias) if media == "audio"]
    if not videos:
        raise ValueError("the ring offered no video line")
    answers = []
    for probe in range(probes):
        video = videos[probe % len(videos)] if test == TEST_SPREAD else videos[0]
        taken = {video}
        if test != TEST_VIDEO_ONLY:
            taken.update(audios[:1])
        answers.append(
            ProbeAnswer(
                accept=tuple(index in taken for index in range(len(medias))),
                list_rejected=test != TEST_SAME_SHORT,
            )
        )
    return answers


def build_answer_sdp(
    offer_lines: list[tuple[str, str, str]],
    ports: list[int],
    *,
    list_rejected: bool,
    username: str,
    media_ip: str,
) -> str:
    """Answer an offer of ``(media, proto, formats)`` lines; port 0 rejects."""
    lines = [
        "v=0",
        f"o={username} 1 1 IN IP4 {media_ip}",
        "s=Talk",
        f"c=IN IP4 {media_ip}",
        "t=0 0",
    ]
    for (media, proto, formats), port in zip(offer_lines, ports):
        if port == 0 and not list_rejected:
            continue
        lines.append(f"m={media} {port} {proto} {formats}")
    return "\r\n".join(lines) + "\r\n"


@dataclass
class ProbeResult:
    number: int
    answered_after: float | None = None
    taken: list[str] = field(default_factory=list)
    listed_lines: int = 0
    packets: dict[str, int] = field(default_factory=dict)
    error: str = ""


def format_report(
    test: str, offered: list[str], results: list[ProbeResult], note: str
) -> str:
    """Render the result as a Markdown table that can be pasted into an issue."""
    rows = [
        f"Relay probe `{test}`: {note}",
        "",
        f"Offered: {', '.join(offered) if offered else 'nothing'}",
        "",
        "| Probe | Answered after | Lines in answer | Took | Packets received |",
        "|---|---|---|---|---|",
    ]
    for result in results:
        if result.error:
            rows.append(f"| {result.number} | - | - | - | {result.error} |")
            continue
        if result.answered_after is None:
            rows.append(f"| {result.number} | not answered | - | - | - |")
            continue
        packets = ", ".join(
            f"{line} {count}" for line, count in result.packets.items()
        )
        rows.append(
            f"| {result.number} | {result.answered_after:.1f} s | "
            f"{result.listed_lines} | {', '.join(result.taken)} | {packets} |"
        )
    return "\n".join(rows)


class _Frame:
    def __init__(self, start: str, headers: list[tuple[str, str]], body: bytes):
        self.start = start
        self.headers = headers
        self.body = body

    def header(self, name: str) -> str:
        return next((v for k, v in self.headers if k.lower() == name.lower()), "")

    def all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]

    @property
    def status(self) -> int | None:
        return int(self.start.split()[1]) if self.start.startswith("SIP/2.0") else None

    @property
    def method(self) -> str:
        return "" if self.status is not None else self.start.split()[0]


class _Counter(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.count = 0

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        self.count += 1


class _Probe:
    """One registered contact that answers the ring once and counts packets."""

    def __init__(self, owner: "RelayProbe", number: int) -> None:
        self.owner = owner
        self.result = ProbeResult(number)
        self.invite: _Frame | None = None
        self.cancelled = asyncio.Event()
        self._tag = uuid.uuid4().hex[:8]
        self._responses: asyncio.Queue[_Frame] = asyncio.Queue()
        self._counters: dict[str, _Counter] = {}
        self._transports: list[asyncio.DatagramTransport] = []
        self._writer: asyncio.StreamWriter | None = None
        self._tasks: list[asyncio.Task] = []
        self._ip = ""
        self._port = 0

    async def start(self) -> None:
        owner = self.owner
        ssl_ctx = _build_ssl_context() if owner.transport == "tls" else None
        reader, self._writer = await asyncio.open_connection(
            owner.host, owner.port, ssl=ssl_ctx
        )
        self._ip, self._port = self._writer.get_extra_info("sockname")[:2]
        self._tasks.append(asyncio.create_task(self._read(reader)))
        await self._register()
        self._tasks.append(asyncio.create_task(self._keep_registered()))

    async def close(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        for transport in self._transports:
            transport.close()
        if self._writer is not None:
            self._writer.close()

    def collect(self) -> None:
        self.result.packets = {
            line: counter.count for line, counter in self._counters.items()
        }

    async def _read(self, reader: asyncio.StreamReader) -> None:
        while True:
            raw = await reader.readuntil(b"\r\n\r\n")
            lines = raw.decode("utf-8", errors="replace").split("\r\n")
            if not lines[0]:
                continue
            headers = [
                (key.strip(), value.strip())
                for key, _, value in (line.partition(":") for line in lines[1:])
                if value
            ]
            frame = _Frame(lines[0], headers, b"")
            length = int(frame.header("Content-Length") or frame.header("l") or 0)
            if length:
                frame.body = await reader.readexactly(length)
            if frame.status is not None:
                self._responses.put_nowait(frame)
            else:
                await self._on_request(frame)

    def _send(self, start: str, headers: list[str], body: str = "") -> None:
        payload = body.encode("utf-8")
        head = "\r\n".join([start, *headers, f"Content-Length: {len(payload)}", "", ""])
        self._writer.write(head.encode("utf-8") + payload)

    def _respond(
        self, request: _Frame, code: int, reason: str, extra: list[str] = (), body: str = ""
    ) -> None:
        to_value = request.header("To")
        if code > 100 and ";tag=" not in to_value:
            to_value = f"{to_value};tag={self._tag}"
        headers = [f"Via: {via}" for via in request.all("Via")]
        if request.method == "INVITE" and 100 < code < 300:
            headers += [f"Record-Route: {r}" for r in request.all("Record-Route")]
        headers += [
            f"From: {request.header('From')}",
            f"To: {to_value}",
            f"Call-ID: {request.header('Call-ID')}",
            f"CSeq: {request.header('CSeq')}",
            f"User-Agent: {USER_AGENT}",
            *extra,
        ]
        self._send(f"SIP/2.0 {code} {reason}", headers, body)

    async def _register(self) -> None:
        owner = self.owner
        tparam = ";transport=tls" if owner.transport == "tls" else ""
        uri = f"sip:{owner.domain}{tparam}"
        identity = f"<sip:{owner.username}@{owner.domain}{tparam}>"
        call_id = uuid.uuid4().hex[:16]
        authorization = ""
        for cseq in (1, 2):
            headers = [
                f"Via: SIP/2.0/{owner.transport.upper()} {self._ip}:{self._port};"
                f"branch=z9hG4bK-{uuid.uuid4().hex[:12]};rport",
                "Max-Forwards: 70",
                f"From: {identity};tag={self._tag}",
                f"To: {identity}",
                f"Call-ID: {call_id}",
                f"CSeq: {cseq} REGISTER",
                f"Contact: <sip:{owner.username}@{self._ip}:{self._port};"
                f"transport={owner.transport}>",
                f"Expires: {_REGISTER_EXPIRES}",
                f"User-Agent: {USER_AGENT}",
            ]
            if authorization:
                headers.append(f"Authorization: {authorization}")
            self._send(f"REGISTER {uri} SIP/2.0", headers)
            while True:
                frame = await asyncio.wait_for(self._responses.get(), 10)
                if frame.header("Call-ID") == call_id and frame.status >= 200:
                    break
            if frame.status == 401 and not authorization:
                challenge = frame.header("WWW-Authenticate")
                authorization = _digest_response(
                    owner.username,
                    owner.password,
                    "REGISTER",
                    uri,
                    _parse_challenge(challenge[len("Digest"):].strip()),
                )
                continue
            if frame.status != 200:
                raise RuntimeError(f"REGISTER refused with {frame.status}")
            return

    async def _keep_registered(self) -> None:
        while self.invite is None:
            await asyncio.sleep(_REGISTER_REFRESH)
            if self.invite is None:
                await self._register()

    async def _on_request(self, frame: _Frame) -> None:
        if frame.method == "INVITE":
            if self.invite is not None:
                self._respond(frame, 486, "Busy Here")
                return
            self.invite = frame
            self._respond(frame, 100, "Trying")
            self.owner.ring_seen(frame)
            self._tasks.append(asyncio.create_task(self._answer()))
        elif frame.method == "CANCEL":
            self._respond(frame, 200, "OK")
            if self.invite is not None:
                self._respond(self.invite, 487, "Request Terminated")
            self.cancelled.set()
        elif frame.method != "ACK":
            self._respond(frame, 200, "OK")

    async def _answer(self) -> None:
        owner = self.owner
        number = self.result.number
        await asyncio.sleep(
            FIRST_ANSWER_SECONDS + ANSWER_INTERVAL_SECONDS * (number - 1)
        )
        try:
            offer = parse_sdp(self.invite.body)
            medias = [desc.media for desc in offer.medias]
            answer = plan_answers(owner.test, medias, owner.probes)[number - 1]
            loop = asyncio.get_running_loop()
            ports = []
            offer_lines = []
            for desc, accepted in zip(offer.medias, answer.accept):
                offer_lines.append(
                    (desc.media, desc.proto, " ".join(map(str, desc.payload_types)))
                )
                if not accepted:
                    ports.append(0)
                    continue
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((self._ip, 0))
                counter = _Counter()
                transport, _ = await loop.create_datagram_endpoint(
                    lambda counter=counter: counter, sock=sock
                )
                self._transports.append(transport)
                label = "audio" if desc.media == "audio" else (
                    _offered_video_size(desc) or "video"
                )
                self._counters[label] = counter
                ports.append(sock.getsockname()[1])
            body = build_answer_sdp(
                offer_lines,
                ports,
                list_rejected=answer.list_rejected,
                username=owner.username,
                media_ip=self._ip,
            )
            self.result.taken = list(self._counters)
            self.result.listed_lines = body.count("\r\nm=")
            self._respond(
                self.invite,
                183,
                "Session Progress",
                [
                    f"Contact: <sip:{owner.username}@{self._ip}:{self._port};"
                    f"transport={owner.transport}>",
                    "Content-Type: application/sdp",
                ],
                body,
            )
            self.result.answered_after = time.monotonic() - owner.ring_started
        except (ValueError, OSError) as err:
            self.result.error = f"could not answer: {err}"


class RelayProbe:
    """Register the probes, wait for one ring and report what each received."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        domain: str,
        *,
        test: str,
        probes: int = DEFAULT_PROBES,
        wait: float = DEFAULT_WAIT_SECONDS,
        port: int = 5061,
        transport: str = "tls",
    ) -> None:
        if test not in TESTS:
            raise ValueError(f"unknown test {test!r}")
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.test = test
        self.probes = probes
        self.wait = wait
        self.port = port
        self.transport = transport
        self.ring_started = 0.0
        self._ring = asyncio.Event()
        self._offered: list[str] = []

    def ring_seen(self, invite: _Frame) -> None:
        if self._ring.is_set():
            return
        self.ring_started = time.monotonic()
        offer = parse_sdp(invite.body)
        self._offered = [
            "audio" if desc.media == "audio" else (_offered_video_size(desc) or "video")
            for desc in offer.medias
        ]
        self._ring.set()

    async def run(self) -> str:
        probes = [_Probe(self, number) for number in range(1, self.probes + 1)]
        try:
            for probe in probes:
                try:
                    await probe.start()
                except (OSError, RuntimeError, asyncio.TimeoutError) as err:
                    probe.result.error = f"could not register: {err}"
            ready = [probe for probe in probes if not probe.result.error]
            if not ready:
                return format_report(
                    self.test, [], [p.result for p in probes], "no probe registered"
                )
            try:
                await asyncio.wait_for(self._ring.wait(), self.wait)
            except asyncio.TimeoutError:
                return f"Relay probe `{self.test}`: no ring arrived within {int(self.wait)} s"
            ended = [
                asyncio.create_task(probe.cancelled.wait())
                for probe in ready
                if probe.invite is not None
            ]
            done, pending = await asyncio.wait(
                ended, timeout=RING_LIMIT_SECONDS, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            # Let the other probes see their own CANCEL before the sockets close.
            await asyncio.sleep(1)
            length = time.monotonic() - self.ring_started
            for probe in probes:
                probe.collect()
            return format_report(
                self.test,
                self._offered,
                [p.result for p in probes],
                f"ring ended after {length:.0f} s"
                if done
                else f"ring still open after {length:.0f} s",
            )
        finally:
            for probe in probes:
                await probe.close()


_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def scrub(report: str) -> str:
    """Drop addresses that an error text may carry before the report is shown."""
    return _IP_RE.sub("<address>", report)
