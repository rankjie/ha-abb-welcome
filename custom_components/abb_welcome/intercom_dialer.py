"""Async SIP dialer for outbound surveillance/intercom calls.

This is the *outgoing* counterpart to :mod:`sip_listener`: opens a TLS
connection to the gateway, REGISTERs once, then on demand sends an
INVITE to a chosen outdoor-station SIP URI advertising local UDP RTP
ports.  After the gateway answers 200 OK we ACK and the dialog is
established; ``hangup()`` sends BYE.

Adapted from the standalone prototype (intercom_prototype/backend/sip.py)
to run as a regular asyncio task inside HA.  Single connection per
``IntercomDialer`` instance — one dialer per integration entry is enough.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import socket
import ssl
import time
import uuid
import warnings
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

_LOGGER = logging.getLogger(__name__)

USER_AGENT = "ABB-Welcome-HA-Dialer/1.0"
DEFAULT_REGISTER_EXPIRES = 600


@dataclass
class SipFrame:
    start_line: str
    headers: list[tuple[str, str]]
    body: bytes
    raw: bytes

    @property
    def is_response(self) -> bool:
        return self.start_line.startswith("SIP/2.0 ")

    @property
    def status_code(self) -> int | None:
        if not self.is_response:
            return None
        try:
            return int(self.start_line.split()[1])
        except (IndexError, ValueError):
            return None

    @property
    def method(self) -> str:
        if self.is_response:
            return ""
        return self.start_line.split(" ", 1)[0].upper()

    def header(self, name: str) -> str:
        wanted = name.lower()
        for k, v in self.headers:
            if k.lower() == wanted:
                return v
        return ""

    def all_headers(self, name: str) -> list[str]:
        wanted = name.lower()
        return [v for k, v in self.headers if k.lower() == wanted]


def _parse_headers(raw: bytes) -> tuple[str, list[tuple[str, str]]]:
    text = raw.decode("utf-8", errors="replace")
    lines = text.split("\r\n")
    start = lines[0]
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers.append((k.strip(), v.strip()))
    return start, headers


async def _read_frame(reader: asyncio.StreamReader) -> SipFrame:
    head = await reader.readuntil(b"\r\n\r\n")
    start, headers = _parse_headers(head[:-4])
    cl = re.search(rb"Content-Length:\s*(\d+)", head, re.IGNORECASE)
    body = b""
    if cl:
        n = int(cl.group(1))
        if n:
            body = await reader.readexactly(n)
    return SipFrame(start_line=start, headers=headers, body=body, raw=head + body)


def _parse_challenge(value: str) -> dict[str, str]:
    if value.lower().startswith("digest"):
        value = value[len("digest"):].strip()
    out: dict[str, str] = {}
    for m in re.finditer(r'(\w+)\s*=\s*"?([^",]+)"?', value):
        out[m.group(1)] = m.group(2)
    return out


def _digest(
    username: str, password: str, method: str, uri: str, c: dict[str, str]
) -> str:
    realm = c["realm"]
    nonce = c["nonce"]
    qop = c.get("qop", "auth")
    opaque = c.get("opaque", "")
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    nc = "00000001"
    cnonce = uuid.uuid4().hex[:8]
    response = hashlib.md5(
        f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()
    ).hexdigest()
    parts = [
        f'Digest username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
        "algorithm=MD5",
        f'cnonce="{cnonce}"',
        f"qop={qop}",
        f"nc={nc}",
    ]
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return ", ".join(parts)


@dataclass
class MediaDescription:
    media: str
    port: int
    proto: str
    payload_types: list[int] = field(default_factory=list)
    connection_ip: str = ""
    rtpmap: dict[int, str] = field(default_factory=dict)


@dataclass
class ParsedSdp:
    session_ip: str = ""
    medias: list[MediaDescription] = field(default_factory=list)


def parse_sdp(body: bytes | str) -> ParsedSdp:
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    sdp = ParsedSdp()
    current: MediaDescription | None = None
    for line in text.splitlines():
        if line.startswith("c=") and "IN IP4" in line:
            ip = line.split("IN IP4", 1)[1].strip().split()[0]
            if current is None:
                sdp.session_ip = ip
            else:
                current.connection_ip = ip
        elif line.startswith("m="):
            parts = line[2:].split()
            if len(parts) < 4:
                continue
            current = MediaDescription(
                media=parts[0],
                port=int(parts[1]),
                proto=parts[2],
                payload_types=[int(p) for p in parts[3:] if p.isdigit()],
                connection_ip=sdp.session_ip,
            )
            sdp.medias.append(current)
        elif current is not None and line.startswith("a=rtpmap:"):
            rest = line[len("a=rtpmap:"):]
            try:
                pt_str, enc = rest.split(" ", 1)
                current.rtpmap[int(pt_str)] = enc.strip()
            except ValueError:
                continue
    return sdp


@dataclass
class Door:
    name: str
    address: str
    station_id: str = ""


@dataclass
class CallState:
    door: Door
    call_id: str
    local_tag: str
    remote_tag: str
    invite_cseq: int
    request_uri: str
    remote_contact: str
    audio_local_port: int
    video_local_port: int
    answer: ParsedSdp


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "TLSVersion"):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
        ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
    return ctx


def _build_offer_sdp(media_ip: str, audio_port: int, video_port: int) -> str:
    sid = int(time.time() * 1000)
    return "\r\n".join(
        [
            "v=0",
            f"o=- {sid} 1 IN IP4 {media_ip}",
            "s=ABB Welcome HA",
            f"c=IN IP4 {media_ip}",
            "t=0 0",
            f"m=audio {audio_port} RTP/AVP 0 8 101",
            "a=rtpmap:0 PCMU/8000",
            "a=rtpmap:8 PCMA/8000",
            "a=rtpmap:101 telephone-event/8000",
            "a=fmtp:101 0-16",
            "a=sendrecv",
            f"m=video {video_port} RTP/AVP 96",
            "a=rtpmap:96 H264/90000",
            "a=sendrecv",
            "",
        ]
    )


class IntercomDialer:
    """Single-connection async SIP dialer for the outgoing surveillance path."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        domain: str,
        port: int = 5061,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.port = port

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._local_ip: str = ""
        self._local_port: int = 0
        self._media_ip: str = ""
        self._cseq: int = 0
        self._call: CallState | None = None
        self._registered = False
        self._reader_task: asyncio.Task | None = None
        self._inbound_queue: asyncio.Queue[SipFrame] = asyncio.Queue()
        self._lock = asyncio.Lock()

    @property
    def media_ip(self) -> str:
        return self._media_ip or self._local_ip

    @property
    def in_call(self) -> bool:
        return self._call is not None

    async def ensure_connected(self) -> None:
        async with self._lock:
            if self._writer is not None and self._registered:
                return
            await self._connect_locked()

    async def _connect_locked(self) -> None:
        reader, writer = await asyncio.open_connection(
            self.host, self.port, ssl=_ssl_context()
        )
        self._reader = reader
        self._writer = writer
        sock = writer.get_extra_info("socket")
        self._local_ip, self._local_port = sock.getsockname()[:2]

        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect((self.host, 9))
            self._media_ip = probe.getsockname()[0]
        except OSError:
            self._media_ip = self._local_ip
        finally:
            probe.close()

        self._cseq = 1
        self._reader_task = asyncio.create_task(
            self._reader_loop(), name="abb_welcome_dialer_reader"
        )
        try:
            await self._register(DEFAULT_REGISTER_EXPIRES)
            self._registered = True
        except Exception:
            self._reader_task.cancel()
            raise

    async def close(self) -> None:
        async with self._lock:
            if self._call is not None:
                try:
                    await self._hangup_locked()
                except Exception as err:  # noqa: BLE001
                    _LOGGER.debug("hangup during close failed: %s", err)
            if self._writer is not None:
                if self._registered:
                    try:
                        await asyncio.wait_for(self._register(0), timeout=2.0)
                    except Exception:  # noqa: BLE001
                        pass
                try:
                    self._writer.close()
                    await self._writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
            self._reader = None
            self._writer = None
            self._registered = False
            if self._reader_task is not None:
                self._reader_task.cancel()
                try:
                    await self._reader_task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
                self._reader_task = None

    async def _reader_loop(self) -> None:
        assert self._reader is not None
        try:
            while True:
                frame = await _read_frame(self._reader)
                if not frame.is_response:
                    if frame.method in ("OPTIONS", "NOTIFY", "MESSAGE"):
                        await self._send_response(frame, 200, "OK")
                        continue
                    if frame.method == "BYE":
                        await self._send_response(frame, 200, "OK")
                        self._call = None
                        continue
                await self._inbound_queue.put(frame)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            return
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("dialer reader exited: %s", err)

    async def _await_response(
        self, predicate: Callable[[SipFrame], bool], timeout: float
    ) -> SipFrame:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError("dialer SIP response timeout")
            frame = await asyncio.wait_for(
                self._inbound_queue.get(), timeout=remaining
            )
            if predicate(frame):
                return frame

    async def _send_request(
        self, method: str, uri: str, headers: list[str], body: str = ""
    ) -> None:
        assert self._writer is not None
        body_bytes = body.encode("utf-8")
        lines = [
            f"{method} {uri} SIP/2.0",
            *headers,
            f"Content-Length: {len(body_bytes)}",
            "",
            body,
        ]
        self._writer.write("\r\n".join(lines).encode("utf-8"))
        await self._writer.drain()

    async def _send_response(self, frame: SipFrame, code: int, reason: str) -> None:
        assert self._writer is not None
        lines = [f"SIP/2.0 {code} {reason}"]
        for via in frame.all_headers("Via"):
            lines.append(f"Via: {via}")
        for name in ("From", "To", "Call-ID", "CSeq"):
            v = frame.header(name)
            lines.append(f"{name}: {v}")
        lines.append(f"User-Agent: {USER_AGENT}")
        lines.append("Content-Length: 0")
        lines.append("")
        lines.append("")
        self._writer.write("\r\n".join(lines).encode("utf-8"))
        await self._writer.drain()

    async def _register(self, expires: int) -> None:
        tparam = ";transport=tls"
        reg_uri = f"sip:{self.domain}{tparam}"
        from_tag = uuid.uuid4().hex[:8]
        call_id = uuid.uuid4().hex[:16] + "@" + self.domain
        contact = (
            f"<sip:{self.username}@{self._local_ip}:{self._local_port};transport=tls>"
        )
        branch = "z9hG4bK-" + uuid.uuid4().hex[:12]

        cseq = self._cseq
        headers = [
            f"Via: SIP/2.0/TLS {self._local_ip}:{self._local_port};branch={branch};rport",
            "Max-Forwards: 70",
            f"From: <sip:{self.username}@{self.domain}{tparam}>;tag={from_tag}",
            f"To: <sip:{self.username}@{self.domain}{tparam}>",
            f"Call-ID: {call_id}",
            f"CSeq: {cseq} REGISTER",
            f"Contact: {contact}",
            f"Expires: {expires}",
            f"User-Agent: {USER_AGENT}",
        ]
        await self._send_request("REGISTER", reg_uri, headers)
        frame = await self._await_response(
            lambda f: f.is_response and f.header("CSeq").endswith("REGISTER"),
            timeout=10.0,
        )
        if frame.status_code == 401:
            challenge = _parse_challenge(frame.header("WWW-Authenticate"))
            self._cseq += 1
            cseq = self._cseq
            auth = _digest(self.username, self.password, "REGISTER", reg_uri, challenge)
            new_branch = "z9hG4bK-" + uuid.uuid4().hex[:12]
            headers[0] = f"Via: SIP/2.0/TLS {self._local_ip}:{self._local_port};branch={new_branch};rport"
            headers[5] = f"CSeq: {cseq} REGISTER"
            headers.append(f"Authorization: {auth}")
            await self._send_request("REGISTER", reg_uri, headers)
            frame = await self._await_response(
                lambda f: f.is_response and f.header("CSeq").endswith("REGISTER"),
                timeout=10.0,
            )
        if frame.status_code != 200:
            raise RuntimeError(f"REGISTER failed: {frame.start_line}")
        self._cseq += 1

    async def dial(self, door: Door, *, audio_port: int, video_port: int) -> CallState:
        await self.ensure_connected()
        async with self._lock:
            if self._call is not None:
                raise RuntimeError("a call is already active; hangup() first")
            return await self._dial_locked(door, audio_port, video_port)

    async def _dial_locked(
        self, door: Door, audio_port: int, video_port: int
    ) -> CallState:
        request_uri = door.address
        local_tag = uuid.uuid4().hex[:8]
        call_id = uuid.uuid4().hex[:16] + "@" + self.domain
        invite_branch = "z9hG4bK-" + uuid.uuid4().hex[:12]
        from_header = f"<sip:{self.username}@{self.domain};transport=tls>"
        to_header = f"<{request_uri}>"
        local_contact = f"<sip:{self.username}@{self._local_ip}:{self._local_port};transport=tls>"

        sdp = _build_offer_sdp(self.media_ip, audio_port, video_port)
        invite_cseq = self._cseq
        headers = [
            f"Via: SIP/2.0/TLS {self._local_ip}:{self._local_port};branch={invite_branch};rport",
            "Max-Forwards: 70",
            f"From: {from_header};tag={local_tag}",
            f"To: {to_header}",
            f"Call-ID: {call_id}",
            f"CSeq: {invite_cseq} INVITE",
            f"Contact: {local_contact}",
            f"User-Agent: {USER_AGENT}",
            "Allow: INVITE, ACK, CANCEL, BYE, MESSAGE, OPTIONS",
            "Accept: application/sdp",
            "Content-Type: application/sdp",
        ]
        await self._send_request("INVITE", request_uri, headers, sdp)

        frame = await self._await_response(
            lambda f: f.is_response and f.header("CSeq").endswith("INVITE") and f.header("Call-ID") == call_id,
            timeout=15.0,
        )

        if frame.status_code in (401, 407):
            self._cseq += 1
            invite_cseq = self._cseq
            challenge_hdr = "Proxy-Authenticate" if frame.status_code == 407 else "WWW-Authenticate"
            auth_hdr = "Proxy-Authorization" if frame.status_code == 407 else "Authorization"
            challenge = _parse_challenge(frame.header(challenge_hdr))
            auth = _digest(self.username, self.password, "INVITE", request_uri, challenge)
            new_branch = "z9hG4bK-" + uuid.uuid4().hex[:12]
            headers = [h for h in headers if not h.startswith("Authorization:") and not h.startswith("Proxy-Authorization:")]
            headers[0] = f"Via: SIP/2.0/TLS {self._local_ip}:{self._local_port};branch={new_branch};rport"
            headers[5] = f"CSeq: {invite_cseq} INVITE"
            headers.append(f"{auth_hdr}: {auth}")
            invite_branch = new_branch
            await self._send_request("INVITE", request_uri, headers, sdp)
            frame = await self._await_response(
                lambda f: f.is_response and f.header("CSeq").endswith("INVITE") and f.header("Call-ID") == call_id,
                timeout=15.0,
            )

        while frame.is_response and 100 <= (frame.status_code or 0) < 200:
            frame = await self._await_response(
                lambda f: f.is_response and f.header("CSeq").endswith("INVITE") and f.header("Call-ID") == call_id,
                timeout=15.0,
            )

        if frame.status_code != 200:
            raise RuntimeError(f"INVITE rejected: {frame.start_line}")

        remote_to = frame.header("To")
        m = re.search(r"tag=([^;>]+)", remote_to)
        remote_tag = m.group(1) if m else ""
        remote_contact_raw = frame.header("Contact")
        cm = re.search(r"<([^>]+)>", remote_contact_raw)
        remote_contact = cm.group(1) if cm else remote_contact_raw

        ack_branch = "z9hG4bK-" + uuid.uuid4().hex[:12]
        ack_headers = [
            f"Via: SIP/2.0/TLS {self._local_ip}:{self._local_port};branch={ack_branch};rport",
            "Max-Forwards: 70",
            f"From: {from_header};tag={local_tag}",
            f"To: {remote_to}",
            f"Call-ID: {call_id}",
            f"CSeq: {invite_cseq} ACK",
            f"Contact: {local_contact}",
            f"User-Agent: {USER_AGENT}",
        ]
        await self._send_request("ACK", request_uri, ack_headers)

        try:
            answer = parse_sdp(frame.body)
            self._call = CallState(
                door=door,
                call_id=call_id,
                local_tag=local_tag,
                remote_tag=remote_tag,
                invite_cseq=invite_cseq,
                request_uri=request_uri,
                remote_contact=remote_contact,
                audio_local_port=audio_port,
                video_local_port=video_port,
                answer=answer,
            )
            self._cseq += 1
            return self._call
        except Exception as err:
            _LOGGER.error("post-2xx setup failed (%s); sending best-effort BYE", err)
            await self._best_effort_bye(
                request_uri, remote_contact, call_id, local_tag,
                remote_tag, from_header, local_contact,
            )
            raise

    async def _best_effort_bye(
        self, request_uri: str, remote_contact: str, call_id: str,
        local_tag: str, remote_tag: str, from_header: str, local_contact: str,
    ) -> None:
        if self._writer is None:
            return
        bye_branch = "z9hG4bK-" + uuid.uuid4().hex[:12]
        target = remote_contact or request_uri
        to_value = (
            f"<{request_uri}>;tag={remote_tag}" if remote_tag else f"<{request_uri}>"
        )
        headers = [
            f"Via: SIP/2.0/TLS {self._local_ip}:{self._local_port};branch={bye_branch};rport",
            "Max-Forwards: 70",
            f"From: {from_header};tag={local_tag}",
            f"To: {to_value}",
            f"Call-ID: {call_id}",
            f"CSeq: {self._cseq} BYE",
            f"Contact: {local_contact}",
            f"User-Agent: {USER_AGENT}",
        ]
        self._cseq += 1
        try:
            await self._send_request("BYE", target, headers)
            await asyncio.wait_for(
                self._await_response(
                    lambda f: f.is_response and f.header("CSeq").endswith("BYE") and f.header("Call-ID") == call_id,
                    timeout=3.0,
                ),
                timeout=3.0,
            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("best-effort BYE failed: %s", err)

    async def hangup(self) -> None:
        async with self._lock:
            await self._hangup_locked()

    async def _hangup_locked(self) -> None:
        if self._call is None or self._writer is None:
            return
        call = self._call
        bye_branch = "z9hG4bK-" + uuid.uuid4().hex[:12]
        target = call.remote_contact or call.request_uri
        to_value = (
            f"<{call.request_uri}>;tag={call.remote_tag}"
            if call.remote_tag
            else f"<{call.request_uri}>"
        )
        headers = [
            f"Via: SIP/2.0/TLS {self._local_ip}:{self._local_port};branch={bye_branch};rport",
            "Max-Forwards: 70",
            f"From: <sip:{self.username}@{self.domain};transport=tls>;tag={call.local_tag}",
            f"To: {to_value}",
            f"Call-ID: {call.call_id}",
            f"CSeq: {self._cseq} BYE",
            f"Contact: <sip:{self.username}@{self._local_ip}:{self._local_port};transport=tls>",
            f"User-Agent: {USER_AGENT}",
        ]
        await self._send_request("BYE", target, headers)
        self._cseq += 1
        try:
            await self._await_response(
                lambda f: f.is_response and f.header("CSeq").endswith("BYE") and f.header("Call-ID") == call.call_id,
                timeout=5.0,
            )
        except asyncio.TimeoutError:
            pass
        self._call = None
