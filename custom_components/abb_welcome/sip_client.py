"""Hybrid SIP client for ABB Welcome door unlock.

- First outdoor station keeps the fast TCP MESSAGE path.
- Other stations use the MRANGE invite-then-unlock flow.

This module also tolerates old config-entry door payloads where every door
stored the first station address and encoded the real target in a `b:<station>`
body.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import logging
import re
import socket
import ssl
import time
import uuid
import warnings

_LOGGER = logging.getLogger(__name__)

FAST_TCP_PORT = 5060
INVITE_TLS_PORT = 5061
DEFAULT_INVITE_TRANSPORT = "tls"
DEFAULT_INVITE_TIMEOUT = 2.5
DEFAULT_UNLOCK_DELAY = 0.0


@dataclass(frozen=True)
class DoorSpec:
    """Normalized door target."""

    name: str
    station_id: str
    address: str
    unlock_body: str
    index: int | None


@dataclass(frozen=True)
class GatewayConfig:
    """Socket transport config."""

    sip_domain: str
    gw_host: str
    gw_port: int
    transport: str


@dataclass
class SipFrame:
    """Parsed SIP message."""

    start_line: str
    headers: list[tuple[str, str]]
    body: bytes

    def is_response(self) -> bool:
        return self.start_line.startswith("SIP/2.0 ")

    def status_code(self) -> int | None:
        if not self.is_response():
            return None
        parts = self.start_line.split()
        if len(parts) < 2:
            return None
        try:
            return int(parts[1])
        except ValueError:
            return None

    def header(self, name: str) -> str:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return ""


@dataclass
class InviteSession:
    """Active or early invite session."""

    target_uri: str
    request_uri: str
    call_id: str
    from_header: str
    local_tag: str
    local_contact: str
    invite_cseq: int
    invite_branch: str
    remote_to: str
    established: bool = False
    remote_contact: str = ""
    audio_sock: socket.socket | None = None
    video_sock: socket.socket | None = None

    def close_media(self) -> None:
        for media_sock in (self.audio_sock, self.video_sock):
            if media_sock is None:
                continue
            try:
                media_sock.close()
            except OSError:
                pass


class SipStream:
    """Incremental SIP frame reader."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.leftover = b""

    def recv_frame(self) -> SipFrame:
        buf = self.leftover
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("socket closed while reading SIP headers")
            buf += chunk

        sep = buf.find(b"\r\n\r\n")
        header_bytes = buf[:sep]
        rest = buf[sep + 4 :]

        content_length = 0
        match = re.search(rb"Content-Length:\s*(\d+)", header_bytes, re.IGNORECASE)
        if match:
            content_length = int(match.group(1))

        while len(rest) < content_length:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("socket closed while reading SIP body")
            rest += chunk

        body = rest[:content_length]
        self.leftover = rest[content_length:]

        header_lines = header_bytes.decode("utf-8", errors="replace").split("\r\n")
        start_line = header_lines[0]
        headers: list[tuple[str, str]] = []
        for line in header_lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers.append((key.strip(), value.strip()))
        return SipFrame(start_line=start_line, headers=headers, body=body)

    def recv_final_response(self) -> SipFrame:
        while True:
            frame = self.recv_frame()
            if frame.is_response() and (frame.status_code() or 0) // 100 == 1:
                continue
            return frame


def _sip_request(method: str, uri: str, headers: list[str], body: str = "") -> bytes:
    body_bytes = body.encode("utf-8")
    lines = [
        f"{method} {uri} SIP/2.0",
        *headers,
        f"Content-Length: {len(body_bytes)}",
        "",
        body,
    ]
    return "\r\n".join(lines).encode("utf-8")


def _send_sip_response(
    sock: socket.socket, frame: SipFrame, code: int = 200, reason: str = "OK"
) -> None:
    lines = [f"SIP/2.0 {code} {reason}"]
    for header_name in ("Via", "From", "To", "Call-ID", "CSeq"):
        value = frame.header(header_name)
        if value:
            lines.append(f"{header_name}: {value}")
    lines.extend(("Content-Length: 0", "", ""))
    sock.sendall("\r\n".join(lines).encode("utf-8"))


def _parse_station_id_from_address(address: str) -> str:
    if not address:
        return ""
    value = address.strip().strip("<>")
    if value.startswith("sip:"):
        value = value[4:]
    value = value.split("@", 1)[0]
    value = value.split(";", 1)[0]
    return value


def _parse_station_id_from_legacy_body(body: str) -> str:
    body = body.strip()
    if body.startswith("b:"):
        return body.split(":", 1)[1].strip()
    return ""


def _normalize_unlock_body(body: str) -> str:
    body = body.strip()
    if not body:
        return "1"
    if body.startswith("b:"):
        return "1"
    return body


def _parse_contact_uri(value: str) -> str:
    match = re.search(r"<([^>]+)>", value)
    if match:
        return match.group(1)
    return value.strip()


def _digest_auth(
    username: str,
    password: str,
    method: str,
    uri: str,
    challenge_str: str,
    header_name: str,
) -> str:
    params = {}
    for match in re.finditer(r'(\w+)="?([^",$]+)"?', challenge_str):
        params[match.group(1)] = match.group(2)

    realm = params["realm"]
    nonce = params["nonce"]
    qop = params.get("qop", "auth")
    opaque = params.get("opaque", "")

    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    nc = "00000001"
    cnonce = uuid.uuid4().hex[:8]
    response = hashlib.md5(
        f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()
    ).hexdigest()

    header = (
        f'{header_name}: Digest username="{username}", realm="{realm}", '
        f'nonce="{nonce}", uri="{uri}", response="{response}", '
        f'algorithm=MD5, cnonce="{cnonce}", qop={qop}, nc={nc}'
    )
    if opaque:
        header += f', opaque="{opaque}"'
    return header


def _build_ssl_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    if hasattr(ssl, "TLSVersion"):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=DeprecationWarning)
            context.minimum_version = ssl.TLSVersion.TLSv1
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
        context.options |= ssl.OP_LEGACY_SERVER_CONNECT
    return context


def _build_socket(
    gw: GatewayConfig, timeout: float
) -> tuple[socket.socket, str, int]:
    if gw.transport == "tls":
        raw_sock = socket.create_connection((gw.gw_host, gw.gw_port), timeout=timeout)
        context = _build_ssl_context()
        sock = context.wrap_socket(raw_sock, server_hostname=None)
    else:
        sock = socket.create_connection((gw.gw_host, gw.gw_port), timeout=timeout)
    sock.settimeout(timeout)
    local_ip, local_port = sock.getsockname()[:2]
    return sock, local_ip, local_port


def _guess_media_ip(gw_host: str) -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((gw_host, 9))
        return probe.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        probe.close()


def _build_gateway_config(domain: str, host: str, transport: str) -> GatewayConfig:
    port = FAST_TCP_PORT if transport == "tcp" else INVITE_TLS_PORT
    return GatewayConfig(
        sip_domain=domain,
        gw_host=host,
        gw_port=port,
        transport=transport,
    )


def _register_client(
    stream: SipStream,
    local_ip: str,
    local_port: int,
    gw: GatewayConfig,
    sip_user: str,
    sip_pass: str,
) -> None:
    transport = gw.transport.upper()
    transport_param = f";transport={gw.transport}" if gw.transport == "tls" else ""
    reg_uri = f"sip:{gw.sip_domain}{transport_param}"
    from_tag = uuid.uuid4().hex[:8]
    call_id = uuid.uuid4().hex[:16] + "@" + gw.sip_domain
    branch = "z9hG4bK-" + uuid.uuid4().hex[:12]
    contact = f"<sip:{sip_user}@{local_ip}:{local_port};transport={gw.transport}>"

    headers = [
        f"Via: SIP/2.0/{transport} {local_ip}:{local_port};branch={branch};rport",
        "Max-Forwards: 70",
        f"From: <sip:{sip_user}@{gw.sip_domain}{transport_param}>;tag={from_tag}",
        f"To: <sip:{sip_user}@{gw.sip_domain}{transport_param}>",
        f"Call-ID: {call_id}",
        "CSeq: 1 REGISTER",
        f"Contact: {contact}",
        "Expires: 3600",
        "User-Agent: ABB-Welcome-HA/1.0",
    ]
    stream.sock.sendall(_sip_request("REGISTER", reg_uri, headers))
    response = stream.recv_final_response()

    raw_headers = "\r\n".join(
        [response.start_line, *(f"{k}: {v}" for k, v in response.headers)]
    )
    challenge = re.search(
        r"WWW-Authenticate:\s*Digest\s+(.*?)(?:\r\n(?!\s)|$)",
        raw_headers,
        re.DOTALL,
    )
    if challenge:
        auth = _digest_auth(
            sip_user,
            sip_pass,
            "REGISTER",
            reg_uri,
            challenge.group(1),
            "Authorization",
        )
        headers[0] = (
            f"Via: SIP/2.0/{transport} {local_ip}:{local_port};"
            f"branch=z9hG4bK-{uuid.uuid4().hex[:12]};rport"
        )
        headers[5] = "CSeq: 2 REGISTER"
        headers.append(auth)
        stream.sock.sendall(_sip_request("REGISTER", reg_uri, headers))
        response = stream.recv_final_response()

    if response.status_code() != 200:
        raise RuntimeError(f"REGISTER failed: {response.start_line}")


def _maybe_auth_resend(
    stream: SipStream,
    response: SipFrame,
    method: str,
    uri: str,
    headers: list[str],
    body: str,
    sip_user: str,
    sip_pass: str,
    transport: str,
    local_ip: str,
    local_port: int,
    cseq_index: int,
) -> tuple[SipFrame, list[str]]:
    raw_headers = "\r\n".join(
        [response.start_line, *(f"{k}: {v}" for k, v in response.headers)]
    )
    if response.status_code() == 407:
        challenge_re = r"Proxy-Authenticate:\s*Digest\s+(.*?)(?:\r\n(?!\s)|$)"
        auth_name = "Proxy-Authorization"
    elif response.status_code() == 401:
        challenge_re = r"WWW-Authenticate:\s*Digest\s+(.*?)(?:\r\n(?!\s)|$)"
        auth_name = "Authorization"
    else:
        return response, headers

    challenge = re.search(challenge_re, raw_headers, re.DOTALL)
    if not challenge:
        raise RuntimeError(f"{method} {response.status_code()} without auth challenge")

    auth = _digest_auth(
        sip_user, sip_pass, method, uri, challenge.group(1), auth_name
    )
    headers = [
        line
        for line in headers
        if not line.startswith("Authorization:")
        and not line.startswith("Proxy-Authorization:")
    ]
    headers[0] = (
        f"Via: SIP/2.0/{transport} {local_ip}:{local_port};"
        f"branch=z9hG4bK-{uuid.uuid4().hex[:12]};rport"
    )
    cseq_value = headers[cseq_index].split(":", 1)[1].strip()
    cseq_num = int(cseq_value.split()[0]) + 1
    headers[cseq_index] = f"CSeq: {cseq_num} {method}"
    headers.append(auth)
    stream.sock.sendall(_sip_request(method, uri, headers, body))
    return stream.recv_frame(), headers


def _send_plain_message(
    stream: SipStream,
    local_ip: str,
    local_port: int,
    gw: GatewayConfig,
    sip_user: str,
    sip_pass: str,
    target_uri: str,
    body: str,
) -> SipFrame:
    transport = gw.transport.upper()
    transport_param = f";transport={gw.transport}" if gw.transport == "tls" else ""
    headers = [
        f"Via: SIP/2.0/{transport} {local_ip}:{local_port};branch=z9hG4bK-{uuid.uuid4().hex[:12]};rport",
        "Max-Forwards: 70",
        f"From: <sip:{sip_user}@{gw.sip_domain}{transport_param}>;tag={uuid.uuid4().hex[:8]}",
        f"To: <{target_uri}>",
        f"Call-ID: {uuid.uuid4().hex[:16]}@{gw.sip_domain}",
        "CSeq: 1 MESSAGE",
        "Content-Type: text/plain",
        "User-Agent: ABB-Welcome-HA/1.0",
    ]
    stream.sock.sendall(_sip_request("MESSAGE", target_uri, headers, body))
    response = stream.recv_final_response()
    if response.status_code() in (401, 407):
        response, headers = _maybe_auth_resend(
            stream,
            response,
            "MESSAGE",
            target_uri,
            headers,
            body,
            sip_user,
            sip_pass,
            transport,
            local_ip,
            local_port,
            5,
        )
        while response.is_response() and (response.status_code() or 0) // 100 == 1:
            response = stream.recv_frame()
    return response


def _make_dummy_rtp_socket(bind_ip: str) -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, 0))
    sock.setblocking(False)
    return sock, sock.getsockname()[1]


def _build_offer_sdp(media_ip: str, audio_port: int, video_port: int) -> str:
    session_id = int(time.time() * 1000)
    return "\r\n".join(
        [
            "v=0",
            f"o=- {session_id} 1 IN IP4 {media_ip}",
            "s=ABB Welcome Home Assistant",
            f"c=IN IP4 {media_ip}",
            "t=0 0",
            f"m=audio {audio_port} RTP/AVP 0 8 101",
            "a=rtpmap:0 PCMU/8000",
            "a=rtpmap:8 PCMA/8000",
            "a=rtpmap:101 telephone-event/8000",
            "a=fmtp:101 0-16",
            "a=sendrecv",
            f"m=video {video_port} RTP/AVP 96 97 98",
            "a=rtpmap:96 H264/90000",
            "a=rtpmap:97 VP8/90000",
            "a=rtpmap:98 H263-1998/90000",
            "a=sendrecv",
            "",
        ]
    )


def _start_invite_call(
    stream: SipStream,
    local_ip: str,
    local_port: int,
    gw: GatewayConfig,
    sip_user: str,
    sip_pass: str,
    door: DoorSpec,
    invite_timeout: float,
    media_ip: str,
    rtp_bind_ip: str,
) -> InviteSession:
    transport = gw.transport.upper()
    transport_param = f";transport={gw.transport}" if gw.transport == "tls" else ""
    request_uri = door.address
    target_uri = request_uri + transport_param if gw.transport == "tls" else request_uri
    local_contact = f"<sip:{sip_user}@{local_ip}:{local_port};transport={gw.transport}>"
    from_header = f"<sip:{sip_user}@{gw.sip_domain}{transport_param}>"
    to_header = f"<{door.address}>"

    audio_sock, audio_port = _make_dummy_rtp_socket(rtp_bind_ip)
    video_sock, video_port = _make_dummy_rtp_socket(rtp_bind_ip)
    sdp = _build_offer_sdp(media_ip, audio_port, video_port)
    try:
        local_tag = uuid.uuid4().hex[:8]
        call_id = uuid.uuid4().hex[:16] + "@" + gw.sip_domain
        headers = [
            f"Via: SIP/2.0/{transport} {local_ip}:{local_port};branch=z9hG4bK-{uuid.uuid4().hex[:12]};rport",
            "Max-Forwards: 70",
            f"From: {from_header};tag={local_tag}",
            f"To: {to_header}",
            f"Call-ID: {call_id}",
            "CSeq: 1 INVITE",
            f"Contact: {local_contact}",
            "User-Agent: ABB-Welcome-HA/1.0",
            "Allow: INVITE, ACK, CANCEL, BYE, MESSAGE, OPTIONS",
            "Accept: application/sdp",
            "Content-Type: application/sdp",
        ]
        stream.sock.sendall(_sip_request("INVITE", request_uri, headers, sdp))

        deadline = time.monotonic() + invite_timeout
        response = stream.recv_frame()
        if response.status_code() in (401, 407):
            response, headers = _maybe_auth_resend(
                stream,
                response,
                "INVITE",
                request_uri,
                headers,
                sdp,
                sip_user,
                sip_pass,
                transport,
                local_ip,
                local_port,
                5,
            )

        remote_to = ""
        remote_contact = ""
        invite_cseq = int(headers[5].split(":", 1)[1].strip().split()[0])
        invite_branch = headers[0].split("branch=", 1)[1].split(";", 1)[0]

        while True:
            if response.is_response():
                status = response.status_code() or 0
                if response.header("To"):
                    remote_to = response.header("To")
                if response.header("Contact"):
                    remote_contact = _parse_contact_uri(response.header("Contact"))

                if status == 183:
                    return InviteSession(
                        target_uri=target_uri,
                        request_uri=request_uri,
                        call_id=call_id,
                        from_header=from_header,
                        local_tag=local_tag,
                        local_contact=local_contact,
                        invite_cseq=invite_cseq,
                        invite_branch=invite_branch,
                        remote_to=remote_to or f"{to_header};tag=unknown",
                        established=False,
                        remote_contact=remote_contact,
                        audio_sock=audio_sock,
                        video_sock=video_sock,
                    )
                if status == 200:
                    session = InviteSession(
                        target_uri=target_uri,
                        request_uri=request_uri,
                        call_id=call_id,
                        from_header=from_header,
                        local_tag=local_tag,
                        local_contact=local_contact,
                        invite_cseq=invite_cseq,
                        invite_branch=invite_branch,
                        remote_to=remote_to or f"{to_header};tag=unknown",
                        established=True,
                        remote_contact=remote_contact or request_uri,
                        audio_sock=audio_sock,
                        video_sock=video_sock,
                    )
                    _send_ack(stream, local_ip, local_port, gw, session)
                    return session
                if status >= 300:
                    raise RuntimeError(f"INVITE failed: {response.start_line}")

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for 183/200 from INVITE")
            stream.sock.settimeout(remaining)
            response = stream.recv_frame()
    except Exception:
        audio_sock.close()
        video_sock.close()
        raise


def _send_ack(
    stream: SipStream,
    local_ip: str,
    local_port: int,
    gw: GatewayConfig,
    session: InviteSession,
) -> None:
    transport = gw.transport.upper()
    headers = [
        f"Via: SIP/2.0/{transport} {local_ip}:{local_port};branch=z9hG4bK-{uuid.uuid4().hex[:12]};rport",
        "Max-Forwards: 70",
        f"From: {session.from_header};tag={session.local_tag}",
        session.remote_to if session.remote_to.lower().startswith("to:") else f"To: {session.remote_to}",
        f"Call-ID: {session.call_id}",
        f"CSeq: {session.invite_cseq} ACK",
        "Content-Length: 0",
    ]
    stream.sock.sendall(
        ("\r\n".join([f"ACK {session.request_uri} SIP/2.0", *headers, "", ""])).encode("utf-8")
    )


def _cancel_invite(
    stream: SipStream,
    local_ip: str,
    local_port: int,
    gw: GatewayConfig,
    session: InviteSession,
    timeout: float,
) -> None:
    transport = gw.transport.upper()
    headers = [
        f"Via: SIP/2.0/{transport} {local_ip}:{local_port};branch={session.invite_branch};rport",
        "Max-Forwards: 70",
        f"From: {session.from_header};tag={session.local_tag}",
        f"To: {session.remote_to}",
        f"Call-ID: {session.call_id}",
        f"CSeq: {session.invite_cseq} CANCEL",
        "User-Agent: ABB-Welcome-HA/1.0",
        "Content-Length: 0",
    ]
    stream.sock.sendall(
        ("\r\n".join([f"CANCEL {session.request_uri} SIP/2.0", *headers, "", ""])).encode("utf-8")
    )

    deadline = time.monotonic() + timeout
    saw_cancel_200 = False
    saw_invite_487 = False
    while time.monotonic() < deadline and not (saw_cancel_200 and saw_invite_487):
        stream.sock.settimeout(deadline - time.monotonic())
        frame = stream.recv_frame()
        if not frame.is_response():
            continue
        status = frame.status_code() or 0
        cseq = frame.header("CSeq")
        if status == 200 and cseq.endswith("CANCEL"):
            saw_cancel_200 = True
            continue
        if status == 487 and cseq.endswith("INVITE"):
            saw_invite_487 = True
            session.remote_to = frame.header("To") or session.remote_to
            _send_ack(stream, local_ip, local_port, gw, session)


def _send_bye(
    stream: SipStream,
    local_ip: str,
    local_port: int,
    gw: GatewayConfig,
    sip_user: str,
    sip_pass: str,
    session: InviteSession,
) -> SipFrame:
    transport = gw.transport.upper()
    request_uri = session.remote_contact or session.request_uri
    headers = [
        f"Via: SIP/2.0/{transport} {local_ip}:{local_port};branch=z9hG4bK-{uuid.uuid4().hex[:12]};rport",
        "Max-Forwards: 70",
        f"From: {session.from_header};tag={session.local_tag}",
        f"To: {session.remote_to}",
        f"Call-ID: {session.call_id}",
        f"CSeq: {session.invite_cseq + 1} BYE",
        f"Contact: {session.local_contact}",
        "User-Agent: ABB-Welcome-HA/1.0",
    ]
    stream.sock.sendall(
        ("\r\n".join([f"BYE {request_uri} SIP/2.0", *headers, "Content-Length: 0", "", ""])).encode("utf-8")
    )

    while True:
        response = stream.recv_frame()
        if response.is_response() and (response.status_code() or 0) // 100 == 1:
            continue
        if not response.is_response():
            _send_sip_response(stream.sock, response, 200, "OK")
            continue
        break

    if response.status_code() in (401, 407):
        raw_headers = "\r\n".join(
            [response.start_line, *(f"{k}: {v}" for k, v in response.headers)]
        )
        if response.status_code() == 407:
            challenge_re = r"Proxy-Authenticate:\s*Digest\s+(.*?)(?:\r\n(?!\s)|$)"
            header_name = "Proxy-Authorization"
        else:
            challenge_re = r"WWW-Authenticate:\s*Digest\s+(.*?)(?:\r\n(?!\s)|$)"
            header_name = "Authorization"
        challenge = re.search(challenge_re, raw_headers, re.DOTALL)
        if not challenge:
            raise RuntimeError("BYE challenge missing auth header")
        auth = _digest_auth(
            sip_user, sip_pass, "BYE", request_uri, challenge.group(1), header_name
        )
        headers[0] = (
            f"Via: SIP/2.0/{transport} {local_ip}:{local_port};"
            f"branch=z9hG4bK-{uuid.uuid4().hex[:12]};rport"
        )
        headers[5] = f"CSeq: {session.invite_cseq + 2} BYE"
        headers.append(auth)
        stream.sock.sendall(
            ("\r\n".join([f"BYE {request_uri} SIP/2.0", *headers, "Content-Length: 0", "", ""])).encode("utf-8")
        )
        while True:
            response = stream.recv_frame()
            if response.is_response() and (response.status_code() or 0) // 100 == 1:
                continue
            if not response.is_response():
                _send_sip_response(stream.sock, response, 200, "OK")
                continue
            break

    return response


class SIPClient:
    """ABB Welcome unlock client with hybrid MRANGE routing."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        domain: str,
        doors: list[dict] | None = None,
        invite_transport: str = DEFAULT_INVITE_TRANSPORT,
        unlock_strategy: str = "hybrid",
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.invite_transport = invite_transport if invite_transport in ("tls", "tcp") else DEFAULT_INVITE_TRANSPORT
        if unlock_strategy not in ("hybrid", "fast", "standard"):
            unlock_strategy = "hybrid"
        self.unlock_strategy = unlock_strategy
        self._first_station_id = self._derive_first_station_id(doors or [])

    def _derive_first_station_id(self, doors: list[dict]) -> str:
        for door in doors:
            station_id = self._extract_station_id(door)
            if station_id:
                return station_id
        return ""

    def _extract_station_id(self, door: Mapping[str, object]) -> str:
        station_id = str(door.get("station_id", "")).strip()
        if station_id:
            return station_id
        body = str(door.get("body", "")).strip()
        station_id = _parse_station_id_from_legacy_body(body)
        if station_id:
            return station_id
        return _parse_station_id_from_address(str(door.get("address", "")))

    def _normalize_door(
        self, door: Mapping[str, object] | str, body_override: str | None
    ) -> DoorSpec:
        if isinstance(door, Mapping):
            raw = door
        else:
            raw = {"name": str(door), "address": str(door)}
            if body_override is not None:
                raw["body"] = body_override

        station_id = self._extract_station_id(raw)
        if not station_id:
            raise ValueError("could not determine door station id")

        name = str(raw.get("name", station_id))
        raw_address = str(raw.get("address", "")).strip()
        address = f"sip:{station_id}@{self.domain}"
        if _parse_station_id_from_address(raw_address) == station_id and raw_address:
            address = raw_address

        raw_body = body_override if body_override is not None else str(raw.get("body", "1"))
        unlock_body = _normalize_unlock_body(raw_body)

        index_value = raw.get("index")
        try:
            index = int(index_value) if index_value is not None else None
        except (TypeError, ValueError):
            index = None

        return DoorSpec(
            name=name,
            station_id=station_id,
            address=address,
            unlock_body=unlock_body,
            index=index,
        )

    def _use_fast_route(self, door: DoorSpec) -> bool:
        if self.unlock_strategy == "fast":
            return True
        if self.unlock_strategy == "standard":
            return False
        # hybrid: fast for the first station, standard for the rest.
        if self._first_station_id:
            return door.station_id == self._first_station_id
        if door.index is not None:
            return door.index == 0
        return False

    def _unlock_fast(self, door: DoorSpec, timeout: float) -> bool:
        gw = _build_gateway_config(self.domain, self.host, "tcp")
        try:
            sock, local_ip, local_port = _build_socket(gw, timeout)
        except (ConnectionError, OSError) as err:
            _LOGGER.error("Fast unlock connection error for %s: %s", door.name, err)
            return False

        stream = SipStream(sock)
        try:
            _register_client(stream, local_ip, local_port, gw, self.username, self.password)
            response = _send_plain_message(
                stream,
                local_ip,
                local_port,
                gw,
                self.username,
                self.password,
                door.address,
                door.unlock_body,
            )
            if response.status_code() != 200:
                _LOGGER.error("Fast unlock MESSAGE failed for %s: %s", door.name, response.start_line)
                return False
            _LOGGER.debug("Fast unlock succeeded for %s", door.name)
            return True
        except RuntimeError as err:
            _LOGGER.error("Fast unlock failed for %s: %s", door.name, err)
            return False
        except (ConnectionError, OSError, ssl.SSLError) as err:
            _LOGGER.error("Fast unlock network error for %s: %s", door.name, err)
            return False
        finally:
            sock.close()

    def _unlock_via_invite(self, door: DoorSpec, timeout: float) -> bool:
        gw = _build_gateway_config(self.domain, self.host, self.invite_transport)
        media_ip = _guess_media_ip(gw.gw_host)
        invite_timeout = min(timeout, DEFAULT_INVITE_TIMEOUT) if timeout > 0 else DEFAULT_INVITE_TIMEOUT

        try:
            sock, local_ip, local_port = _build_socket(gw, timeout)
        except (ConnectionError, OSError, ssl.SSLError) as err:
            _LOGGER.error("Invite unlock connection error for %s: %s", door.name, err)
            return False

        stream = SipStream(sock)
        session: InviteSession | None = None
        unlocked = False
        try:
            _register_client(stream, local_ip, local_port, gw, self.username, self.password)
            session = _start_invite_call(
                stream,
                local_ip,
                local_port,
                gw,
                self.username,
                self.password,
                door,
                invite_timeout,
                media_ip,
                "0.0.0.0",
            )
            stream.sock.settimeout(timeout)

            if DEFAULT_UNLOCK_DELAY > 0:
                time.sleep(DEFAULT_UNLOCK_DELAY)

            response = _send_plain_message(
                stream,
                local_ip,
                local_port,
                gw,
                self.username,
                self.password,
                session.target_uri,
                door.unlock_body,
            )
            if response.status_code() != 200:
                _LOGGER.error("Invite unlock MESSAGE failed for %s: %s", door.name, response.start_line)
                return False

            unlocked = True
            _LOGGER.debug("Invite unlock succeeded for %s", door.name)
            return True
        except TimeoutError as err:
            _LOGGER.error("Invite unlock timed out for %s: %s", door.name, err)
            return False
        except RuntimeError as err:
            message = str(err)
            if "486 Busy Here" in message:
                _LOGGER.error("Invite unlock busy for %s: another intercom/call is active", door.name)
            else:
                _LOGGER.error("Invite unlock failed for %s: %s", door.name, message)
            return False
        except (ConnectionError, OSError, ssl.SSLError) as err:
            _LOGGER.error("Invite unlock network error for %s: %s", door.name, err)
            return False
        finally:
            if session is not None:
                try:
                    if session.established:
                        response = _send_bye(
                            stream,
                            local_ip,
                            local_port,
                            gw,
                            self.username,
                            self.password,
                            session,
                        )
                        _LOGGER.debug("BYE result for %s: %s", door.name, response.start_line)
                    else:
                        _cancel_invite(stream, local_ip, local_port, gw, session, timeout)
                except (ConnectionError, OSError, ssl.SSLError, TimeoutError, RuntimeError) as err:
                    if unlocked:
                        _LOGGER.debug("Call teardown issue after unlock for %s: %s", door.name, err)
                    else:
                        _LOGGER.warning("Call teardown issue for %s: %s", door.name, err)
                session.close_media()
            sock.close()

    def unlock_door(
        self,
        door: Mapping[str, object] | str,
        body: str | None = None,
        timeout: float = 5.0,
    ) -> bool:
        """Unlock a door using the correct MRANGE path."""
        try:
            spec = self._normalize_door(door, body)
        except ValueError as err:
            _LOGGER.error("Invalid ABB Welcome door config: %s", err)
            return False

        if self._use_fast_route(spec):
            return self._unlock_fast(spec, timeout)
        return self._unlock_via_invite(spec, timeout)
