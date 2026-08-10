"""Persistent SIP listener for incoming intercom INVITEs.

Maintains a long-lived REGISTER on the gateway so the integration receives
``INVITE`` messages within tens of milliseconds of someone pressing the
doorbell — much faster than the 30 s cloud-event poll.

The listener runs on its own asyncio task on a dedicated socket and uses a
distinct ``Contact`` URI from :mod:`sip_client`, so unlock requests and
incoming-call notifications coexist as independent SIP bindings on the
gateway.

By default it observes incoming calls without accepting them.  When a
camera consumer opens the stream while a matching INVITE is pending, the
media pipeline can ask this listener to answer that exact call with a
``200 OK`` SDP answer, avoiding the busy/loopback problem caused by
actively dialing the outdoor station while it is already calling us.
``CANCEL`` from the gateway (someone else picked up, or timeout) is
acknowledged properly with ``200 OK`` + ``487 Request Terminated`` so
the dialog closes without leaking transactions.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import ssl
import time
import uuid
import warnings
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from .intercom_dialer import ParsedSdp, parse_sdp

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

# REGISTER lifetime requested from the gateway.  We refresh at half this
# value to leave headroom for jitter / retries.
DEFAULT_EXPIRES = 600
REFRESH_MARGIN = 60

# Reconnect backoff steps (seconds) used after unexpected disconnects.
RECONNECT_BACKOFF = (2, 5, 10, 30, 60)

USER_AGENT = "ABB-Welcome-HA-Listener/1.0"


@dataclass
class IncomingCall:
    """Snapshot of an incoming INVITE."""

    caller_uri: str
    caller_user: str  # extracted user portion of the URI (often the station id)
    call_id: str
    from_header: str
    to_header: str
    via_header: str
    cseq: str
    raw_invite: bytes
    received_at: float


@dataclass
class AcceptedIncomingCall:
    """A door-station originated INVITE that HA has answered."""

    caller_uri: str
    caller_user: str
    call_id: str
    local_tag: str
    remote_tag: str
    invite_cseq: int
    remote_contact: str
    local_contact: str
    from_header: str
    to_header: str
    remote_sdp: ParsedSdp
    audio_local_port: int
    video_local_port: int
    ack_received: bool = False


@dataclass
class _AcceptedDialog:
    call: AcceptedIncomingCall
    ack_received: bool = False
    ack_event: asyncio.Event = field(default_factory=asyncio.Event)
    ended_event: asyncio.Event = field(default_factory=asyncio.Event)
    end_reason: str = ""


RingCallback = Callable[[IncomingCall], Awaitable[None] | None]
FrameCallback = Callable[[dict[str, Any]], None]


def _summarise_frame(frame: "_SipFrame") -> dict[str, Any]:
    """Convert a SIP frame to a JSON-serialisable dict for HA event payloads.

    Lossless on purpose: every header is preserved (multi-valued ones as a
    list), the full body is included as text (UTF-8 with replacement on
    non-text), and the complete wire bytes are exposed as ``raw`` so the
    event subscriber can rebuild the original frame byte-for-byte.
    """
    summary: dict[str, Any] = {
        "start_line": frame.start_line,
        "is_response": frame.is_response,
    }
    if frame.is_response:
        summary["status_code"] = frame.status_code
    else:
        summary["method"] = frame.method
        summary["request_uri"] = (
            frame.start_line.split(" ", 2)[1] if " " in frame.start_line else ""
        )

    # Group headers preserving order; multi-valued headers (Via, Route, etc)
    # become lists.  Header names are case-insensitive in SIP, so we
    # canonicalise on first-seen capitalisation.
    headers: dict[str, Any] = {}
    seen_case: dict[str, str] = {}
    for key, value in frame.headers:
        canonical = seen_case.setdefault(key.lower(), key)
        if canonical in headers:
            current = headers[canonical]
            if isinstance(current, list):
                current.append(value)
            else:
                headers[canonical] = [current, value]
        else:
            headers[canonical] = value
    summary["headers"] = headers

    body_bytes = frame.body
    if body_bytes:
        summary["body"] = body_bytes.decode("utf-8", errors="replace")
        summary["body_bytes"] = len(body_bytes)
    else:
        summary["body"] = ""
        summary["body_bytes"] = 0

    # Full wire bytes — handy when a future bug needs an exact byte-by-byte
    # reproduction.  Decoded with replacement so the event payload stays
    # JSON-safe.
    summary["raw"] = frame.raw.decode("utf-8", errors="replace")
    summary["raw_bytes"] = len(frame.raw)
    return summary


# ---------------------------------------------------------------------------
# Low-level SIP helpers (async-friendly).
# ---------------------------------------------------------------------------


def _build_ssl_context() -> ssl.SSLContext:
    """SSL context that tolerates the gateway's old TLS / self-signed cert."""
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


def _parse_headers(raw: bytes) -> tuple[str, list[tuple[str, str]]]:
    text = raw.decode("utf-8", errors="replace")
    lines = text.split("\r\n")
    start_line = lines[0]
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers.append((key.strip(), value.strip()))
    return start_line, headers


def _header(headers: list[tuple[str, str]], name: str) -> str:
    wanted = name.lower()
    for key, value in headers:
        if key.lower() == wanted:
            return value
    return ""


def _all_headers(headers: list[tuple[str, str]], name: str) -> list[str]:
    wanted = name.lower()
    return [v for k, v in headers if k.lower() == wanted]


def _user_from_uri(uri: str) -> str:
    """Extract the 'user' portion of a SIP URI inside <...> or bare."""
    match = re.search(r"sip:([^@>;\s]+)@", uri)
    if match:
        return match.group(1)
    return ""


def _tag_from_header(value: str) -> str:
    match = re.search(r"(?:^|[;\s])tag=([^;>\s]+)", value)
    return match.group(1) if match else ""


def _contact_uri(value: str) -> str:
    match = re.search(r"<([^>]+)>", value)
    if match:
        return match.group(1)
    return value.strip()


def _cseq_number(value: str) -> int:
    try:
        return int(value.split()[0])
    except (IndexError, ValueError):
        return 1


def _preferred_payload(
    offer: ParsedSdp,
    media: str,
    preferred: tuple[str, ...],
) -> tuple[int, str, str | None, str] | None:
    for desc in offer.medias:
        if desc.media != media:
            continue
        for codec in preferred:
            for pt in desc.payload_types:
                rtpmap = desc.rtpmap.get(pt, "")
                if codec.lower() in rtpmap.lower():
                    return pt, rtpmap, desc.fmtp.get(pt), desc.proto or "RTP/AVP"
        if desc.payload_types:
            pt = desc.payload_types[0]
            return pt, desc.rtpmap.get(pt, ""), desc.fmtp.get(pt), desc.proto or "RTP/AVP"
    return None


def _mirrored_crypto_lines(offer: ParsedSdp, media: str) -> list[str]:
    """Return the offer's ``a=crypto`` lines for the given media section."""
    for desc in offer.medias:
        if desc.media == media and getattr(desc, "crypto", None):
            return [f"a=crypto:{line}" for line in desc.crypto]
    return []


def _build_answer_sdp(
    offer: ParsedSdp,
    *,
    username: str,
    media_ip: str,
    audio_port: int,
    video_port: int,
) -> str:
    """Build a conservative SDP answer for an incoming door-station INVITE."""
    sid = int(time.time() * 1000)
    lines = [
        "v=0",
        f"o={username} {sid} {sid} IN IP4 {media_ip}",
        "s=Talk",
        f"c=IN IP4 {media_ip}",
        "b=AS:380",
        "t=0 0",
    ]

    audio = _preferred_payload(offer, "audio", ("PCMA/8000", "PCMU/8000"))
    if audio is not None:
        pt, rtpmap, _fmtp, proto = audio
        lines.extend([
            f"m=audio {audio_port} {proto} {pt}",
            f"a=rtpmap:{pt} {rtpmap or 'PCMA/8000'}",
            "a=ptime:20",
        ])
        # Echo the panel's own crypto attribute.  ABB WiFi panels expect
        # the uplink to use the same AES key they announced, so mirroring
        # the line keeps both interpretations of the (non-standard)
        # handshake consistent: whichever key the panel decrypts with, it
        # is the one we encrypt with.
        lines.extend(_mirrored_crypto_lines(offer, "audio"))
        lines.append("a=sendrecv")

    video = _preferred_payload(offer, "video", ("H264/90000",))
    if video is not None:
        pt, rtpmap, fmtp, proto = video
        lines.extend([
            f"m=video {video_port} {proto} {pt}",
            f"a=rtpmap:{pt} {rtpmap or 'H264/90000'}",
        ])
        if fmtp:
            lines.append(f"a=fmtp:{pt} {fmtp}")
        lines.extend(_mirrored_crypto_lines(offer, "video"))
        lines.append("a=sendrecv")

    lines.append("")
    return "\r\n".join(lines)


def _parse_challenge(value: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for match in re.finditer(r'(\w+)\s*=\s*"?([^",]+)"?', value):
        params[match.group(1)] = match.group(2)
    return params


def _digest_response(
    username: str,
    password: str,
    method: str,
    uri: str,
    challenge: dict[str, str],
) -> str:
    realm = challenge["realm"]
    nonce = challenge["nonce"]
    qop = challenge.get("qop", "auth")
    opaque = challenge.get("opaque", "")
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


# ---------------------------------------------------------------------------
# Listener.
# ---------------------------------------------------------------------------


class SipListener:
    """Long-lived SIP REGISTER + INVITE observer.

    Lifecycle: :py:meth:`start` schedules a background task that connects to
    the gateway, registers, and reads frames until cancelled.  The task is
    self-healing — disconnects trigger reconnection with exponential
    backoff.  :py:meth:`stop` cancels the task and tears down the socket.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        domain: str,
        *,
        port: int = 5061,
        transport: str = "tls",
        on_ring: RingCallback | None = None,
        on_state_change: Callable[[str], None] | None = None,
        on_frame: FrameCallback | None = None,
        wifi_panel: bool = False,
    ) -> None:
        if transport not in ("tls", "tcp"):
            raise ValueError("transport must be 'tls' or 'tcp'")
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.port = port
        self.transport = transport
        self.wifi_panel = wifi_panel
        self._on_ring = on_ring
        self._on_state_change = on_state_change
        self._on_frame = on_frame

        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._local_ip: str = ""
        self._local_port: int = 0
        self._reg_cseq: int = 0
        self._state = "stopped"
        # Map Call-ID -> last INVITE frame so CANCEL can echo the right Vias.
        self._open_invites: dict[str, _SipFrame] = {}
        self._accepted_dialogs: dict[str, _AcceptedDialog] = {}
        self._ended_dialog_reasons: dict[str, str] = {}
        self._dialog_cseq = 1
        self._dialog_lock = asyncio.Lock()

    # ----- Public lifecycle -----

    @property
    def state(self) -> str:
        """Current high-level state: stopped / connecting / registered / disconnected."""
        return self._state

    def pending_call_for_station(self, station_id: str) -> bool:
        """Return whether an unanswered INVITE is pending for this station."""
        station_id = str(station_id or "").strip()
        now = time.time()
        pending = 0
        for call_id, frame in list(self._open_invites.items()):
            if now - self._invite_received_at(frame) > 45:
                self._open_invites.pop(call_id, None)
                continue
            pending += 1
            if self._frame_station_id(frame) == station_id:
                return True
        return pending == 1

    async def accept_pending_call(
        self,
        *,
        station_id: str,
        media_ip: str,
        audio_port: int,
        video_port: int,
    ) -> AcceptedIncomingCall | None:
        """Answer a pending door-station INVITE with local RTP ports."""
        async with self._dialog_lock:
            if self._writer is None or self._writer.is_closing():
                return None
            frame = self._pop_pending_invite(station_id)
            if frame is None:
                return None

            call_id = _header(frame.headers, "Call-ID")
            offer = parse_sdp(frame.body)
            # Log the full incoming INVITE SDP body to find sprop-parameter-sets
            _LOGGER.info(
                "[abb] Incoming INVITE SDP body call_id=%s:\n%s",
                call_id,
                frame.body.decode("utf-8", errors="replace") if frame.body else "(empty)",
            )
            for m in offer.medias:
                _LOGGER.info(
                    "[abb] Incoming SDP media=%s port=%d pts=%s rtpmap=%s fmtp=%s direction=%s",
                    m.media, m.port, m.payload_types, m.rtpmap, m.fmtp, m.direction,
                )
            answer = _build_answer_sdp(
                offer,
                username=self.username,
                media_ip=media_ip,
                audio_port=audio_port,
                video_port=video_port,
            )
            local_tag = uuid.uuid4().hex[:8]
            local_contact = (
                f"<sip:{self.username}@{self._local_ip}:{self._local_port};"
                f"transport={self.transport}>"
            )
            from_header = _header(frame.headers, "From")
            to_header = _header(frame.headers, "To")
            to_with_tag = (
                to_header if ";tag=" in to_header else f"{to_header};tag={local_tag}"
            )
            remote_contact = _contact_uri(_header(frame.headers, "Contact"))
            caller_match = re.search(r"<([^>]+)>", from_header)
            caller_uri = caller_match.group(1) if caller_match else from_header
            accepted = AcceptedIncomingCall(
                caller_uri=caller_uri,
                caller_user=_user_from_uri(caller_uri),
                call_id=call_id,
                local_tag=local_tag,
                remote_tag=_tag_from_header(from_header),
                invite_cseq=_cseq_number(_header(frame.headers, "CSeq")),
                remote_contact=remote_contact,
                local_contact=local_contact,
                from_header=from_header,
                to_header=to_with_tag,
                remote_sdp=offer,
                audio_local_port=audio_port,
                video_local_port=video_port,
            )
            dialog = _AcceptedDialog(call=accepted)
            self._ended_dialog_reasons.pop(call_id, None)
            self._accepted_dialogs[call_id] = dialog
            await self._respond(
                self._writer,
                frame,
                200,
                "OK",
                to_tag=local_tag,
                extra_headers=[
                    f"Contact: {local_contact}",
                    (
                        "Allow: INVITE, ACK, CANCEL, OPTIONS, MESSAGE, INFO, REFER, "
                        "BYE, NOTIFY, PRACK, UPDATE, SUBSCRIBE"
                    ),
                    "Supported: replaces, outbound",
                    "Content-Type: application/sdp",
                ],
                body=answer,
            )
            _LOGGER.info(
                "[abb] Accepted incoming call station=%s call_id=%s "
                "audio_port=%d video_port=%d",
                station_id,
                call_id,
                audio_port,
                video_port,
            )
        try:
            # WiFi panels don't send ACK after 200 OK — don't block media
            # startup waiting for it.  Use a very short timeout (200ms)
            # instead of 3 seconds.
            ack_timeout = 0.2 if self.wifi_panel else 3.0
            await asyncio.wait_for(dialog.ack_event.wait(), timeout=ack_timeout)
            accepted.ack_received = True
            _LOGGER.info("[abb] Incoming call ACK received call_id=%s", call_id)
        except asyncio.TimeoutError:
            if self.wifi_panel:
                _LOGGER.info(
                    "[abb] WiFi panel: ACK not received (expected); starting media immediately call_id=%s",
                    call_id,
                )
            else:
                _LOGGER.warning(
                    "[abb] Incoming call ACK not received within timeout call_id=%s; "
                    "continuing media setup",
                    call_id,
                )
        if dialog.ended_event.is_set():
            _LOGGER.warning(
                "[abb] Incoming call ended while waiting for ACK call_id=%s reason=%s",
                call_id,
                dialog.end_reason,
            )
            return None
        accepted.ack_received = dialog.ack_received
        return accepted

    async def wait_accepted_call_end(self, call_id: str) -> str:
        """Wait until an accepted incoming call ends; return the end reason."""
        dialog = self._accepted_dialogs.get(call_id)
        if dialog is None:
            return self._ended_dialog_reasons.get(call_id, "not_found")
        await dialog.ended_event.wait()
        return dialog.end_reason or "ended"

    async def hangup_accepted_call(self, call_id: str) -> None:
        """Send BYE for an incoming call previously accepted by this listener."""
        async with self._dialog_lock:
            dialog = self._accepted_dialogs.get(call_id)
            if dialog is None or self._writer is None or self._writer.is_closing():
                return
            call = dialog.call
            target = call.remote_contact or call.caller_uri
            branch = "z9hG4bK-" + uuid.uuid4().hex[:12]
            cseq = self._dialog_cseq
            self._dialog_cseq += 1
            headers = [
                (
                    f"Via: SIP/2.0/{self.transport.upper()} "
                    f"{self._local_ip}:{self._local_port};branch={branch};rport"
                ),
                "Max-Forwards: 70",
                f"From: {call.to_header}",
                f"To: {call.from_header}",
                f"Call-ID: {call.call_id}",
                f"CSeq: {cseq} BYE",
                f"Contact: {call.local_contact}",
                f"User-Agent: {USER_AGENT}",
            ]
            await self._send_request(self._writer, "BYE", target, headers, "")
            self._finish_accepted_dialog(call_id, "local_bye")
            _LOGGER.info("[abb] Sent BYE for accepted incoming call %s", call_id)

    def start(self, hass: "HomeAssistant" | None = None) -> None:
        """Schedule the listener loop.  Idempotent.

        Pass ``hass`` so the task is registered with HA's task tracking and
        survives the chaotic startup window properly; without it we fall
        back to a bare ``asyncio.create_task`` which can be starved during
        HA boot when many integrations are coming up at once.
        """
        if self._task is not None and not self._task.done():
            return
        self._stop_event.clear()
        if hass is not None:
            self._task = hass.async_create_background_task(
                self._main_loop(), name="abb_welcome_sip_listener"
            )
        else:
            self._task = asyncio.create_task(
                self._main_loop(), name="abb_welcome_sip_listener"
            )

    async def stop(self) -> None:
        """Cancel the listener loop and close the socket.

        If we're currently registered, try to send a graceful ``REGISTER``
        with ``Expires: 0`` first so the gateway drops our binding
        immediately instead of keeping a dead Contact in its forking list
        until the original Expires window runs out.  Best-effort — we
        absorb any failure to avoid blocking unload.
        """
        self._stop_event.set()
        if self._writer is not None and self._state == "registered":
            try:
                await asyncio.wait_for(self._deregister(), timeout=2.0)
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("[abb] deregister on stop failed: %s", err)
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass
            self._writer = None
        for call_id in list(self._accepted_dialogs):
            self._finish_accepted_dialog(call_id, "listener_stopped")
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None
        self._set_state("stopped")

    # ----- Internal -----

    def _set_state(self, new_state: str) -> None:
        if new_state != self._state:
            _LOGGER.info("[abb] SIP listener state: %s -> %s", self._state, new_state)
            self._state = new_state
            if self._on_state_change is not None:
                try:
                    self._on_state_change(new_state)
                except Exception as err:  # noqa: BLE001
                    _LOGGER.debug("on_state_change raised: %s", err)

    async def _main_loop(self) -> None:
        attempt = 0
        while not self._stop_event.is_set():
            try:
                self._set_state("connecting")
                await self._connect_register_and_read()
                attempt = 0  # successful run resets the backoff
            except asyncio.CancelledError:
                raise
            except Exception as err:  # noqa: BLE001
                self._set_state("disconnected")
                delay = RECONNECT_BACKOFF[min(attempt, len(RECONNECT_BACKOFF) - 1)]
                _LOGGER.warning(
                    "[abb] SIP listener error (%s); reconnecting in %ds",
                    err, delay,
                )
                attempt += 1
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=delay)
                    break  # stop_event fired during sleep
                except asyncio.TimeoutError:
                    continue

    async def _connect_register_and_read(self) -> None:
        ssl_ctx = _build_ssl_context() if self.transport == "tls" else None
        reader, writer = await asyncio.open_connection(
            self.host, self.port, ssl=ssl_ctx
        )
        self._reader = reader
        self._writer = writer
        try:
            local_ip, local_port = writer.get_extra_info("sockname")[:2]
            self._local_ip = local_ip
            self._local_port = local_port
            cseq = 1
            cseq = await self._do_register(
                reader, writer, local_ip, local_port, cseq, DEFAULT_EXPIRES
            )
            self._reg_cseq = cseq
            self._set_state("registered")

            # Schedule periodic re-REGISTER.
            refresh_in = max(60, DEFAULT_EXPIRES - REFRESH_MARGIN)
            next_refresh = asyncio.get_running_loop().time() + refresh_in

            while not self._stop_event.is_set():
                # Read next frame, but wake up to refresh REGISTER on time.
                now = asyncio.get_running_loop().time()
                timeout = max(1.0, next_refresh - now)
                try:
                    frame = await asyncio.wait_for(
                        self._read_frame(reader), timeout=timeout
                    )
                except asyncio.TimeoutError:
                    cseq = await self._do_register(
                        reader, writer, local_ip, local_port, cseq + 1, DEFAULT_EXPIRES
                    )
                    self._reg_cseq = cseq
                    next_refresh = asyncio.get_running_loop().time() + refresh_in
                    continue

                await self._dispatch(frame, writer, local_ip, local_port)
        finally:
            self._reader = None
            self._writer = None
            for call_id in list(self._accepted_dialogs):
                self._finish_accepted_dialog(call_id, "listener_disconnected")
            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass

    # ----- REGISTER -----

    def _transport_param(self) -> str:
        return f";transport={self.transport}" if self.transport == "tls" else ""

    async def _do_register(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        local_ip: str,
        local_port: int,
        cseq: int,
        expires: int,
    ) -> int:
        """Send REGISTER, handle 401 challenge, return last CSeq used."""
        transport = self.transport.upper()
        tparam = self._transport_param()
        reg_uri = f"sip:{self.domain}{tparam}"
        from_tag = uuid.uuid4().hex[:8]
        call_id = uuid.uuid4().hex[:16] + "@" + self.domain
        contact = (
            f"<sip:{self.username}@{local_ip}:{local_port};"
            f"transport={self.transport}>"
        )
        branch = "z9hG4bK-" + uuid.uuid4().hex[:12]

        base_headers = [
            f"Via: SIP/2.0/{transport} {local_ip}:{local_port};branch={branch};rport",
            "Max-Forwards: 70",
            f"From: <sip:{self.username}@{self.domain}{tparam}>;tag={from_tag}",
            f"To: <sip:{self.username}@{self.domain}{tparam}>",
            f"Call-ID: {call_id}",
            f"CSeq: {cseq} REGISTER",
            f"Contact: {contact}",
            f"Expires: {expires}",
            f"User-Agent: {USER_AGENT}",
        ]
        await self._send_request(writer, "REGISTER", reg_uri, base_headers, "")

        frame = await self._read_final_response(reader)
        if frame.status_code == 401:
            challenge = _header(frame.headers, "WWW-Authenticate")
            if not challenge.lower().startswith("digest"):
                raise RuntimeError(f"REGISTER 401 without Digest challenge: {challenge!r}")
            params = _parse_challenge(challenge[len("Digest"):].strip())
            cseq += 1
            auth = _digest_response(
                self.username, self.password, "REGISTER", reg_uri, params
            )
            new_branch = "z9hG4bK-" + uuid.uuid4().hex[:12]
            base_headers[0] = (
                f"Via: SIP/2.0/{transport} {local_ip}:{local_port};"
                f"branch={new_branch};rport"
            )
            base_headers[5] = f"CSeq: {cseq} REGISTER"
            base_headers.append(f"Authorization: {auth}")
            await self._send_request(writer, "REGISTER", reg_uri, base_headers, "")
            frame = await self._read_final_response(reader)

        if frame.status_code != 200:
            raise RuntimeError(f"REGISTER rejected: {frame.start_line}")
        _LOGGER.info(
            "[abb] SIP listener registered as %s on %s:%d (Expires=%d)",
            self.username, self.host, self.port, expires,
        )
        return cseq

    async def _deregister(self) -> None:
        """Send a REGISTER with Expires:0 so the gateway drops our binding now.

        Without this, every restart leaves a stale Contact in the gateway's
        forking list until its Expires window runs out (up to 10 min on the
        reference firmware), causing the gateway to fork incoming INVITEs
        to dead sockets and waste tens of milliseconds per ring.
        """
        if self._reader is None or self._writer is None:
            return
        if not self._local_ip or not self._local_port:
            return
        await self._do_register(
            self._reader,
            self._writer,
            self._local_ip,
            self._local_port,
            self._reg_cseq + 1,
            0,
        )
        _LOGGER.info("[abb] SIP listener de-registered (Expires=0)")

    # ----- Inbound dispatch -----

    def _emit_frame(self, direction: str, frame: "_SipFrame") -> None:
        """Notify the on_frame callback (HA bus) about a frame in either direction."""
        if self._on_frame is None:
            return
        try:
            payload = _summarise_frame(frame)
            payload["direction"] = direction  # "in" or "out"
            payload["received_at"] = time.time()
            self._on_frame(payload)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("[abb] on_frame callback raised: %s", err)

    async def _dispatch(
        self,
        frame: "_SipFrame",
        writer: asyncio.StreamWriter,
        local_ip: str,
        local_port: int,
    ) -> None:
        self._emit_frame("in", frame)
        method = frame.method
        if method == "INVITE":
            await self._handle_invite(frame, writer, local_ip, local_port)
        elif method == "OPTIONS":
            await self._respond(writer, frame, 200, "OK")
        elif method == "MESSAGE":
            # Some gateways push status MESSAGEs (e.g. door-open broadcasts).
            # Acknowledge politely.
            _LOGGER.debug("[abb] Inbound MESSAGE: %s", frame.body[:200])
            await self._respond(writer, frame, 200, "OK")
        elif method == "NOTIFY":
            await self._respond(writer, frame, 200, "OK")
        elif method == "CANCEL":
            # 200 OK to the CANCEL itself, then 487 Request Terminated to the
            # original INVITE so the gateway closes the transaction cleanly.
            await self._respond(writer, frame, 200, "OK")
            invite = self._open_invites.pop(_header(frame.headers, "Call-ID"), None)
            if invite is not None:
                await self._respond(
                    writer, invite, 487, "Request Terminated", with_to_tag=True
                )
            else:
                _LOGGER.info(
                    "[abb] CANCEL for non-pending call_id=%s",
                    _header(frame.headers, "Call-ID"),
                )
        elif method == "BYE":
            self._finish_accepted_dialog(_header(frame.headers, "Call-ID"), "remote_bye")
            await self._respond(writer, frame, 200, "OK")
        elif method == "ACK":
            dialog = self._accepted_dialogs.get(_header(frame.headers, "Call-ID"))
            if dialog is not None:
                dialog.ack_received = True
                dialog.call.ack_received = True
                dialog.ack_event.set()
            # ACKs are fire-and-forget.
        elif frame.is_response:
            # Stray response for a transaction we no longer track — ignore.
            _LOGGER.debug(
                "[abb] Stray response: %s (CSeq=%s)",
                frame.start_line, _header(frame.headers, "CSeq"),
            )
        else:
            _LOGGER.debug("[abb] Unhandled SIP method %s", method)

    async def _handle_invite(
        self,
        frame: "_SipFrame",
        writer: asyncio.StreamWriter,
        local_ip: str,
        local_port: int,
    ) -> None:
        from_header = _header(frame.headers, "From")
        caller_uri = re.search(r"<([^>]+)>", from_header)
        caller = caller_uri.group(1) if caller_uri else from_header
        to_header = _header(frame.headers, "To")
        contact_header = _header(frame.headers, "Contact")
        call_id = _header(frame.headers, "Call-ID")
        call = IncomingCall(
            caller_uri=caller,
            caller_user=_user_from_uri(caller),
            call_id=call_id,
            from_header=from_header,
            to_header=to_header,
            via_header=_header(frame.headers, "Via"),
            cseq=_header(frame.headers, "CSeq"),
            raw_invite=frame.raw,
            received_at=time.time(),
        )
        _LOGGER.info(
            "[abb] Incoming INVITE from %s (call_id=%s)",
            call.caller_uri, call.call_id,
        )
        _LOGGER.debug(
            "[abb] INVITE details: From=%s To=%s Contact=%s Call-ID=%s "
            "caller_user=%s",
            from_header, to_header, contact_header, call_id,
            call.caller_user,
        )

        # Remember the INVITE so we can issue 487 if a CANCEL arrives later.
        self._open_invites[call.call_id] = frame

        # 100 Trying is purely informational — it acknowledges receipt over
        # an unreliable transport and doesn't claim or reject the call.
        # We send no further response: no 180 Ringing, no 200 OK, no 4xx/6xx.
        # That keeps us a silent observer; the gateway continues to fork the
        # INVITE to the indoor stations and other apps without interference.
        await self._respond(writer, frame, 100, "Trying")

        if self._on_ring is not None:
            try:
                result = self._on_ring(call)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as err:  # noqa: BLE001
                _LOGGER.exception("[abb] on_ring callback raised: %s", err)

    async def _respond(
        self,
        writer: asyncio.StreamWriter,
        frame: "_SipFrame",
        code: int,
        reason: str,
        *,
        with_to_tag: bool = False,
        to_tag: str | None = None,
        extra_headers: list[str] | None = None,
        body: str = "",
    ) -> None:
        lines = [f"SIP/2.0 {code} {reason}"]
        out_headers: list[tuple[str, str]] = []
        # SIP requires the response to echo Via, From, To, Call-ID and CSeq.
        for via in _all_headers(frame.headers, "Via"):
            lines.append(f"Via: {via}")
            out_headers.append(("Via", via))
        from_value = _header(frame.headers, "From")
        lines.append(f"From: {from_value}")
        out_headers.append(("From", from_value))
        to_value = _header(frame.headers, "To")
        if (with_to_tag or to_tag) and ";tag=" not in to_value:
            to_value = f"{to_value};tag={to_tag or uuid.uuid4().hex[:8]}"
        lines.append(f"To: {to_value}")
        out_headers.append(("To", to_value))
        call_id = _header(frame.headers, "Call-ID")
        lines.append(f"Call-ID: {call_id}")
        out_headers.append(("Call-ID", call_id))
        cseq = _header(frame.headers, "CSeq")
        lines.append(f"CSeq: {cseq}")
        out_headers.append(("CSeq", cseq))
        lines.append(f"User-Agent: {USER_AGENT}")
        out_headers.append(("User-Agent", USER_AGENT))
        if extra_headers:
            for header in extra_headers:
                lines.append(header)
                if ":" in header:
                    key, value = header.split(":", 1)
                    out_headers.append((key.strip(), value.strip()))
        body_bytes = body.encode("utf-8")
        lines.append(f"Content-Length: {len(body_bytes)}")
        out_headers.append(("Content-Length", str(len(body_bytes))))
        lines.append("")
        lines.append(body)
        wire = "\r\n".join(lines).encode("utf-8")
        writer.write(wire)
        await writer.drain()
        self._emit_frame(
            "out",
            _SipFrame(
                start_line=f"SIP/2.0 {code} {reason}",
                headers=out_headers,
                body=body_bytes,
                raw=wire,
            ),
        )

    def _invite_received_at(self, frame: "_SipFrame") -> float:
        try:
            return float(getattr(frame, "_received_at", 0.0))
        except (TypeError, ValueError):
            return 0.0

    def _frame_station_id(self, frame: "_SipFrame") -> str:
        from_header = _header(frame.headers, "From")
        station = _user_from_uri(from_header)
        if station:
            return station
        if " " in frame.start_line:
            return _user_from_uri(frame.start_line.split(" ", 2)[1])
        return ""

    def _pop_pending_invite(self, station_id: str) -> "_SipFrame | None":
        station_id = str(station_id or "").strip()
        now = time.time()
        fallback: _SipFrame | None = None
        for call_id, frame in list(self._open_invites.items()):
            if now - self._invite_received_at(frame) > 45:
                self._open_invites.pop(call_id, None)
                continue
            if self._frame_station_id(frame) == station_id:
                return self._open_invites.pop(call_id)
            if fallback is None:
                fallback = frame
        if fallback is not None and len(self._open_invites) == 1:
            call_id = _header(fallback.headers, "Call-ID")
            return self._open_invites.pop(call_id, None)
        return None

    def _finish_accepted_dialog(self, call_id: str, reason: str) -> None:
        dialog = self._accepted_dialogs.pop(call_id, None)
        self._ended_dialog_reasons[call_id] = reason
        while len(self._ended_dialog_reasons) > 20:
            self._ended_dialog_reasons.pop(next(iter(self._ended_dialog_reasons)))
        if dialog is None:
            return
        dialog.end_reason = reason
        dialog.ended_event.set()

    async def _send_request(
        self,
        writer: asyncio.StreamWriter,
        method: str,
        uri: str,
        headers: list[str],
        body: str,
    ) -> None:
        body_bytes = body.encode("utf-8")
        lines = [
            f"{method} {uri} SIP/2.0",
            *headers,
            f"Content-Length: {len(body_bytes)}",
            "",
            body,
        ]
        wire = "\r\n".join(lines).encode("utf-8")
        writer.write(wire)
        await writer.drain()
        # Build a parsed view so on_frame sees a uniform structure.
        parsed_headers: list[tuple[str, str]] = []
        for line in headers:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            parsed_headers.append((key.strip(), value.strip()))
        parsed_headers.append(("Content-Length", str(len(body_bytes))))
        self._emit_frame(
            "out",
            _SipFrame(
                start_line=f"{method} {uri} SIP/2.0",
                headers=parsed_headers,
                body=body_bytes,
                raw=wire,
            ),
        )

    # ----- Frame reader -----

    async def _read_frame(self, reader: asyncio.StreamReader) -> "_SipFrame":
        head = await reader.readuntil(b"\r\n\r\n")
        start_line, headers = _parse_headers(head[:-4])
        cl_match = re.search(rb"Content-Length:\s*(\d+)", head, re.IGNORECASE)
        body = b""
        if cl_match:
            length = int(cl_match.group(1))
            if length > 0:
                body = await reader.readexactly(length)
        frame = _SipFrame(start_line=start_line, headers=headers, body=body, raw=head + body)
        setattr(frame, "_received_at", time.time())
        return frame

    async def _read_final_response(self, reader: asyncio.StreamReader) -> "_SipFrame":
        while True:
            frame = await self._read_frame(reader)
            # Emit every frame, provisional or final, so subscribers see the
            # full REGISTER round-trip (challenge + retry).
            self._emit_frame("in", frame)
            if frame.is_response and 100 <= (frame.status_code or 0) < 200:
                continue
            return frame


@dataclass
class _SipFrame:
    """Parsed SIP message (request or response)."""

    start_line: str
    headers: list[tuple[str, str]]
    body: bytes
    raw: bytes

    @property
    def is_response(self) -> bool:
        return self.start_line.startswith("SIP/2.0 ")

    @property
    def method(self) -> str:
        if self.is_response:
            return ""
        return self.start_line.split(" ", 1)[0].upper()

    @property
    def status_code(self) -> int | None:
        if not self.is_response:
            return None
        parts = self.start_line.split()
        if len(parts) < 2:
            return None
        try:
            return int(parts[1])
        except ValueError:
            return None
