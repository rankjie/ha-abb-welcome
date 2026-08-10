"""On-demand RTP receiver + RTSP publisher for ABB streaming.

The integration's job:

* SIP-dial the outdoor station when a downstream WebRTC consumer asks
  for the stream
* receive the gateway's RTP/AVP (H.264 video + PCMA audio) on UDP
* push each packet onto an RTSP control connection to HA's bundled
  go2rtc — TCP-interleaved, so video/audio framing is preserved and
  there's no extra muxing latency or "green frame" recovery problem

Closing the pipeline tears everything down: cancel keepalives, BYE
the SIP call, TEARDOWN the RTSP session.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import math
import re
import secrets
import socket
import struct
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .intercom_dialer import CallState, Door, IntercomDialer

_LOGGER = logging.getLogger(__name__)

_KEEPALIVE_INTERVAL = 1.0
_RTCP_INTERVAL = 5.0
_PCMA_SILENCE_20MS = b"\xd5" * 160

# H.264 NAL unit type names for diagnostics
_NAL_TYPE_NAMES = {
    0: "unspecified", 1: "non-IDR", 2: "part-A", 3: "part-B",
    4: "part-C", 5: "IDR", 6: "SEI", 7: "SPS", 8: "PPS",
    9: "AUD", 10: "end-seq", 11: "end-stream", 12: "filler",
    24: "STAP-A", 28: "FU-A", 99: "annex-b",
}


def _parse_nal_types(payload: bytes) -> list[int]:
    """Extract NAL unit types from an H264 RTP payload (RFC 6184 or Annex B)."""
    if not payload:
        return []
    # Annex-B detection is only a fallback.  On ABB WiFi panels the payload
    # is decrypted before we get here and is always plain RFC 6184, so a
    # leading 0x00 means "forbidden_zero_bit set / bad packet", not Annex B.
    if len(payload) >= 4 and payload[0] == 0 and payload[1] == 0:
        if payload[2] == 1:
            # 3-byte start code: 00 00 01 [NAL header] [data] ...
            types = []
            i = 0
            while i + 3 <= len(payload):
                if payload[i] == 0 and payload[i + 1] == 0 and payload[i + 2] == 1:
                    if i + 3 < len(payload):
                        types.append(payload[i + 3] & 0x1F)
                    i += 3
                    while i < len(payload) and not (payload[i] == 0 and i + 2 < len(payload) and payload[i + 1] == 0 and payload[i + 2] == 1):
                        i += 1
                else:
                    i += 1
            return types if types else [99]  # 99 = annex-b detected but no NALs found
        if len(payload) >= 4 and payload[2] == 0 and payload[3] == 1:
            # 4-byte start code: 00 00 00 01 [NAL header] [data] ...
            types = []
            i = 0
            while i + 4 <= len(payload):
                if payload[i] == 0 and payload[i + 1] == 0 and payload[i + 2] == 0 and payload[i + 3] == 1:
                    if i + 4 < len(payload):
                        types.append(payload[i + 4] & 0x1F)
                    i += 4
                    while i < len(payload) and not (i + 3 < len(payload) and payload[i] == 0 and payload[i + 1] == 0 and payload[i + 2] == 0 and payload[i + 3] == 1):
                        if i + 2 < len(payload) and payload[i] == 0 and payload[i + 1] == 0 and payload[i + 2] == 1:
                            break
                        i += 1
                else:
                    i += 1
            return types if types else [99]
    # Standard RFC 6184 parsing
    nal_type = payload[0] & 0x1F
    if nal_type <= 23:
        return [nal_type]
    if nal_type == 24:  # STAP-A
        types = []
        i = 1  # skip the STAP-A header byte
        while i + 2 <= len(payload):
            nalu_len = struct.unpack_from("!H", payload, i)[0]
            i += 2
            if i >= len(payload):
                break
            types.append(payload[i] & 0x1F)
            i += nalu_len
        return [24] + types
    if nal_type == 28:  # FU-A
        if len(payload) >= 2:
            fu_type = payload[1] & 0x1F
            start_bit = payload[1] & 0x80
            return [28, fu_type] if start_bit else [28]
        return [28]
    return [nal_type]


def _build_rtp_keepalive(seq: int, pt: int = 0) -> bytes:
    return struct.pack("!BBHII", 0x80, pt & 0x7F, seq & 0xFFFF, 0, 0xCAFEBABE)


def _build_rtcp_pli(reporter: int, media: int) -> bytes:
    return struct.pack("!BBHII", 0x81, 206, 2, reporter, media)


def _build_rtcp_fir(reporter: int, media: int, seq_nr: int) -> bytes:
    """Build RTCP FIR (Full Intra Refresh) packet per RFC 5104 4.3.1."""
    return struct.pack(
        "!BBHIIIBBBB",
        0x84, 206, 4,          # V=2, P=0, FMT=4, PT=206, length=4
        reporter & 0xFFFFFFFF,  # SSRC of sender
        0,                       # Unused
        media & 0xFFFFFFFF,     # SSRC of media source
        seq_nr & 0xFF,          # Seq nr.
        0, 0, 0,                # Reserved (3 bytes)
    )


def _build_rtcp_rr(reporter: int, source: int, last_seq: int) -> bytes:
    return struct.pack(
        "!BBH IIIIIII",
        0x81, 201, 7,
        reporter & 0xFFFFFFFF,
        source & 0xFFFFFFFF,
        0,
        last_seq & 0xFFFFFFFF,
        0, 0, 0,
    )


def _rtp_payload(data: bytes) -> bytes | None:
    if len(data) < 12 or (data[0] >> 6) != 2:
        return None
    cc = data[0] & 0x0F
    offset = 12 + (cc * 4)
    if len(data) < offset:
        return None
    if data[0] & 0x10:
        if len(data) < offset + 4:
            return None
        extension_words = struct.unpack_from("!H", data, offset + 2)[0]
        offset += 4 + (extension_words * 4)
        if len(data) < offset:
            return None
    end = len(data)
    if data[0] & 0x20:
        padding = data[-1]
        if padding == 0 or padding > end - offset:
            return None
        end -= padding
    return data[offset:end]


def _linear16_to_pcma_sample(sample: int) -> int:
    sample = max(-32768, min(32767, sample)) >> 3
    if sample >= 0:
        mask = 0xD5
    else:
        mask = 0x55
        sample = -sample - 1
    if sample > 0xFFF:
        sample = 0xFFF

    seg_ends = (0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF)
    seg = 0
    while seg < 8 and sample > seg_ends[seg]:
        seg += 1

    if seg >= 8:
        aval = 0x7F
    else:
        aval = seg << 4
        if seg < 2:
            aval |= (sample >> 1) & 0x0F
        else:
            aval |= (sample >> seg) & 0x0F
    return aval ^ mask


try:  # numpy ships with Home Assistant core; degrade gracefully if absent.
    import numpy as _np
except Exception:  # noqa: BLE001 - any import failure means "no fast path"
    _np = None

# A-law has only 65 536 possible 16-bit inputs, so we precompute the whole
# mapping once from the reference scalar encoder.  The table is therefore
# byte-for-byte identical to the per-sample implementation, but lookups are
# branch-free.  Talkback encoding runs inside the event loop on every audio
# chunk, so keeping it off the per-sample Python path keeps RTP forwarding for
# the rest of the pipeline responsive.
_ALAW_TABLE: bytes = bytes(_linear16_to_pcma_sample(s) for s in range(-32768, 32768))
_ALAW_LUT = _np.frombuffer(_ALAW_TABLE, dtype=_np.uint8) if _np is not None else None


def _encode_pcm16le_to_pcma(pcm: bytes) -> bytes:
    n = len(pcm) // 2
    if n == 0:
        return b""
    usable = pcm[: n * 2]
    if _ALAW_LUT is not None:
        # int16 + 32768 would overflow the int16 dtype, so widen first.
        samples = _np.frombuffer(usable, dtype="<i2").astype(_np.int32)
        return _ALAW_LUT[samples + 32768].tobytes()
    table = _ALAW_TABLE
    out = bytearray(n)
    for i, sample in enumerate(struct.unpack("<%dh" % n, usable)):
        out[i] = table[sample + 32768]
    return bytes(out)


class _PCMATalkSender:
    """Continuous PCMA RTP sender for the intercom talkback uplink."""

    def __init__(
        self,
        transport: asyncio.DatagramTransport,
        dest: tuple[str, int],
        *,
        payload_type: int = 8,
        samples_per_packet: int = 160,
        packet_rate: int = 50,
        max_queue_frames: int = 25,
        encrypt: Callable[[bytes], bytes] | None = None,
    ) -> None:
        self.transport = transport
        self.dest = dest
        self.payload_type = payload_type
        self._encrypt = encrypt
        self.samples_per_packet = samples_per_packet
        self.interval = 1.0 / packet_rate
        self.max_queue_frames = max_queue_frames
        self.ssrc = secrets.randbits(32)
        self.seq = secrets.randbits(16)
        self.timestamp = secrets.randbits(32)
        self.talking = False
        self._marker_next = False
        self._pcm_buffer = bytearray()
        self._queued_pcma: deque[bytes] = deque()
        self._pcma_buffer = bytearray()
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self.packets_sent = 0
        self.bytes_sent = 0
        self.frames_received = 0
        self.voice_packets_sent = 0
        self.silence_packets_sent = 0
        self.underrun_silence_packets = 0
        self.dropped_frames = 0

    @property
    def active(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._loop(), name="abb_pcma_talk_sender")

    async def stop(self) -> None:
        self.stop_talk()
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    def start_talk(self) -> None:
        self.talking = True
        self._marker_next = True

    def stop_talk(self) -> None:
        self.talking = False
        self._marker_next = False
        self._pcm_buffer.clear()
        self._pcma_buffer.clear()
        self._queued_pcma.clear()

    async def drain(self, timeout: float = 1.0) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while self._queued_pcma and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(self.interval)

    def feed_pcm16le(self, pcm: bytes) -> int:
        if not self.talking:
            return 0
        self._pcm_buffer.extend(pcm)
        frame_bytes = self.samples_per_packet * 2
        queued = 0
        while len(self._pcm_buffer) >= frame_bytes:
            frame = bytes(self._pcm_buffer[:frame_bytes])
            del self._pcm_buffer[:frame_bytes]
            self._queued_pcma.append(_encode_pcm16le_to_pcma(frame))
            self.frames_received += 1
            queued += 1
            while len(self._queued_pcma) > self.max_queue_frames:
                self._queued_pcma.popleft()
                self.dropped_frames += 1
        return queued

    def feed_pcma(self, pcma: bytes) -> int:
        """Queue already-PCMA-encoded audio (ONVIF backchannel path).

        go2rtc negotiates PCMA/8000 on the backchannel, so its packets are
        already in the exact codec the panel wants.  Re-decoding to PCM16
        and re-encoding would be lossy and pointless: we just re-frame the
        bytes to our packet size and hand them to the same queue used by
        the service-call path.
        """
        if not self.talking:
            return 0
        self._pcma_buffer.extend(pcma)
        frame_bytes = self.samples_per_packet
        queued = 0
        while len(self._pcma_buffer) >= frame_bytes:
            frame = bytes(self._pcma_buffer[:frame_bytes])
            del self._pcma_buffer[:frame_bytes]
            self._queued_pcma.append(frame)
            self.frames_received += 1
            queued += 1
            while len(self._queued_pcma) > self.max_queue_frames:
                self._queued_pcma.popleft()
                self.dropped_frames += 1
        return queued

    async def _loop(self) -> None:
        loop = asyncio.get_running_loop()
        next_at = loop.time()
        while not self._stop.is_set():
            payload = _PCMA_SILENCE_20MS
            marker = False
            if self.talking:
                if self._queued_pcma:
                    payload = self._queued_pcma.popleft()
                    marker = self._marker_next
                    self._marker_next = False
                    self.voice_packets_sent += 1
                else:
                    self.underrun_silence_packets += 1
                    self.silence_packets_sent += 1
            else:
                self.silence_packets_sent += 1

            self._send_pcma(payload, marker=marker)
            next_at += self.interval
            sleep_for = next_at - loop.time()
            if sleep_for > 0:
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=sleep_for)
                    return
                except asyncio.TimeoutError:
                    pass
            else:
                next_at = loop.time()

    def _send_pcma(self, payload: bytes, *, marker: bool = False) -> None:
        header = struct.pack(
            "!BBHII",
            0x80,
            (0x80 if marker else 0) | (self.payload_type & 0x7F),
            self.seq & 0xFFFF,
            self.timestamp & 0xFFFFFFFF,
            self.ssrc & 0xFFFFFFFF,
        )
        samples = len(payload)
        wire_payload = self._encrypt(payload) if self._encrypt else payload
        self.transport.sendto(header + wire_payload, self.dest)
        self.packets_sent += 1
        self.bytes_sent += len(header) + len(wire_payload)
        self.seq = (self.seq + 1) & 0xFFFF
        # Advance the RTP clock by the number of *samples*, not by the
        # encrypted wire length (which is padded to a 16-byte boundary).
        self.timestamp = (self.timestamp + samples) & 0xFFFFFFFF

    def stats(self) -> dict[str, Any]:
        return {
            "talking": self.talking,
            "active": self.active,
            "packets": self.packets_sent,
            "bytes": self.bytes_sent,
            "frames": self.frames_received,
            "voice_packets": self.voice_packets_sent,
            "silence_packets": self.silence_packets_sent,
            "underrun_packets": self.underrun_silence_packets,
            "dropped_frames": self.dropped_frames,
            "queue_frames": len(self._queued_pcma),
            "payload_type": self.payload_type,
            "ssrc": self.ssrc,
            "dest": f"{self.dest[0]}:{self.dest[1]}",
        }


def best_local_ip_for(host: str) -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((host, 9))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def _alloc_udp(bind_ip: str) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind_ip, 0))
    s.setblocking(False)
    return s


# ---------------------------------------------------------------------------
# ABB WiFi panel payload encryption
# ---------------------------------------------------------------------------
#
# The M22401-W style WiFi panel does NOT send plain RTP/AVP media even
# though its SDP says ``RTP/AVP``.  Each RTP payload is:
#
#     [2 bytes big-endian plaintext length][AES-128-ECB ciphertext]
#
# The ciphertext is zero/garbage padded up to a 16-byte boundary, so the
# observed payload length is always ``2 + ceil(len/16)*16``.  The AES key
# is the *raw* base64 blob from the SDP ``a=crypto:1 AES_CM_128_HMAC_SHA1_32
# inline:<b64>`` line — it decodes to exactly 16 ASCII bytes and is used
# directly as the AES-128 key.  This is NOT standard SRTP: there is no
# AES-CM keystream, no salt, no auth tag, and no ROC.
#
# Decrypting yields ordinary RFC 6184 H.264 RTP payloads (single NAL,
# STAP-A, FU-A) including the SPS/PPS/IDR that earlier versions were
# hunting for.  What looked like "NAL type 0/2/3/4 with nri=0" was simply
# the high byte of the 2-byte length prefix.

_CRYPTO_INLINE_RE = re.compile(r"inline:([A-Za-z0-9+/=]+)")


def parse_crypto_key(crypto_lines: list[str]) -> bytes | None:
    """Extract the 16-byte AES key from SDP ``a=crypto:`` lines."""
    for line in crypto_lines:
        match = _CRYPTO_INLINE_RE.search(line)
        if not match:
            continue
        try:
            raw = base64.b64decode(match.group(1) + "===")
        except Exception:  # noqa: BLE001
            continue
        if len(raw) >= 16:
            return raw[:16]
    return None


def _aes_ecb_decryptor(key: bytes):
    """Return a callable decrypting whole 16-byte blocks with AES-128-ECB."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cipher = Cipher(algorithms.AES(key), modes.ECB())

    def _decrypt(data: bytes) -> bytes:
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()

    return _decrypt


def make_abb_payload_encryptor(key: bytes) -> Callable[[bytes], bytes]:
    """Build the inverse of :func:`decrypt_abb_rtp` for the uplink.

    Produces ``[2-byte BE plaintext length][AES-128-ECB ciphertext]`` with
    the plaintext zero-padded up to a 16-byte boundary — byte-for-byte the
    same framing the panel uses for its own media.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cipher = Cipher(algorithms.AES(key), modes.ECB())

    def _encrypt(payload: bytes) -> bytes:
        pad = (-len(payload)) % 16
        enc = cipher.encryptor()
        blob = enc.update(payload + b"\x00" * pad) + enc.finalize()
        return struct.pack("!H", len(payload)) + blob

    return _encrypt


def rtp_header_length(data: bytes) -> int:
    """Length of the RTP header including CSRCs and any extension."""
    if len(data) < 12:
        return 0
    csrc_count = data[0] & 0x0F
    has_ext = (data[0] >> 4) & 0x01
    offset = 12 + 4 * csrc_count
    if has_ext and len(data) >= offset + 4:
        ext_words = struct.unpack_from("!H", data, offset + 2)[0]
        offset += 4 + 4 * ext_words
    return offset if offset <= len(data) else 0


def decrypt_abb_rtp(data: bytes, decrypt: Callable[[bytes], bytes]) -> bytes | None:
    """Return the RTP packet with its payload decrypted, or ``None``."""
    offset = rtp_header_length(data)
    if offset == 0:
        return None
    payload = data[offset:]
    if len(payload) < 18:
        return None
    declared = struct.unpack_from("!H", payload, 0)[0]
    ciphertext = payload[2:]
    if not declared or len(ciphertext) % 16 or declared > len(ciphertext):
        return None
    if len(ciphertext) - declared >= 16:
        # Padding must be less than one full block; otherwise the length
        # prefix guess is wrong and we should not touch the packet.
        return None
    return data[:offset] + decrypt(ciphertext)[:declared]


class _RTPProtocol(asyncio.DatagramProtocol):
    """Receive gateway RTP, optionally rewrite PT, hand off to publisher.

    PT rewriting matters because the ABB gateway negotiates one PT in
    SDP but emits a different PT on the wire.  When we ANNOUNCE our
    SDP to go2rtc we pick a single PT; rewriting incoming packets to
    match keeps go2rtc happy.
    """

    def __init__(
        self,
        on_packet: Callable[[bytes], None],
        rewrite_pt: int | None,
        on_first_packet: Callable[[bytes], None] | None,
        label: str = "rtp",
        decrypt_key: bytes | None = None,
        gate_until_sps: bool = False,
        on_parameter_sets: Callable[[bytes, bytes], None] | None = None,
        accept_pts: set[int] | None = None,
    ) -> None:
        # Payload types we are willing to forward.  Anything else (DTMF
        # telephone-event, a codec the panel switches to mid-call) is
        # counted and dropped rather than confusing the RTSP consumer.
        self._accept_pts = accept_pts
        self.dropped_pts: dict[int, int] = {}
        self._on_packet = on_packet
        self._rewrite_pt = rewrite_pt
        self._on_first_packet = on_first_packet
        self.label = label
        # Payload decryption (ABB WiFi panel)
        self._decrypt = _aes_ecb_decryptor(decrypt_key) if decrypt_key else None
        self.decrypt_ok = 0
        self.decrypt_failed = 0
        # Start-of-stream gating: hold packets back until SPS is seen so
        # go2rtc's H.264 depacketiser starts on a decodable boundary.
        self._gate_until_sps = gate_until_sps
        self._gate_open = not gate_until_sps
        self._gate_dropped = 0
        self._gate_deadline = 0.0
        self._on_parameter_sets = on_parameter_sets
        self.sps: bytes | None = None
        self.pps: bytes | None = None
        self.transport: asyncio.DatagramTransport | None = None
        self.packets = 0
        self.bytes_received = 0
        self.last_seq = 0
        self.media_ssrc = 0
        self.payload_types: dict[int, int] = {}
        self._rewrites = 0
        # H.264 NAL diagnostics (video only)
        self._nal_counts: dict[int, int] = {}
        self._diag_logged = 0
        self._marker_count = 0
        self._seq_gaps = 0
        # Raw RTP capture for debugging
        self._capture_file = None
        self._capture_count = 0
        # Raw capture is disabled now that the payload format is known; it
        # did blocking file I/O inside the event loop.  Set to a positive
        # number only when a fresh on-the-wire sample is needed.
        self._capture_max = 0

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        if self._gate_until_sps:
            self._gate_deadline = asyncio.get_running_loop().time() + 8.0

    def _note_parameter_sets(self, payload: bytes) -> None:
        """Remember SPS/PPS so the RTSP SDP can advertise sprop-parameter-sets."""
        if not payload:
            return
        nal_type = payload[0] & 0x1F
        units: list[bytes] = []
        if nal_type == 24:  # STAP-A aggregate
            offset = 1
            while offset + 2 <= len(payload):
                size = struct.unpack_from("!H", payload, offset)[0]
                offset += 2
                if size == 0 or offset + size > len(payload):
                    break
                units.append(payload[offset:offset + size])
                offset += size
        else:
            units.append(payload)
        changed = False
        for unit in units:
            if not unit:
                continue
            unit_type = unit[0] & 0x1F
            if unit_type == 7 and unit != self.sps:
                self.sps = unit
                changed = True
            elif unit_type == 8 and unit != self.pps:
                self.pps = unit
                changed = True
        if changed and self.sps and self.pps and self._on_parameter_sets:
            try:
                self._on_parameter_sets(self.sps, self.pps)
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("on_parameter_sets handler raised: %s", err)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.packets += 1
        self.bytes_received += len(data)
        if (
            self._accept_pts is not None
            and len(data) >= 12
            and not 192 <= data[1] <= 223
        ):
            incoming_pt = data[1] & 0x7F
            if incoming_pt not in self._accept_pts:
                count = self.dropped_pts.get(incoming_pt, 0) + 1
                self.dropped_pts[incoming_pt] = count
                if count == 1:
                    _LOGGER.info(
                        "[abb] media: %s dropping unnegotiated payload type %d",
                        self.label, incoming_pt,
                    )
                return
        if self._decrypt is not None and len(data) >= 12 and not (
            192 <= data[1] <= 223
        ):
            decrypted = decrypt_abb_rtp(data, self._decrypt)
            if decrypted is None:
                self.decrypt_failed += 1
                if self.decrypt_failed <= 5:
                    _LOGGER.warning(
                        "[abb] media: %s payload decrypt skipped pkt=%d size=%d "
                        "(unexpected framing)",
                        self.label, self.packets, len(data),
                    )
            else:
                data = decrypted
                self.decrypt_ok += 1
                if self.decrypt_ok == 1:
                    _LOGGER.info(
                        "[abb] media: %s payload decryption active "
                        "(AES-128-ECB, first NAL=0x%02x)",
                        self.label, data[rtp_header_length(data)],
                    )
        if len(data) >= 12:
            # Detect RTCP (PT 192-223) BEFORE masking with 0x7F
            rtcp_pt = data[1]
            if 192 <= rtcp_pt <= 223 and len(data) >= 4:
                rtcp_len = (struct.unpack_from("!H", data, 2)[0] + 1) * 4
                fmt = data[0] & 0x1F
                _LOGGER.info(
                    "[abb] media: RTCP received label=%s pt=%d fmt=%d len=%d "
                    "from=%s:%d first_bytes=%s",
                    self.label, rtcp_pt, fmt, rtcp_len, addr[0], addr[1],
                    data[:min(20, len(data))].hex(),
                )
                try:
                    self._on_packet(data)
                except Exception as err:  # noqa: BLE001
                    _LOGGER.debug("on_packet handler raised on RTCP: %s", err)
                return
            pt = data[1] & 0x7F
            self.payload_types[pt] = self.payload_types.get(pt, 0) + 1
            seq = struct.unpack_from("!H", data, 2)[0]
            marker = bool(data[1] & 0x80)
            if marker:
                self._marker_count += 1
            if self.packets > 1:
                expected = (self.last_seq + 1) & 0xFFFF
                if seq != expected:
                    self._seq_gaps += 1
            self.last_seq = seq
            if self.media_ssrc == 0:
                self.media_ssrc = struct.unpack_from("!I", data, 8)[0]
            # H.264 NAL diagnostics — count ALL packets, log periodically
            if self.label == "video":
                payload = data[rtp_header_length(data) or 12:]
                self._note_parameter_sets(payload)
                nal_types = _parse_nal_types(payload)
                for nt in nal_types:
                    self._nal_counts[nt] = self._nal_counts.get(nt, 0) + 1
                self._diag_logged += 1
                if self._diag_logged <= 10 or self._diag_logged % 100 == 0:
                    nal_desc = ", ".join(
                        f"{_NAL_TYPE_NAMES.get(nt, f"type-{nt}")}={self._nal_counts[nt]}"
                        for nt in sorted(self._nal_counts)
                    )
                    ts = struct.unpack_from("!I", data, 4)[0]
                    first_byte_hex = f"0x{payload[0]:02x}" if payload else "none"
                    rtp_byte0_hex = f"0x{data[0]:02x}"
                    hex_dump = payload[:32].hex() if payload else ""
                    _LOGGER.info(
                        "[abb] media: H264 NAL diag pkt=%d rtp_byte0=%s pt=%d seq=%d ts=%u "
                        "marker=%s size=%d payload=%d first_byte=%s hex=%s nal_types=[%s] gaps=%d markers=%d",
                        self.packets, rtp_byte0_hex, pt, seq, ts, marker, len(data), len(payload),
                        first_byte_hex, hex_dump, nal_desc, self._seq_gaps, self._marker_count,
                    )
            if self._rewrite_pt is not None and pt != self._rewrite_pt:
                marker_byte = data[1] & 0x80
                data = (
                    bytes((data[0], marker_byte | (self._rewrite_pt & 0x7F)))
                    + data[2:]
                )
                self._rewrites += 1
        if self.packets == 1 and self._on_first_packet is not None:
            try:
                self._on_first_packet(data)
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("on_first_packet handler raised: %s", err)
        # Hold the stream back until an SPS arrives, so the first bytes
        # go2rtc sees are a decodable parameter-set + keyframe sequence.
        if not self._gate_open:
            if self.sps is not None:
                self._gate_open = True
                _LOGGER.info(
                    "[abb] media: %s SPS seen after %d packets; opening stream "
                    "gate (dropped %d pre-SPS packets)",
                    self.label, self.packets, self._gate_dropped,
                )
            elif asyncio.get_running_loop().time() >= self._gate_deadline:
                self._gate_open = True
                _LOGGER.warning(
                    "[abb] media: %s no SPS within timeout; forwarding anyway "
                    "(dropped %d packets)",
                    self.label, self._gate_dropped,
                )
            else:
                self._gate_dropped += 1
                return
        try:
            self._on_packet(data)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("on_packet handler raised: %s", err)
        # Raw RTP capture for offline analysis
        if self.label == "video" and self._capture_count < self._capture_max:
            self._capture_count += 1
            if self._capture_file is None:
                import os, time
                capture_path = os.path.join(
                    os.path.dirname(__file__),
                    f"rtp_capture_{self.label}_{int(time.time())}.bin",
                )
                self._capture_file = open(capture_path, "wb")
                _LOGGER.info(
                    "[abb] media: raw RTP capture started to %s label=%s",
                    capture_path, self.label,
                )
            # Write: 2-byte length + raw RTP packet
            self._capture_file.write(len(data).to_bytes(2, "big"))
            self._capture_file.write(data)
            if self._capture_count == self._capture_max:
                self._capture_file.flush()
                self._capture_file.close()
                self._capture_file = None
                _LOGGER.info(
                    "[abb] media: raw RTP capture complete (%d packets) label=%s",
                    self._capture_count, self.label,
                )

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("RTP datagram error: %s", exc)


@dataclass
class _MediaEndpoints:
    audio: tuple[str, int] | None
    video: tuple[str, int] | None


class StreamSession:
    """One SIP call + RTP receivers + RTSP publisher to go2rtc.

    Responsibilities:

    * dial the gateway, advertise our UDP ports
    * receive video/audio RTP on those ports
    * forward each packet over an RTSP/TCP-interleaved connection to
      go2rtc (which then serves it as ``rtsp://...`` to its consumers
      and via its WebRTC pipeline to the browser)
    """

    VIDEO_SDP_PT = 96
    AUDIO_SDP_PT = 8  # PCMA static PT — no rewrite needed.

    def __init__(
        self,
        *,
        dialer: IntercomDialer,
        door: Door,
        gateway_host: str,
        camera_index: int | None = None,
        incoming_listener: Any | None = None,
        pickup_allowed: Callable[[], bool] | None = None,
        on_call_ended: Callable[[str, str], None] | None = None,
        on_video_packet: Callable[[bytes], None] | None = None,
        on_audio_packet: Callable[[bytes], None] | None = None,
        wifi_panel: bool = False,
    ) -> None:
        self._dialer = dialer
        self._door = door
        self._gateway_host = gateway_host
        self._camera_index = camera_index
        self._incoming_listener = incoming_listener
        self._pickup_allowed = pickup_allowed
        self._on_call_ended = on_call_ended
        self._on_video_packet = on_video_packet
        self._on_audio_packet = on_audio_packet
        self._wifi_panel = wifi_panel

        self._media_ip = ""
        self._video_sock: socket.socket | None = None
        self._audio_sock: socket.socket | None = None
        self._video_proto: _RTPProtocol | None = None
        self._audio_proto: _RTPProtocol | None = None
        self._video_transport: asyncio.DatagramTransport | None = None
        self._audio_transport: asyncio.DatagramTransport | None = None
        self._call: CallState | None = None
        self._accepted_incoming_call_id: str | None = None
        self._accepted_incoming_ack_received: bool | None = None
        self._incoming_end_task: asyncio.Task | None = None
        self._outbound_end_task: asyncio.Task | None = None
        self._endpoints = _MediaEndpoints(None, None)
        self._video_codec = "H264/90000"
        self._video_fmtp: str | None = None
        self._video_crypto_key: bytes | None = None
        self._audio_crypto_key: bytes | None = None
        self._audio_codec = "PCMA/8000"
        self._sprop_fmtp: str | None = None
        self._remote_audio_pt = 8
        self._remote_video_pt = 102
        self._talk_sender: _PCMATalkSender | None = None

        self._stop = asyncio.Event()
        self._keepalive_task: asyncio.Task | None = None
        self._rtcp_task: asyncio.Task | None = None
        self._stats_task: asyncio.Task | None = None
        self._keyframe_task: asyncio.Task | None = None
        self._video_media_ssrc: int = 0
        self._fir_seq: int = 0

    @property
    def active(self) -> bool:
        return self._call is not None

    @property
    def video_codec(self) -> str:
        return self._video_codec

    @property
    def video_fmtp(self) -> str | None:
        return self._sprop_fmtp or self._video_fmtp

    @property
    def audio_pt(self) -> int:
        return self._remote_audio_pt

    @property
    def audio_codec(self) -> str:
        return self._audio_codec

    @property
    def talkback_ready(self) -> bool:
        # WiFi panels are no longer excluded: the uplink is encrypted with
        # the panel's own AES key, so what arrives at its speaker is valid
        # PCMA instead of noise.
        return self._talk_sender is not None and self._talk_sender.active

    def talkback_stats(self) -> dict[str, Any]:
        sender = self._talk_sender
        if sender is None:
            return {"active": False, "talking": False}
        return sender.stats()

    def set_packet_handlers(
        self,
        on_video: Callable[[bytes], None] | None,
        on_audio: Callable[[bytes], None] | None,
    ) -> None:
        """Replace the per-packet RTP handlers (used by the RTSP server)."""
        self._on_video_packet = on_video
        self._on_audio_packet = on_audio

    async def open(self) -> None:
        """Dial gateway and start receiving RTP."""
        loop = asyncio.get_running_loop()
        self._accepted_incoming_call_id = None
        self._accepted_incoming_ack_received = None

        self._media_ip = best_local_ip_for(self._gateway_host)
        self._video_sock = _alloc_udp(self._media_ip)
        self._audio_sock = _alloc_udp(self._media_ip)
        offer_audio_port = self._audio_sock.getsockname()[1]
        offer_video_port = self._video_sock.getsockname()[1]

        call = await self._accept_incoming_call_if_pending(
            audio_port=offer_audio_port,
            video_port=offer_video_port,
        )
        accepted_incoming = call is not None
        if call is None:
            if self._wifi_panel:
                _LOGGER.warning(
                    "[abb] media: no incoming call for WiFi panel %s; outbound dialing "
                    "disabled (panel rejects with 403)",
                    self._door.name,
                )
                # Clean up allocated sockets before raising.
                self._video_sock.close()
                self._audio_sock.close()
                self._video_sock = self._audio_sock = None
                raise RuntimeError(
                    "No active call for WiFi panel — camera is only available "
                    "during an incoming ring"
                )
            _LOGGER.info(
                "[abb] media: dialing gateway for door=%s media_ip=%s "
                "audio_port=%d video_port=%d camera_index=%s",
                self._door.name, self._media_ip,
                offer_audio_port, offer_video_port,
                self._camera_index if self._camera_index is not None else "default",
            )
            call = await self._dialer.dial(
                self._door,
                audio_port=offer_audio_port,
                video_port=offer_video_port,
            )
        else:
            _LOGGER.info(
                "[abb] media: using accepted incoming gateway call for door=%s "
                "call_id=%s ack=%s media_ip=%s audio_port=%d video_port=%d",
                self._door.name,
                call.call_id,
                self._accepted_incoming_ack_received,
                self._media_ip,
                offer_audio_port,
                offer_video_port,
            )
        self._call = call
        if accepted_incoming:
            self._start_incoming_end_watcher(call.call_id)
        else:
            self._start_outbound_end_watcher(call.call_id)
        if self._camera_index is not None and self._accepted_incoming_call_id is None:
            switch_body = f"d:{self._camera_index}"
            _LOGGER.info(
                "[abb] media: selecting camera index %d for door=%s "
                "call_id=%s body=%r",
                self._camera_index, self._door.name, call.call_id, switch_body,
            )
            try:
                response = await self._dialer.send_active_message(
                    switch_body, timeout=3.0
                )
                if response is None:
                    _LOGGER.warning(
                        "[abb] media: camera index %d switch timed out for "
                        "door=%s call_id=%s; continuing stream so logs show RTP",
                        self._camera_index, self._door.name, call.call_id,
                    )
                else:
                    _LOGGER.info(
                        "[abb] media: camera index %d switch accepted for "
                        "door=%s call_id=%s response=%s",
                        self._camera_index, self._door.name, call.call_id,
                        response.start_line,
                    )
            except Exception as err:  # noqa: BLE001
                _LOGGER.exception(
                    "[abb] media: camera index %d switch failed for door=%s "
                    "call_id=%s body=%r; continuing default video: %s",
                    self._camera_index, self._door.name, call.call_id,
                    switch_body, err,
                )

        for m in call.answer.medias:
            _LOGGER.info(
                "[abb] media: %s SDP answer camera_index=%s media=%s ip=%s "
                "port=%d pts=%s rtpmap=%s direction=%s",
                self._door.name,
                self._camera_index if self._camera_index is not None else "default",
                m.media, m.connection_ip, m.port,
                m.payload_types, m.rtpmap, m.direction,
            )
            if m.media == "audio" and m.connection_ip and m.port:
                if m.payload_types:
                    self._remote_audio_pt = (
                        8
                        if 8 in m.payload_types
                        else m.payload_types[0]
                    )
                self._endpoints = _MediaEndpoints(
                    audio=(m.connection_ip, m.port),
                    video=self._endpoints.video,
                )
            elif m.media == "video" and m.connection_ip and m.port:
                if m.payload_types:
                    self._remote_video_pt = next(
                        (
                            pt for pt in m.payload_types
                            if "H264" in m.rtpmap.get(pt, "").upper()
                        ),
                        m.payload_types[0],
                    )
                self._endpoints = _MediaEndpoints(
                    audio=self._endpoints.audio,
                    video=(m.connection_ip, m.port),
                )
                if m.payload_types:
                    pt = m.payload_types[0]
                    self._video_codec = m.rtpmap.get(pt, self._video_codec)
                    self._video_fmtp = m.fmtp.get(pt)
                self._video_crypto_key = parse_crypto_key(getattr(m, "crypto", []))
            if m.media == "audio":
                self._audio_crypto_key = parse_crypto_key(getattr(m, "crypto", []))
                if m.payload_types:
                    # The panel lists PCMA first and everything else as a
                    # fallback; we only ever accept the first (negotiated)
                    # one so the RTSP SDP and the wire always agree.
                    self._remote_audio_pt = m.payload_types[0]
                    self._audio_codec = m.rtpmap.get(
                        self._remote_audio_pt, self._audio_codec
                    )

        if self._video_crypto_key:
            _LOGGER.info(
                "[abb] media: %s video payload is encrypted (a=crypto present); "
                "enabling AES-128-ECB payload decryption key_len=%d",
                self._door.name, len(self._video_crypto_key),
            )
        elif self._wifi_panel:
            _LOGGER.warning(
                "[abb] media: %s WiFi panel offered no a=crypto line; video will "
                "be forwarded as-is and may not decode",
                self._door.name,
            )

        def _video_first(data: bytes) -> None:
            _LOGGER.info(
                "[abb] media: first video RTP packet for %s camera_index=%s "
                    "(%d bytes)",
                self._door.name,
                self._camera_index if self._camera_index is not None else "default",
                len(data),
            )
            if self._endpoints.video and self._video_transport:
                ssrc = (
                    struct.unpack_from("!I", data, 8)[0]
                    if len(data) >= 12 else 0
                )
                self._video_media_ssrc = ssrc
                _LOGGER.info(
                    "[abb] media: video SSRC=0x%08X for %s, starting RTCP "
                    "keyframe requests to %s:%d",
                    ssrc, self._door.name,
                    self._endpoints.video[0], self._endpoints.video[1],
                )
                # Start repeated PLI/FIR keyframe request task
                if self._keyframe_task is None:
                    self._keyframe_task = asyncio.get_running_loop().create_task(
                        self._send_keyframe_requests(),
                    )

        def _on_video(packet: bytes) -> None:
            cb = self._on_video_packet
            if cb is not None:
                cb(packet)

        def _on_audio(packet: bytes) -> None:
            cb = self._on_audio_packet
            if cb is not None:
                cb(packet)

        def _on_parameter_sets(sps: bytes, pps: bytes) -> None:
            sprop = (
                f"{base64.b64encode(sps).decode()},"
                f"{base64.b64encode(pps).decode()}"
            )
            profile = sps[1:4].hex() if len(sps) >= 4 else "42e01f"
            self._sprop_fmtp = (
                f"packetization-mode=1;profile-level-id={profile};"
                f"sprop-parameter-sets={sprop}"
            )
            _LOGGER.info(
                "[abb] media: %s H264 parameter sets captured "
                "profile-level-id=%s sprop-parameter-sets=%s",
                self._door.name, profile, sprop,
            )

        self._video_proto = _RTPProtocol(
            on_packet=_on_video,
            rewrite_pt=self.VIDEO_SDP_PT,
            on_first_packet=_video_first,
            label="video",
            decrypt_key=self._video_crypto_key,
            gate_until_sps=self._video_crypto_key is not None,
            on_parameter_sets=_on_parameter_sets,
        )
        self._video_transport, _ = await loop.create_datagram_endpoint(
            lambda: self._video_proto, sock=self._video_sock
        )

        _LOGGER.info(
            "[abb] media: %s audio leg pt=%d codec=%s encrypted=%s",
            self._door.name, self._remote_audio_pt, self._audio_codec,
            self._audio_crypto_key is not None,
        )
        self._audio_proto = _RTPProtocol(
            on_packet=_on_audio,
            rewrite_pt=self._remote_audio_pt,
            on_first_packet=None,
            label="audio",
            decrypt_key=self._audio_crypto_key,
            accept_pts={self._remote_audio_pt},
        )
        self._audio_transport, _ = await loop.create_datagram_endpoint(
            lambda: self._audio_proto, sock=self._audio_sock
        )

        # Punch audio with PCMA PT (8) and video with H.264 PT (102) so
        # the gateway recognises them as legitimate media flows.
        # Keepalives later in ``_keepalive_loop`` use the same PTs.
        #
        # For WiFi panels we skip audio punching entirely — the panel's
        # speaker would otherwise receive RTP and produce deafening noise.
        if self._endpoints.audio and not self._wifi_panel:
            await self._punch(
                self._audio_transport, self._endpoints.audio, pt=self._remote_audio_pt
            )
        if self._endpoints.video:
            await self._punch(
                self._video_transport, self._endpoints.video, pt=self._remote_video_pt
            )

        if self._audio_transport is not None and self._endpoints.audio is not None:
            # WiFi panels used to be excluded here: without knowing the
            # payload encryption, anything we sent arrived as loud noise on
            # the panel speaker.  Now that we can produce correctly framed
            # encrypted PCMA, the uplink is enabled for them too.
            encryptor = (
                make_abb_payload_encryptor(self._audio_crypto_key)
                if self._audio_crypto_key
                else None
            )
            self._talk_sender = _PCMATalkSender(
                self._audio_transport,
                self._endpoints.audio,
                payload_type=self._remote_audio_pt,
                encrypt=encryptor,
            )
            await self._talk_sender.start()
            _LOGGER.info(
                "[abb] media: talkback RTP leg ready for %s -> %s:%d pt=%d "
                "encrypted=%s",
                self._door.name,
                self._endpoints.audio[0],
                self._endpoints.audio[1],
                self._remote_audio_pt,
                encryptor is not None,
            )

        self._stop.clear()
        self._keepalive_task = asyncio.create_task(
            self._keepalive_loop(),
            name=f"abb_keepalive_{self._door.station_id}",
        )
        self._rtcp_task = asyncio.create_task(
            self._rtcp_loop(),
            name=f"abb_rtcp_{self._door.station_id}",
        )
        self._stats_task = asyncio.create_task(
            self._stats_loop(),
            name=f"abb_stats_{self._door.station_id}",
        )

    def _start_incoming_end_watcher(self, call_id: str) -> None:
        listener = self._incoming_listener
        wait_end = getattr(listener, "wait_accepted_call_end", None)
        if not callable(wait_end):
            return
        if self._incoming_end_task is not None:
            self._incoming_end_task.cancel()

        async def _watch() -> None:
            try:
                reason = await wait_end(call_id)
            except asyncio.CancelledError:
                return
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("[abb] media: incoming end watcher failed: %s", err)
                return
            if self._call is None or self._call.call_id != call_id:
                return
            _LOGGER.info(
                "[abb] media: incoming call ended by SIP dialog call_id=%s reason=%s",
                call_id,
                reason,
            )
            await self.close()
            self._notify_call_ended(call_id, reason)

        self._incoming_end_task = asyncio.create_task(
            _watch(), name=f"abb_incoming_call_end_{self._door.station_id}"
        )

    def _start_outbound_end_watcher(self, call_id: str) -> None:
        wait_end = getattr(self._dialer, "wait_call_end", None)
        if not callable(wait_end):
            return
        if self._outbound_end_task is not None:
            self._outbound_end_task.cancel()

        async def _watch() -> None:
            try:
                reason = await wait_end(call_id)
            except asyncio.CancelledError:
                return
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("[abb] media: outbound end watcher failed: %s", err)
                return
            if self._call is None or self._call.call_id != call_id:
                return
            _LOGGER.info(
                "[abb] media: outbound call ended by SIP dialog call_id=%s reason=%s",
                call_id,
                reason,
            )
            await self.close()
            self._notify_call_ended(call_id, reason)

        self._outbound_end_task = asyncio.create_task(
            _watch(), name=f"abb_outbound_call_end_{self._door.station_id}"
        )

    def _notify_call_ended(self, call_id: str, reason: str) -> None:
        if self._on_call_ended is None:
            return
        try:
            self._on_call_ended(call_id, reason)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("[abb] media: call-ended callback failed: %s", err)

    async def _accept_incoming_call_if_pending(
        self,
        *,
        audio_port: int,
        video_port: int,
    ) -> CallState | None:
        """Prefer answering the ringing INVITE over dialing the station again."""
        listener = self._incoming_listener
        station_id = str(self._door.station_id or "").strip()
        if listener is None or not station_id:
            return None
        pending_call_for_station = getattr(listener, "pending_call_for_station", None)
        if (
            callable(pending_call_for_station)
            and pending_call_for_station(station_id)
            and self._pickup_allowed is not None
            and not self._pickup_allowed()
        ):
            _LOGGER.info(
                "[abb] media: refusing incoming pickup for door=%s station=%s "
                "because pickup is disabled",
                self._door.name,
                station_id,
            )
            raise RuntimeError("ABB Welcome incoming-call pickup is disabled")
        accept = getattr(listener, "accept_pending_call", None)
        if not callable(accept):
            return None
        try:
            accepted = await accept(
                station_id=station_id,
                media_ip=self._media_ip,
                audio_port=audio_port,
                video_port=video_port,
            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.exception(
                "[abb] media: failed to accept incoming call for door=%s "
                "station=%s: %s",
                self._door.name,
                station_id,
                err,
            )
            return None
        if accepted is None:
            return None
        self._accepted_incoming_call_id = accepted.call_id
        self._accepted_incoming_ack_received = accepted.ack_received
        return CallState(
            door=self._door,
            call_id=accepted.call_id,
            local_tag=accepted.local_tag,
            remote_tag=accepted.remote_tag,
            invite_cseq=accepted.invite_cseq,
            request_uri=accepted.caller_uri,
            remote_contact=accepted.remote_contact,
            audio_local_port=accepted.audio_local_port,
            video_local_port=accepted.video_local_port,
            answer=accepted.remote_sdp,
        )

    async def _send_keyframe_requests(self) -> None:
        """Send repeated RTCP PLI + FIR to request keyframes from the panel."""
        reporter_ssrc = 0xCAFEBABE
        attempts = 0
        max_attempts = 20  # 20 * 0.5s = 10s
        try:
            while not self._stop.is_set() and attempts < max_attempts:
                attempts += 1
                vp = self._video_proto
                media_ssrc = self._video_media_ssrc or (vp.media_ssrc if vp else 0)
                if media_ssrc == 0 or self._video_transport is None or self._endpoints.video is None:
                    _LOGGER.info("[abb] media: keyframe task attempt %d waiting for SSRC/transport", attempts)
                    await asyncio.sleep(0.5)
                    continue
                # Check if we already got SPS/PPS/IDR
                if vp and (7 in vp._nal_counts or 8 in vp._nal_counts or 5 in vp._nal_counts):
                    _LOGGER.info(
                        "[abb] media: keyframe detected after %d PLI/FIR attempts "
                        "for %s (SPS=%d PPS=%d IDR=%d), stopping requests",
                        attempts, self._door.name,
                        vp._nal_counts.get(7, 0),
                        vp._nal_counts.get(8, 0),
                        vp._nal_counts.get(5, 0),
                    )
                    return
                try:
                    # Send PLI
                    pli_pkt = _build_rtcp_pli(reporter_ssrc, media_ssrc)
                    self._video_transport.sendto(pli_pkt, self._endpoints.video)
                    _LOGGER.info(
                        "[abb] media: sent PLI (%d bytes) to %s:%d attempt %d/%d",
                        len(pli_pkt), self._endpoints.video[0],
                        self._endpoints.video[1], attempts, max_attempts,
                    )
                    # Send FIR
                    self._fir_seq = (self._fir_seq + 1) & 0xFF
                    fir_pkt = _build_rtcp_fir(reporter_ssrc, media_ssrc, self._fir_seq)
                    self._video_transport.sendto(fir_pkt, self._endpoints.video)
                    _LOGGER.info(
                        "[abb] media: sent FIR (%d bytes) to %s:%d attempt %d/%d",
                        len(fir_pkt), self._endpoints.video[0],
                        self._endpoints.video[1], attempts, max_attempts,
                    )
                    # Also try RTCP port (port + 1)
                    rtcp_addr = (self._endpoints.video[0], self._endpoints.video[1] + 1)
                    try:
                        self._video_transport.sendto(pli_pkt, rtcp_addr)
                        self._video_transport.sendto(fir_pkt, rtcp_addr)
                    except OSError:
                        pass
                except OSError as err:
                    _LOGGER.warning("[abb] media: RTCP keyframe send failed: %s", err)
                await asyncio.sleep(0.5)
            _LOGGER.info(
                "[abb] media: keyframe requests exhausted after %d attempts "
                "for %s — no SPS/PPS/IDR received",
                attempts, self._door.name,
            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.exception("[abb] media: keyframe task crashed: %s", err)

    async def close(self) -> None:
        current_task = asyncio.current_task()
        vp = self._video_proto
        _LOGGER.info(
            "[abb] media: closing stream for %s "
            "camera_index=%s (video_pkts=%d audio_pkts=%d rewrites=%d)",
            self._door.name,
            self._camera_index if self._camera_index is not None else "default",
            vp.packets if vp else 0,
            self._audio_proto.packets if self._audio_proto else 0,
            vp._rewrites if vp else 0,
        )
        # H.264 NAL summary
        if vp and vp._nal_counts:
            nal_desc = ", ".join(
                f"{_NAL_TYPE_NAMES.get(nt, f'type-{nt}')}={vp._nal_counts[nt]}"
                for nt in sorted(vp._nal_counts)
            )
            has_sps = 7 in vp._nal_counts
            has_pps = 8 in vp._nal_counts
            has_idr = 5 in vp._nal_counts
            _LOGGER.info(
                "[abb] media: H264 NAL summary for %s: [%s] "
                "SPS=%s PPS=%s IDR=%s markers=%d seq_gaps=%d diag_pkts=%d "
                "decrypted=%d decrypt_failed=%d gate_dropped=%d",
                self._door.name, nal_desc,
                has_sps, has_pps, has_idr,
                vp._marker_count, vp._seq_gaps, vp._diag_logged,
                vp.decrypt_ok, vp.decrypt_failed, vp._gate_dropped,
            )
        if (
            self._incoming_end_task is not None
            and self._incoming_end_task is not current_task
        ):
            self._incoming_end_task.cancel()
            try:
                await self._incoming_end_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._incoming_end_task = None
        if (
            self._outbound_end_task is not None
            and self._outbound_end_task is not current_task
        ):
            self._outbound_end_task.cancel()
            try:
                await self._outbound_end_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._outbound_end_task = None

        self._stop.set()
        for t in (self._keepalive_task, self._rtcp_task, self._stats_task, self._keyframe_task):
            if t is not None:
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
        self._keepalive_task = self._rtcp_task = self._stats_task = self._keyframe_task = None

        if self._talk_sender is not None:
            await self._talk_sender.stop()
            self._talk_sender = None

        for tr in (self._video_transport, self._audio_transport):
            if tr is not None:
                tr.close()
        self._video_transport = self._audio_transport = None
        self._video_sock = self._audio_sock = None
        self._video_proto = self._audio_proto = None

        if self._call is not None:
            try:
                # Scope the hangup to *our* call_id.  Another camera
                # may have replaced the dialer's call between when we
                # dialed and now (the dialer auto-bumps the previous
                # call); without this scope our close() would BYE the
                # successor's call by accident.
                if self._accepted_incoming_call_id is not None:
                    listener = self._incoming_listener
                    hangup = getattr(listener, "hangup_accepted_call", None)
                    if callable(hangup):
                        await hangup(self._accepted_incoming_call_id)
                else:
                    await self._dialer.hangup(call_id=self._call.call_id)
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("[abb] media: hangup failed: %s", err)
            self._call = None
            self._accepted_incoming_call_id = None
            self._accepted_incoming_ack_received = None

        self._endpoints = _MediaEndpoints(None, None)

    def start_talkback(self) -> dict[str, Any]:
        sender = self._talk_sender
        if sender is None or not sender.active:
            raise RuntimeError("talkback is not ready; open the camera stream first")
        sender.start_talk()
        return sender.stats()

    def stop_talkback(self) -> dict[str, Any]:
        sender = self._talk_sender
        if sender is None:
            return {"active": False, "talking": False}
        sender.stop_talk()
        return sender.stats()

    def feed_talkback_pcm16le(self, pcm: bytes) -> dict[str, Any]:
        sender = self._talk_sender
        if sender is None or not sender.active:
            raise RuntimeError("talkback is not ready; open the camera stream first")
        queued = sender.feed_pcm16le(pcm)
        stats = sender.stats()
        stats["queued_frames_now"] = queued
        return stats

    def feed_talkback_pcma(self, pcma: bytes) -> int:
        """Feed PCMA from the ONVIF backchannel; auto-starts talking.

        Unlike the service-call path there is no explicit start/stop here:
        the arrival of packets *is* the start signal, and the watchdog in
        the camera entity stops us again once they dry up.
        """
        sender = self._talk_sender
        if sender is None or not sender.active:
            return 0
        if not sender.talking:
            sender.start_talk()
        return sender.feed_pcma(pcma)

    def backchannel_idle(self) -> None:
        """Called by the watchdog when backchannel packets stop arriving."""
        sender = self._talk_sender
        if sender is not None and sender.talking:
            sender.stop_talk()

    async def send_talkback_tone(
        self,
        *,
        duration_ms: int = 1200,
        frequency_hz: int = 880,
        amplitude: float = 0.35,
    ) -> dict[str, Any]:
        sender = self._talk_sender
        if sender is None or not sender.active:
            raise RuntimeError("talkback is not ready; open the camera stream first")
        duration_ms = max(100, min(int(duration_ms), 5000))
        frequency_hz = max(100, min(int(frequency_hz), 3000))
        amplitude = max(0.0, min(float(amplitude), 1.0))
        sample_rate = 8000
        samples_per_frame = 160
        frames = max(1, duration_ms // 20)

        sender.start_talk()
        try:
            for frame_no in range(frames):
                frame = bytearray(samples_per_frame * 2)
                base = frame_no * samples_per_frame
                for i in range(samples_per_frame):
                    t = (base + i) / sample_rate
                    sample = int(
                        math.sin(2 * math.pi * frequency_hz * t)
                        * amplitude
                        * 32767
                    )
                    frame[i * 2 : i * 2 + 2] = sample.to_bytes(
                        2, "little", signed=True
                    )
                sender.feed_pcm16le(bytes(frame))
                await asyncio.sleep(0.02)
            await sender.drain()
        finally:
            sender.stop_talk()
        return sender.stats()

    async def _punch(
        self,
        transport: asyncio.DatagramTransport,
        dest: tuple[str, int],
        *,
        pt: int = 0,
    ) -> None:
        for i in range(6):
            try:
                transport.sendto(_build_rtp_keepalive(i, pt=pt), dest)
            except OSError:
                break

    async def _keepalive_loop(self) -> None:
        seq = 6
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=_KEEPALIVE_INTERVAL)
                return
            except asyncio.TimeoutError:
                pass
            for transport, dest, pt in (
                (
                    None if self._talk_sender is not None else self._audio_transport,
                    None if self._wifi_panel else self._endpoints.audio,
                    self._remote_audio_pt,
                ),
                (self._video_transport, self._endpoints.video, self._remote_video_pt),
            ):
                if transport is None or dest is None:
                    continue
                try:
                    transport.sendto(_build_rtp_keepalive(seq, pt=pt), dest)
                except OSError:
                    pass
                seq = (seq + 1) & 0xFFFF

    async def _rtcp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=_RTCP_INTERVAL)
                return
            except asyncio.TimeoutError:
                pass
            vp = self._video_proto
            if (
                vp is None
                or self._video_transport is None
                or self._endpoints.video is None
                or vp.media_ssrc == 0
            ):
                continue
            try:
                self._video_transport.sendto(
                    _build_rtcp_rr(0xCAFEBABE, vp.media_ssrc, vp.last_seq),
                    self._endpoints.video,
                )
            except OSError:
                pass

    async def _stats_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=10.0)
                return
            except asyncio.TimeoutError:
                pass
            vp = self._video_proto
            ap = self._audio_proto
            _LOGGER.info(
                "[abb] media stats %s camera_index=%s: video pkts=%d pts=%s "
                "rewrites=%d audio pkts=%d pts=%s decrypted=%d dropped_pts=%s",
                self._door.name,
                self._camera_index if self._camera_index is not None else "default",
                vp.packets if vp else 0,
                dict(vp.payload_types) if vp else {},
                vp._rewrites if vp else 0,
                ap.packets if ap else 0,
                dict(ap.payload_types) if ap else {},
                ap.decrypt_ok if ap else 0,
                dict(ap.dropped_pts) if ap else {},
            )
            if self._talk_sender is not None:
                _LOGGER.info(
                    "[abb] talkback stats %s camera_index=%s: %s",
                    self._door.name,
                    self._camera_index if self._camera_index is not None else "default",
                    self._talk_sender.stats(),
                )
