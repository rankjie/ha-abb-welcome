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
import math
import secrets
import socket
import struct
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .intercom_dialer import (
    CallState,
    Door,
    IntercomDialer,
    MediaDescription,
    MediaEncryptionKeys,
)
from .redaction import get_redacting_logger

_LOGGER = get_redacting_logger(__name__)

_KEEPALIVE_INTERVAL = 1.0
_RTCP_INTERVAL = 5.0
_PLI_INTERVAL = 1.0
_UDP_PAIR_ALLOCATION_ATTEMPTS = 32
_PCMA_SILENCE_20MS = b"\xd5" * 160
_TALK_SEND_GAP_WARNING_SECONDS = 0.030
_TALK_GAIN_MIN_DB = 0.0
_TALK_GAIN_MAX_DB = 3.0
_TALK_LIMITER_RELEASE_ALPHA = 0.2
_NANOSECONDS_PER_SECOND = 1_000_000_000


def _build_rtp_keepalive(seq: int, pt: int = 0) -> bytes:
    return struct.pack("!BBHII", 0x80, pt & 0x7F, seq & 0xFFFF, 0, 0xCAFEBABE)


def _build_rtcp_pli(reporter: int, media: int) -> bytes:
    return struct.pack("!BBHII", 0x81, 206, 2, reporter, media)


def _build_rtcp_fir(reporter: int, media: int, sequence: int) -> bytes:
    """Build an RFC 5104 Full Intra Request with one FCI entry."""
    return struct.pack(
        "!BBHIIIB3x",
        0x84,
        206,
        4,
        reporter,
        0,
        media,
        sequence & 0xFF,
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


def _is_rtcp_packet(data: bytes) -> bool:
    """Recognize the RTCP packet-type range used by RTP/RTCP mux."""
    return len(data) >= 4 and (data[0] >> 6) == 2 and 192 <= data[1] <= 223


def _rtp_payload_bounds(data: bytes) -> tuple[int, int] | None:
    """Return RTP payload bounds, accounting for CSRCs, extensions and padding."""
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
    return offset, end


def _rtp_payload(data: bytes) -> bytes | None:
    bounds = _rtp_payload_bounds(data)
    if bounds is None:
        return None
    return data[bounds[0]:bounds[1]]


def _validate_aes_key(key: bytes) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError("invalid ABB media encryption key length")
    return key


def _media_encryption_key(media: MediaDescription) -> bytes | None:
    """Return the validated negotiated key for one media leg."""
    if not media.abb_encrypt:
        return None
    return _validate_aes_key(media.abb_encrypt_key)


def _directional_media_encryption_keys(
    media: MediaDescription,
    local_send_keys: MediaEncryptionKeys | None,
) -> tuple[bytes | None, bytes | None]:
    """Return receive/decrypt and send/encrypt keys for one media leg.

    ASI22 requires a distinct local key in SDP to establish two-way audio,
    but uses the gateway-provided key for the custom AES RTP framing in both
    directions.  Validate the advertised local key while retaining that
    device-specific symmetric wire-key behavior.
    """
    receive_key = _media_encryption_key(media)
    if local_send_keys is None:
        return receive_key, receive_key
    if receive_key is None:
        raise ValueError(
            f"missing negotiated remote {media.media} media encryption key"
        )
    try:
        send_key = getattr(local_send_keys, media.media)
    except AttributeError as err:
        raise ValueError(f"missing local {media.media} media encryption key") from err
    _validate_aes_key(send_key)
    return receive_key, receive_key


def _encrypt_rtp_payload(packet: bytes, key: bytes) -> bytes:
    """Apply ABB's AES-ECB framing to an RTP payload, leaving RTCP untouched."""
    if _is_rtcp_packet(packet):
        return packet
    key = _validate_aes_key(key)
    bounds = _rtp_payload_bounds(packet)
    if bounds is None:
        raise ValueError("malformed RTP packet")
    offset, end = bounds
    plaintext = packet[offset:end]
    if len(plaintext) > 0xFFFF:
        raise ValueError("RTP payload is too large for ABB encryption framing")
    padded_length = (len(plaintext) + 15) & ~15
    padded = plaintext + (b"\x00" * (padded_length - len(plaintext)))
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    framed = struct.pack("!H", len(plaintext)) + ciphertext
    return packet[:offset] + framed + packet[end:]


def _decrypt_rtp_payload(packet: bytes, key: bytes) -> bytes:
    """Remove ABB's AES-ECB framing from an RTP payload; RTCP is unchanged."""
    if _is_rtcp_packet(packet):
        return packet
    key = _validate_aes_key(key)
    bounds = _rtp_payload_bounds(packet)
    if bounds is None:
        raise ValueError("malformed RTP packet")
    offset, end = bounds
    framed = packet[offset:end]
    if len(framed) < 2 or (len(framed) - 2) % 16:
        raise ValueError("malformed ABB encrypted RTP payload")
    plaintext_length = struct.unpack_from("!H", framed)[0]
    ciphertext = framed[2:]
    if plaintext_length > len(ciphertext):
        raise ValueError("invalid ABB encrypted RTP payload length")
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    if any(padded[plaintext_length:]):
        raise ValueError("invalid ABB encrypted RTP payload padding")
    return packet[:offset] + padded[:plaintext_length] + packet[end:]


@dataclass(frozen=True)
class _SelectedVideoFormat:
    """The negotiated video format selected from an SDP media description."""

    payload_type: int
    codec: str | None
    fmtp: str | None

    @property
    def is_h264(self) -> bool:
        codec_name = (self.codec or "").partition("/")[0]
        return codec_name.upper() == "H264"

    @property
    def has_sprop_parameter_sets(self) -> bool:
        return "sprop-parameter-sets" in (self.fmtp or "").lower()


def _select_video_format(
    payload_types: list[int],
    rtpmap: dict[int, str],
    fmtp: dict[int, str],
) -> _SelectedVideoFormat | None:
    """Prefer H.264 and consistently return metadata for the selected PT."""
    if not payload_types:
        return None
    payload_type = next(
        (
            pt
            for pt in payload_types
            if rtpmap.get(pt, "").partition("/")[0].upper() == "H264"
        ),
        payload_types[0],
    )
    return _SelectedVideoFormat(
        payload_type=payload_type,
        codec=rtpmap.get(payload_type),
        fmtp=fmtp.get(payload_type),
    )


@dataclass(frozen=True)
class _H264NalMetadata:
    """Payload-free RFC 6184 metadata extracted from one RTP packet."""

    packetization_type: int | None
    nal_types: tuple[int, ...] = ()
    fu_start: bool = False
    valid: bool = True


def _h264_nal_metadata(data: bytes) -> _H264NalMetadata:
    """Parse only NAL type metadata; never retain the RTP payload."""
    payload = _rtp_payload(data)
    if not payload:
        return _H264NalMetadata(None, valid=False)

    nal_type = payload[0] & 0x1F
    if 1 <= nal_type <= 23:
        return _H264NalMetadata(nal_type, (nal_type,))

    if nal_type == 24:  # STAP-A: two-byte length followed by each NAL unit.
        member_types: list[int] = []
        offset = 1
        while offset < len(payload):
            if offset + 2 > len(payload):
                return _H264NalMetadata(nal_type, valid=False)
            member_size = struct.unpack_from("!H", payload, offset)[0]
            offset += 2
            if member_size == 0 or offset + member_size > len(payload):
                return _H264NalMetadata(nal_type, valid=False)
            member_type = payload[offset] & 0x1F
            if not 1 <= member_type <= 23:
                return _H264NalMetadata(nal_type, valid=False)
            member_types.append(member_type)
            offset += member_size
        if not member_types:
            return _H264NalMetadata(nal_type, valid=False)
        return _H264NalMetadata(nal_type, tuple(member_types))

    if nal_type == 28:  # FU-A: the FU header carries the original NAL type.
        if len(payload) < 2:
            return _H264NalMetadata(nal_type, valid=False)
        fu_header = payload[1]
        original_type = fu_header & 0x1F
        if fu_header & 0x20 or not 1 <= original_type <= 23:
            return _H264NalMetadata(nal_type, valid=False)
        return _H264NalMetadata(
            nal_type,
            (original_type,),
            fu_start=bool(fu_header & 0x80),
        )

    if nal_type == 0:
        return _H264NalMetadata(nal_type, valid=False)
    return _H264NalMetadata(nal_type, (nal_type,))


@dataclass
class _H264NalCounters:
    """Aggregate safe integer counters without retaining packet data."""

    sps: int = 0
    pps: int = 0
    idr: int = 0
    stap_a: int = 0
    fu_a: int = 0
    fu_a_starts: int = 0
    other: int = 0
    invalid: int = 0
    type_1: int = 0
    type_2: int = 0
    type_3: int = 0
    type_4: int = 0
    type_6: int = 0
    type_9: int = 0
    type_25: int = 0
    type_26: int = 0
    type_27: int = 0
    type_29: int = 0

    def observe(self, data: bytes) -> None:
        metadata = _h264_nal_metadata(data)
        if not metadata.valid:
            self.invalid += 1
            return
        if metadata.packetization_type == 24:
            self.stap_a += 1
        elif metadata.packetization_type == 28:
            self.fu_a += 1
            if metadata.fu_start:
                self.fu_a_starts += 1
        for nal_type in metadata.nal_types:
            if nal_type == 7:
                self.sps += 1
            elif nal_type == 8:
                self.pps += 1
            elif nal_type == 5:
                self.idr += 1
            else:
                self.other += 1
                if nal_type == 1:
                    self.type_1 += 1
                elif nal_type == 2:
                    self.type_2 += 1
                elif nal_type == 3:
                    self.type_3 += 1
                elif nal_type == 4:
                    self.type_4 += 1
                elif nal_type == 6:
                    self.type_6 += 1
                elif nal_type == 9:
                    self.type_9 += 1
                elif nal_type == 25:
                    self.type_25 += 1
                elif nal_type == 26:
                    self.type_26 += 1
                elif nal_type == 27:
                    self.type_27 += 1
                elif nal_type == 29:
                    self.type_29 += 1


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


def _next_talk_send_deadline_ns(
    deadline_ns: int,
    sent_at_ns: int,
    interval_ns: int,
) -> int:
    """Advance an absolute RTP deadline without burst catch-up after a stall."""
    scheduled_ns = deadline_ns + interval_ns
    if scheduled_ns <= sent_at_ns:
        return sent_at_ns + interval_ns
    return scheduled_ns


class _PCMATalkSender:
    """Continuous PCMA RTP sender on a dedicated cadence thread.

    The owned socket is a duplicate of the RTP receive socket, so outgoing
    packets retain the negotiated source port without calling an asyncio
    transport from a foreign thread.
    """

    def __init__(
        self,
        sock: socket.socket,
        dest: tuple[str, int],
        *,
        payload_type: int = 8,
        samples_per_packet: int = 160,
        packet_rate: int = 50,
        max_queue_frames: int = 25,
        encryption_key: bytes | None = None,
        monotonic_ns: Callable[[], int] | None = None,
        talkback_output_gain_db: float = 0.0,
    ) -> None:
        self._sock = sock
        self.dest = dest
        self.payload_type = payload_type
        self.samples_per_packet = samples_per_packet
        self.interval = 1.0 / packet_rate
        self._interval_ns = max(
            1,
            round(_NANOSECONDS_PER_SECOND / packet_rate),
        )
        self.max_queue_frames = max_queue_frames
        self._encryption_key = (
            _validate_aes_key(encryption_key)
            if encryption_key is not None
            else None
        )
        self._monotonic_ns = monotonic_ns or time.monotonic_ns
        try:
            gain_db = float(talkback_output_gain_db)
        except (TypeError, ValueError):
            gain_db = 0.0
        if not math.isfinite(gain_db):
            gain_db = 0.0
        self.gain_db = max(_TALK_GAIN_MIN_DB, min(_TALK_GAIN_MAX_DB, gain_db))
        self._requested_gain_factor = 10 ** (self.gain_db / 20.0)
        self._applied_gain_factor = self._requested_gain_factor
        self._gain_lock = threading.Lock()
        self.ssrc = secrets.randbits(32)
        self.seq = secrets.randbits(16)
        self.timestamp = secrets.randbits(32)
        self.talking = False
        self._marker_next = False
        self._pcm_buffer = bytearray()
        self._queued_pcma: deque[bytes] = deque()
        self._condition = threading.Condition()
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._stop_requested = False
        self._active = False
        self._started = False
        self._socket_closed = False
        self.packets_sent = 0
        self.bytes_sent = 0
        self.frames_received = 0
        self.voice_packets_sent = 0
        self.silence_packets_sent = 0
        self.underrun_silence_packets = 0
        self.dropped_frames = 0
        self.limited_frames = 0
        self.send_errors = 0
        self._last_send_at_ns: int | None = None
        self.send_intervals = 0
        self.send_gaps_over_30ms = 0
        self.max_send_gap_ns = 0

    @property
    def active(self) -> bool:
        with self._condition:
            return self._active

    @property
    def queue_frames(self) -> int:
        with self._condition:
            return len(self._queued_pcma)

    async def start(self) -> None:
        with self._condition:
            if self._active:
                return
            if self._started:
                raise RuntimeError("talkback RTP sender cannot be restarted")
            self._started = True
            self._stop_requested = False
            self._ready.clear()
            thread = threading.Thread(
                target=self._thread_main,
                name="abb_pcma_talk_sender",
                daemon=True,
            )
            self._thread = thread
        try:
            thread.start()
        except BaseException:
            with self._condition:
                self._thread = None
            self._close_owned_socket()
            raise
        await asyncio.to_thread(self._ready.wait)
        if not self.active:
            await asyncio.to_thread(thread.join)
            raise RuntimeError("talkback RTP sender failed to start")

    async def stop(self) -> None:
        self.stop_talk()
        with self._condition:
            self._stop_requested = True
            self._condition.notify_all()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            await asyncio.to_thread(thread.join)
        elif thread is None:
            self._close_owned_socket()
        with self._condition:
            self._thread = None

    def start_talk(self) -> None:
        with self._condition:
            self.talking = True
            self._marker_next = True
            self._condition.notify_all()

    def stop_talk(self) -> None:
        with self._condition:
            self.talking = False
            self._marker_next = False
            self._pcm_buffer.clear()
            self._queued_pcma.clear()
            self._condition.notify_all()

    async def drain(self, timeout: float = 1.0) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while self.queue_frames and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(self.interval)

    def feed_pcm16le(self, pcm: bytes) -> int:
        frame_bytes = self.samples_per_packet * 2
        with self._condition:
            if not self.talking:
                return 0
            self._pcm_buffer.extend(pcm)
            frames: list[bytes] = []
            while len(self._pcm_buffer) >= frame_bytes:
                frames.append(bytes(self._pcm_buffer[:frame_bytes]))
                del self._pcm_buffer[:frame_bytes]
        if self.gain_db == 0.0:
            # Keep the compatibility path bit-for-bit identical, including
            # its PCMA lookup-table behavior and sample rounding.
            encoded = [_encode_pcm16le_to_pcma(frame) for frame in frames]
        else:
            with self._gain_lock:
                encoded = [
                    _encode_pcm16le_to_pcma(self._apply_gain_and_limiter(frame))
                    for frame in frames
                ]
        with self._condition:
            if not self.talking:
                return 0
            for frame in encoded:
                self._queued_pcma.append(frame)
                self.frames_received += 1
            while len(self._queued_pcma) > self.max_queue_frames:
                self._queued_pcma.popleft()
                self.dropped_frames += 1
            self._condition.notify_all()
        return len(encoded)

    def _apply_gain_and_limiter(self, pcm_frame: bytes) -> bytes:
        """Apply stateful peak-safe gain to one 20 ms PCM16LE frame."""
        sample_count = len(pcm_frame) // 2
        if sample_count == 0:
            return b""
        samples = struct.unpack(f"<{sample_count}h", pcm_frame[: sample_count * 2])
        peak = max(abs(sample) for sample in samples)
        safe_factor = (
            self._requested_gain_factor
            if peak == 0
            else min(self._requested_gain_factor, 32767.0 / peak)
        )

        if safe_factor < self._applied_gain_factor:
            # Attack immediately when this frame cannot safely accept the
            # current gain. Release toward the configured gain more gently.
            applied_factor = safe_factor
        else:
            applied_factor = self._applied_gain_factor + (
                self._requested_gain_factor - self._applied_gain_factor
            ) * _TALK_LIMITER_RELEASE_ALPHA
        applied_factor = max(
            0.0,
            min(self._requested_gain_factor, safe_factor, applied_factor),
        )
        self._applied_gain_factor = applied_factor
        if applied_factor < self._requested_gain_factor:
            self.limited_frames += 1

        gained = [
            max(-32768, min(32767, round(sample * applied_factor)))
            for sample in samples
        ]
        return struct.pack(f"<{sample_count}h", *gained)

    def _thread_main(self) -> None:
        deadline_ns = self._monotonic_ns()
        ready = False
        try:
            while True:
                with self._condition:
                    while True:
                        if self._stop_requested:
                            return
                        now_ns = self._monotonic_ns()
                        remaining_ns = deadline_ns - now_ns
                        if remaining_ns <= 0:
                            break
                        self._condition.wait(
                            timeout=remaining_ns / _NANOSECONDS_PER_SECOND
                        )

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
                    self._condition.notify_all()
                    try:
                        self._send_pcma_locked(payload, marker=marker)
                    except BlockingIOError:
                        self.send_errors += 1
                    if not ready:
                        # Report readiness only after packet construction and
                        # the first socket-send attempt completed without a
                        # fatal socket error.
                        self._active = True
                        self._ready.set()
                        ready = True
                    sent_at_ns = self._monotonic_ns()
                    deadline_ns = _next_talk_send_deadline_ns(
                        deadline_ns,
                        sent_at_ns,
                        self._interval_ns,
                    )
        except OSError:
            with self._condition:
                self.send_errors += 1
            _LOGGER.warning("[abb] talkback RTP sender stopped after socket error")
        except Exception:
            _LOGGER.exception("[abb] talkback RTP sender stopped unexpectedly")
        finally:
            with self._condition:
                self._active = False
                self._ready.set()
                self._condition.notify_all()
            self._close_owned_socket()

    def _send_pcma(self, payload: bytes, *, marker: bool = False) -> None:
        with self._condition:
            self._send_pcma_locked(payload, marker=marker)

    def _send_pcma_locked(self, payload: bytes, *, marker: bool = False) -> None:
        header = struct.pack(
            "!BBHII",
            0x80,
            (0x80 if marker else 0) | (self.payload_type & 0x7F),
            self.seq & 0xFFFF,
            self.timestamp & 0xFFFFFFFF,
            self.ssrc & 0xFFFFFFFF,
        )
        packet = header + payload
        if self._encryption_key is not None:
            packet = _encrypt_rtp_payload(packet, self._encryption_key)
        self._sock.sendto(packet, self.dest)
        sent_at_ns = self._monotonic_ns()
        if self._last_send_at_ns is not None:
            gap_ns = sent_at_ns - self._last_send_at_ns
            self.send_intervals += 1
            self.max_send_gap_ns = max(self.max_send_gap_ns, gap_ns)
            if gap_ns > round(
                _TALK_SEND_GAP_WARNING_SECONDS * _NANOSECONDS_PER_SECOND
            ):
                self.send_gaps_over_30ms += 1
        self._last_send_at_ns = sent_at_ns
        self.packets_sent += 1
        self.bytes_sent += len(packet)
        self.seq = (self.seq + 1) & 0xFFFF
        self.timestamp = (self.timestamp + len(payload)) & 0xFFFFFFFF

    def _close_owned_socket(self) -> None:
        with self._condition:
            if self._socket_closed:
                return
            self._socket_closed = True
        _close_socket(self._sock)

    def stats(self) -> dict[str, Any]:
        with self._gain_lock:
            limited_frames = self.limited_frames
        with self._condition:
            return {
                "talking": self.talking,
                "active": self._active,
                "packets": self.packets_sent,
                "bytes": self.bytes_sent,
                "frames": self.frames_received,
                "voice_packets": self.voice_packets_sent,
                "silence_packets": self.silence_packets_sent,
                "underrun_packets": self.underrun_silence_packets,
                "dropped_frames": self.dropped_frames,
                "gain_db": self.gain_db,
                "limited_frames": limited_frames,
                "queue_frames": len(self._queued_pcma),
                "send_errors": self.send_errors,
                "send_intervals": self.send_intervals,
                "send_gaps_over_30ms": self.send_gaps_over_30ms,
                "max_send_gap_ms": round(
                    self.max_send_gap_ns / 1_000_000,
                    3,
                ),
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


def _alloc_udp_pair(
    bind_ip: str,
    *,
    attempts: int = _UDP_PAIR_ALLOCATION_ATTEMPTS,
) -> tuple[socket.socket, socket.socket]:
    """Bind an even RTP port and its adjacent RTCP port with bounded retries."""
    last_error: OSError | None = None
    for _attempt in range(max(1, attempts)):
        first: socket.socket | None = None
        second: socket.socket | None = None
        try:
            first = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            first.bind((bind_ip, 0))
            first_port = first.getsockname()[1]
            second = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if first_port % 2 == 0:
                rtp_sock, rtcp_sock = first, second
                second.bind((bind_ip, first_port + 1))
            else:
                rtp_sock, rtcp_sock = second, first
                second.bind((bind_ip, first_port - 1))
            rtp_sock.setblocking(False)
            rtcp_sock.setblocking(False)
            return rtp_sock, rtcp_sock
        except OSError as err:
            last_error = err
            _close_socket(first)
            _close_socket(second)
    raise OSError(
        "unable to allocate an adjacent UDP RTP/RTCP port pair"
    ) from last_error


def _close_socket(sock: socket.socket | None) -> None:
    if sock is not None:
        sock.close()


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
        *,
        track_h264_nals: bool = False,
        drop_muxed_rtcp: bool = False,
        encryption_key: bytes | None = None,
    ) -> None:
        self._on_packet = on_packet
        self._rewrite_pt = rewrite_pt
        self._on_first_packet = on_first_packet
        self.label = label
        self._drop_muxed_rtcp = drop_muxed_rtcp
        self._encryption_key = (
            _validate_aes_key(encryption_key)
            if encryption_key is not None
            else None
        )
        self.transport: asyncio.DatagramTransport | None = None
        self.packets = 0
        self.bytes_received = 0
        self.last_seq = 0
        self.media_ssrc = 0
        self.payload_types: dict[int, int] = {}
        self._rewrites = 0
        self.rtcp_packets = 0
        self.decrypt_errors = 0
        self.h264_nals = _H264NalCounters() if track_h264_nals else None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if _is_rtcp_packet(data):
            self.rtcp_packets += 1
            if self._drop_muxed_rtcp:
                return
            try:
                self._on_packet(data)
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("on_packet handler raised: %s", err)
            return
        elif self._encryption_key is not None:
            try:
                data = _decrypt_rtp_payload(data, self._encryption_key)
            except ValueError:
                self.decrypt_errors += 1
                _LOGGER.debug("Dropping malformed encrypted ABB RTP packet")
                return
        self.packets += 1
        self.bytes_received += len(data)
        if self.h264_nals is not None:
            self.h264_nals.observe(data)
        if len(data) >= 12:
            pt = data[1] & 0x7F
            self.payload_types[pt] = self.payload_types.get(pt, 0) + 1
            self.last_seq = struct.unpack_from("!H", data, 2)[0]
            if self.media_ssrc == 0:
                self.media_ssrc = struct.unpack_from("!I", data, 8)[0]
            if self._rewrite_pt is not None and pt != self._rewrite_pt:
                marker = data[1] & 0x80
                data = (
                    bytes((data[0], marker | (self._rewrite_pt & 0x7F)))
                    + data[2:]
                )
                self._rewrites += 1
        if self.packets == 1 and self._on_first_packet is not None:
            try:
                self._on_first_packet(data)
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("on_first_packet handler raised: %s", err)
        try:
            self._on_packet(data)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("on_packet handler raised: %s", err)

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("RTP datagram error: %s", exc)


@dataclass(frozen=True)
class _RemoteMediaEndpoints:
    rtp: tuple[str, int]
    rtcp: tuple[str, int]
    rtcp_mux: bool
    explicit_rtcp: bool


def _remote_media_endpoints(
    media: MediaDescription,
) -> _RemoteMediaEndpoints | None:
    """Resolve RTP and RTCP destinations from one SDP media description."""
    if not media.connection_ip or not 1 <= media.port <= 65535:
        return None
    rtp = (media.connection_ip, media.port)
    if media.rtcp_mux:
        return _RemoteMediaEndpoints(rtp, rtp, True, media.rtcp_port is not None)
    rtcp_port = media.rtcp_port
    if rtcp_port is None:
        rtcp_port = media.port + 1
    if not 1 <= rtcp_port <= 65535:
        return None
    rtcp_ip = media.rtcp_ip or media.connection_ip
    return _RemoteMediaEndpoints(
        rtp,
        (rtcp_ip, rtcp_port),
        False,
        media.rtcp_port is not None,
    )


def _select_rtcp_transport(
    rtcp_mux: bool,
    rtp_transport: asyncio.DatagramTransport | None,
    rtcp_transport: asyncio.DatagramTransport | None,
) -> asyncio.DatagramTransport | None:
    """Use the RTP socket for muxed RTCP and the paired socket otherwise."""
    return rtp_transport if rtcp_mux else rtcp_transport


def _should_request_h264_keyframe(counters: _H264NalCounters | None) -> bool:
    """Request a keyframe until SPS, PPS, and IDR metadata have all arrived."""
    return counters is None or not (counters.sps and counters.pps and counters.idr)


@dataclass
class _MediaEndpoints:
    audio: _RemoteMediaEndpoints | None
    video: _RemoteMediaEndpoints | None


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
        talkback_output_gain_db: float = 0.0,
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
        self._talkback_output_gain_db = talkback_output_gain_db

        self._media_ip = ""
        self._video_sock: socket.socket | None = None
        self._video_rtcp_sock: socket.socket | None = None
        self._audio_sock: socket.socket | None = None
        self._audio_rtcp_sock: socket.socket | None = None
        self._video_proto: _RTPProtocol | None = None
        self._audio_proto: _RTPProtocol | None = None
        self._video_transport: asyncio.DatagramTransport | None = None
        self._video_rtcp_transport: asyncio.DatagramTransport | None = None
        self._audio_transport: asyncio.DatagramTransport | None = None
        self._audio_rtcp_transport: asyncio.DatagramTransport | None = None
        self._call: CallState | None = None
        self._accepted_incoming_call_id: str | None = None
        self._accepted_incoming_ack_received: bool | None = None
        self._incoming_end_task: asyncio.Task | None = None
        self._outbound_end_task: asyncio.Task | None = None
        self._endpoints = _MediaEndpoints(None, None)
        # Negotiated media keys are directional and must not outlive the call.
        self._audio_receive_key: bytes | None = None
        self._video_receive_key: bytes | None = None
        self._audio_send_key: bytes | None = None
        self._video_send_key: bytes | None = None
        self._video_codec = "H264/90000"
        self._video_fmtp: str | None = None
        self._remote_audio_pt = 8
        self._remote_video_pt = 102
        self._talk_sender: _PCMATalkSender | None = None
        self._last_pli_at = 0.0
        self._pli_requests_sent = 0
        self._fir_requests_sent = 0
        self._receiver_reports_sent = 0
        self._fir_sequence = 0

        self._stop = asyncio.Event()
        self._keepalive_task: asyncio.Task | None = None
        self._rtcp_task: asyncio.Task | None = None
        self._stats_task: asyncio.Task | None = None

    @property
    def active(self) -> bool:
        return self._call is not None

    @property
    def video_codec(self) -> str:
        return self._video_codec

    @property
    def video_fmtp(self) -> str | None:
        return self._video_fmtp

    @property
    def talkback_ready(self) -> bool:
        return self._talk_sender is not None and self._talk_sender.active

    def talkback_stats(self) -> dict[str, Any]:
        sender = self._talk_sender
        if sender is None:
            return {
                "active": False,
                "talking": False,
                "gain_db": self._talkback_output_gain_db,
                "limited_frames": 0,
            }
        return sender.stats()

    def set_packet_handlers(
        self,
        on_video: Callable[[bytes], None] | None,
        on_audio: Callable[[bytes], None] | None,
    ) -> None:
        """Replace the per-packet RTP handlers (used by the RTSP server)."""
        self._on_video_packet = on_video
        self._on_audio_packet = on_audio

    def _close_media_io(self) -> None:
        """Close transports and any bound sockets not owned by a transport."""
        resources = (
            (self._video_transport, self._video_sock),
            (self._video_rtcp_transport, self._video_rtcp_sock),
            (self._audio_transport, self._audio_sock),
            (self._audio_rtcp_transport, self._audio_rtcp_sock),
        )
        for transport, sock in resources:
            if transport is not None:
                transport.close()
            else:
                _close_socket(sock)
        self._video_transport = None
        self._video_rtcp_transport = None
        self._audio_transport = None
        self._audio_rtcp_transport = None
        self._video_sock = None
        self._video_rtcp_sock = None
        self._audio_sock = None
        self._audio_rtcp_sock = None

    def _video_feedback_transport(self) -> asyncio.DatagramTransport | None:
        endpoints = self._endpoints.video
        if endpoints is None:
            return None
        return _select_rtcp_transport(
            endpoints.rtcp_mux,
            self._video_transport,
            self._video_rtcp_transport,
        )

    def _send_video_pli_if_due(self, now: float) -> bool:
        endpoints = self._endpoints.video
        video_proto = self._video_proto
        video_nals = video_proto.h264_nals if video_proto is not None else None
        if (
            endpoints is None
            or video_proto is None
            or video_proto.media_ssrc == 0
            or not _should_request_h264_keyframe(video_nals)
            or now - self._last_pli_at < _PLI_INTERVAL
        ):
            return False
        transport = self._video_feedback_transport()
        if transport is None:
            return False
        try:
            transport.sendto(
                _build_rtcp_pli(0xCAFEBABE, video_proto.media_ssrc),
                endpoints.rtcp,
            )
        except OSError:
            return False
        self._last_pli_at = now
        self._pli_requests_sent += 1
        try:
            transport.sendto(
                _build_rtcp_fir(
                    0xCAFEBABE,
                    video_proto.media_ssrc,
                    self._fir_sequence,
                ),
                endpoints.rtcp,
            )
        except OSError:
            pass
        else:
            self._fir_sequence = (self._fir_sequence + 1) & 0xFF
            self._fir_requests_sent += 1
        return True

    async def open(self) -> None:
        """Dial gateway and start receiving RTP."""
        loop = asyncio.get_running_loop()
        self._accepted_incoming_call_id = None
        self._accepted_incoming_ack_received = None
        self._last_pli_at = 0.0
        self._pli_requests_sent = 0
        self._fir_requests_sent = 0
        self._receiver_reports_sent = 0
        self._fir_sequence = 0
        self._audio_receive_key = None
        self._video_receive_key = None
        self._audio_send_key = None
        self._video_send_key = None

        self._media_ip = best_local_ip_for(self._gateway_host)
        try:
            self._audio_sock, self._audio_rtcp_sock = _alloc_udp_pair(self._media_ip)
            self._video_sock, self._video_rtcp_sock = _alloc_udp_pair(self._media_ip)
        except OSError:
            self._close_media_io()
            raise
        offer_audio_port = self._audio_sock.getsockname()[1]
        offer_video_port = self._video_sock.getsockname()[1]

        try:
            call = await self._accept_incoming_call_if_pending(
                audio_port=offer_audio_port,
                video_port=offer_video_port,
            )
            accepted_incoming = call is not None
            if call is None:
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
        except BaseException:
            self._close_media_io()
            raise
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
            remote_endpoints = _remote_media_endpoints(m)
            if m.media == "audio" and remote_endpoints is not None:
                self._audio_receive_key, self._audio_send_key = (
                    _directional_media_encryption_keys(m, call.local_send_keys)
                )
                if m.payload_types:
                    self._remote_audio_pt = (
                        8
                        if 8 in m.payload_types
                        else m.payload_types[0]
                    )
                self._endpoints = _MediaEndpoints(
                    audio=remote_endpoints,
                    video=self._endpoints.video,
                )
            elif m.media == "video" and remote_endpoints is not None:
                self._video_receive_key, self._video_send_key = (
                    _directional_media_encryption_keys(m, call.local_send_keys)
                )
                selected = _select_video_format(m.payload_types, m.rtpmap, m.fmtp)
                if selected is not None:
                    self._remote_video_pt = selected.payload_type
                    self._video_codec = selected.codec or self._video_codec
                    self._video_fmtp = selected.fmtp
                _LOGGER.info(
                    "[abb] media: negotiated video metadata h264=%s "
                    "selected_pt=%d payload_count=%d fmtp_present=%s "
                    "sprop_parameter_sets_present=%s rtcp_mux=%s "
                    "explicit_rtcp=%s",
                    selected.is_h264 if selected is not None else False,
                    selected.payload_type if selected is not None else -1,
                    len(m.payload_types),
                    bool(selected and selected.fmtp),
                    bool(selected and selected.has_sprop_parameter_sets),
                    remote_endpoints.rtcp_mux,
                    remote_endpoints.explicit_rtcp,
                )
                self._endpoints = _MediaEndpoints(
                    audio=self._endpoints.audio,
                    video=remote_endpoints,
                )

        _LOGGER.info(
            "[abb] media encryption negotiation: audio_receive=%s "
            "audio_send=%s video_receive=%s video_send=%s",
            self._audio_receive_key is not None,
            self._audio_send_key is not None,
            self._video_receive_key is not None,
            self._video_send_key is not None,
        )

        def _video_first(data: bytes) -> None:
            _LOGGER.info(
                "[abb] media: first video RTP packet for %s camera_index=%s "
                "(%d bytes)",
                self._door.name,
                self._camera_index if self._camera_index is not None else "default",
                len(data),
            )
            self._send_video_pli_if_due(loop.time())

        def _on_video(packet: bytes) -> None:
            cb = self._on_video_packet
            if cb is not None:
                cb(packet)

        def _on_audio(packet: bytes) -> None:
            cb = self._on_audio_packet
            if cb is not None:
                cb(packet)

        self._video_proto = _RTPProtocol(
            on_packet=_on_video,
            rewrite_pt=self.VIDEO_SDP_PT,
            on_first_packet=_video_first,
            label="video",
            track_h264_nals=True,
            encryption_key=self._video_receive_key,
            drop_muxed_rtcp=bool(
                self._endpoints.video and self._endpoints.video.rtcp_mux
            ),
        )
        talkback_sock: socket.socket | None = None
        if self._endpoints.audio is not None and self._audio_sock is not None:
            try:
                # asyncio takes ownership of the receive socket below. Duplicate
                # it first so the cadence thread can send from the exact same
                # negotiated UDP source port without touching the transport.
                talkback_sock = self._audio_sock.dup()
            except OSError:
                self._close_media_io()
                raise
        try:
            self._video_transport, _ = await loop.create_datagram_endpoint(
                lambda: self._video_proto, sock=self._video_sock
            )
            self._video_rtcp_transport, _ = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol, sock=self._video_rtcp_sock
            )

            self._audio_proto = _RTPProtocol(
                on_packet=_on_audio,
                rewrite_pt=None,
                on_first_packet=None,
                label="audio",
                encryption_key=self._audio_receive_key,
                drop_muxed_rtcp=bool(
                    self._endpoints.audio and self._endpoints.audio.rtcp_mux
                ),
            )
            self._audio_transport, _ = await loop.create_datagram_endpoint(
                lambda: self._audio_proto, sock=self._audio_sock
            )
            self._audio_rtcp_transport, _ = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol, sock=self._audio_rtcp_sock
            )
        except BaseException:
            _close_socket(talkback_sock)
            self._close_media_io()
            raise

        sender: _PCMATalkSender | None = None
        try:
            # Punch audio with PCMA PT (8) and video with H.264 PT (102) so
            # the gateway recognises them as legitimate media flows.
            # Keepalives later in ``_keepalive_loop`` use the same PTs.
            if self._endpoints.audio:
                await self._punch(
                    self._audio_transport,
                    self._endpoints.audio.rtp,
                    pt=self._remote_audio_pt,
                    encryption_key=self._audio_send_key,
                )
            if self._endpoints.video:
                await self._punch(
                    self._video_transport,
                    self._endpoints.video.rtp,
                    pt=self._remote_video_pt,
                    encryption_key=self._video_send_key,
                )

            if talkback_sock is not None and self._endpoints.audio is not None:
                sender = _PCMATalkSender(
                    talkback_sock,
                    self._endpoints.audio.rtp,
                    payload_type=self._remote_audio_pt,
                    encryption_key=self._audio_send_key,
                    talkback_output_gain_db=self._talkback_output_gain_db,
                )
                talkback_sock = None  # Ownership transferred to the sender.
                await sender.start()
                self._talk_sender = sender
                _LOGGER.info(
                    "[abb] media: talkback RTP leg ready for %s -> %s:%d pt=%d",
                    self._door.name,
                    self._endpoints.audio.rtp[0],
                    self._endpoints.audio.rtp[1],
                    self._remote_audio_pt,
                )
        except BaseException:
            _close_socket(talkback_sock)
            if sender is not None:
                await sender.stop()
            self._talk_sender = None
            self._close_media_io()
            raise

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
            local_send_keys=accepted.local_send_keys,
        )

    async def close(self) -> None:
        current_task = asyncio.current_task()
        video_nals = (
            self._video_proto.h264_nals if self._video_proto is not None else None
        )
        _LOGGER.info(
            "[abb] media: closing stream for %s "
            "camera_index=%s (video_pkts=%d audio_pkts=%d rewrites=%d)",
            self._door.name,
            self._camera_index if self._camera_index is not None else "default",
            self._video_proto.packets if self._video_proto else 0,
            self._audio_proto.packets if self._audio_proto else 0,
            self._video_proto._rewrites if self._video_proto else 0,
        )
        _LOGGER.info(
            "[abb] media H264 final metadata: sps=%d pps=%d idr=%d "
            "stap_a=%d fu_a=%d fu_a_starts=%d other=%d invalid=%d "
            "nal1=%d nal2=%d nal3=%d nal4=%d nal6=%d nal9=%d "
            "nal25=%d nal26=%d nal27=%d nal29=%d "
            "pli_sent=%d fir_sent=%d rr_sent=%d muxed_rtcp_received=%d "
            "video_decrypt_errors=%d audio_decrypt_errors=%d",
            video_nals.sps if video_nals else 0,
            video_nals.pps if video_nals else 0,
            video_nals.idr if video_nals else 0,
            video_nals.stap_a if video_nals else 0,
            video_nals.fu_a if video_nals else 0,
            video_nals.fu_a_starts if video_nals else 0,
            video_nals.other if video_nals else 0,
            video_nals.invalid if video_nals else 0,
            video_nals.type_1 if video_nals else 0,
            video_nals.type_2 if video_nals else 0,
            video_nals.type_3 if video_nals else 0,
            video_nals.type_4 if video_nals else 0,
            video_nals.type_6 if video_nals else 0,
            video_nals.type_9 if video_nals else 0,
            video_nals.type_25 if video_nals else 0,
            video_nals.type_26 if video_nals else 0,
            video_nals.type_27 if video_nals else 0,
            video_nals.type_29 if video_nals else 0,
            self._pli_requests_sent,
            self._fir_requests_sent,
            self._receiver_reports_sent,
            self._video_proto.rtcp_packets if self._video_proto else 0,
            self._video_proto.decrypt_errors if self._video_proto else 0,
            self._audio_proto.decrypt_errors if self._audio_proto else 0,
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
        for t in (self._keepalive_task, self._rtcp_task, self._stats_task):
            if t is not None:
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
        self._keepalive_task = self._rtcp_task = self._stats_task = None

        if self._talk_sender is not None:
            await self._talk_sender.stop()
            self._talk_sender = None

        self._close_media_io()
        self._video_proto = self._audio_proto = None
        self._audio_receive_key = None
        self._video_receive_key = None
        self._audio_send_key = None
        self._video_send_key = None

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

        # Build the synthetic signal before switching the sender into talking
        # mode, then keep a small queue ahead of the 20 ms RTP clock. Feeding
        # one frame followed by a 20 ms asyncio sleep lets normal scheduling
        # jitter empty the queue, which the outdoor station renders as a row
        # of short beeps instead of one continuous tone.
        tone_frames: list[bytes] = []
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
            tone_frames.append(bytes(frame))

        sender.start_talk()
        try:
            high_watermark = max(1, min(sender.max_queue_frames, 10))
            low_watermark = max(1, high_watermark // 2)
            next_frame = 0
            while next_frame < len(tone_frames):
                while (
                    next_frame < len(tone_frames)
                    and sender.queue_frames < high_watermark
                ):
                    sender.feed_pcm16le(tone_frames[next_frame])
                    next_frame += 1
                if next_frame < len(tone_frames):
                    while sender.queue_frames > low_watermark:
                        await asyncio.sleep(min(0.005, sender.interval / 4))
            await sender.drain(timeout=max(1.0, duration_ms / 1000 + 1.0))
        finally:
            sender.stop_talk()
        return sender.stats()

    async def _punch(
        self,
        transport: asyncio.DatagramTransport,
        dest: tuple[str, int],
        *,
        pt: int = 0,
        encryption_key: bytes | None = None,
    ) -> None:
        for i in range(6):
            try:
                packet = _build_rtp_keepalive(i, pt=pt)
                if encryption_key is not None:
                    packet = _encrypt_rtp_payload(packet, encryption_key)
                transport.sendto(packet, dest)
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
            for transport, dest, pt, encryption_key in (
                (
                    None if self._talk_sender is not None else self._audio_transport,
                    (
                        self._endpoints.audio.rtp
                        if self._endpoints.audio is not None
                        else None
                    ),
                    self._remote_audio_pt,
                    self._audio_send_key,
                ),
                (
                    self._video_transport,
                    (
                        self._endpoints.video.rtp
                        if self._endpoints.video is not None
                        else None
                    ),
                    self._remote_video_pt,
                    self._video_send_key,
                ),
            ):
                if transport is None or dest is None:
                    continue
                try:
                    packet = _build_rtp_keepalive(seq, pt=pt)
                    if encryption_key is not None:
                        packet = _encrypt_rtp_payload(packet, encryption_key)
                    transport.sendto(packet, dest)
                except OSError:
                    pass
                seq = (seq + 1) & 0xFFFF

    async def _rtcp_loop(self) -> None:
        loop = asyncio.get_running_loop()
        last_rr_at = loop.time()
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=_PLI_INTERVAL)
                return
            except asyncio.TimeoutError:
                pass
            vp = self._video_proto
            now = loop.time()
            self._send_video_pli_if_due(now)
            if (
                vp is None
                or self._endpoints.video is None
                or vp.media_ssrc == 0
                or now - last_rr_at < _RTCP_INTERVAL
            ):
                continue
            transport = self._video_feedback_transport()
            if transport is None:
                continue
            try:
                transport.sendto(
                    _build_rtcp_rr(0xCAFEBABE, vp.media_ssrc, vp.last_seq),
                    self._endpoints.video.rtcp,
                )
            except OSError:
                pass
            else:
                last_rr_at = now
                self._receiver_reports_sent += 1

    async def _stats_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=10.0)
                return
            except asyncio.TimeoutError:
                pass
            vp = self._video_proto
            ap = self._audio_proto
            video_nals = vp.h264_nals if vp is not None else None
            _LOGGER.info(
                "[abb] media stats %s camera_index=%s: video pkts=%d "
                "payload_type_count=%d rewrites=%d audio pkts=%d "
                "video_decrypt_errors=%d audio_decrypt_errors=%d",
                self._door.name,
                self._camera_index if self._camera_index is not None else "default",
                vp.packets if vp else 0,
                len(vp.payload_types) if vp else 0,
                vp._rewrites if vp else 0,
                ap.packets if ap else 0,
                vp.decrypt_errors if vp else 0,
                ap.decrypt_errors if ap else 0,
            )
            _LOGGER.info(
                "[abb] media H264 periodic metadata: sps=%d pps=%d idr=%d "
                "stap_a=%d fu_a=%d fu_a_starts=%d other=%d invalid=%d "
                "nal1=%d nal2=%d nal3=%d nal4=%d nal6=%d nal9=%d "
                "nal25=%d nal26=%d nal27=%d nal29=%d "
                "pli_sent=%d fir_sent=%d rr_sent=%d muxed_rtcp_received=%d",
                video_nals.sps if video_nals else 0,
                video_nals.pps if video_nals else 0,
                video_nals.idr if video_nals else 0,
                video_nals.stap_a if video_nals else 0,
                video_nals.fu_a if video_nals else 0,
                video_nals.fu_a_starts if video_nals else 0,
                video_nals.other if video_nals else 0,
                video_nals.invalid if video_nals else 0,
                video_nals.type_1 if video_nals else 0,
                video_nals.type_2 if video_nals else 0,
                video_nals.type_3 if video_nals else 0,
                video_nals.type_4 if video_nals else 0,
                video_nals.type_6 if video_nals else 0,
                video_nals.type_9 if video_nals else 0,
                video_nals.type_25 if video_nals else 0,
                video_nals.type_26 if video_nals else 0,
                video_nals.type_27 if video_nals else 0,
                video_nals.type_29 if video_nals else 0,
                self._pli_requests_sent,
                self._fir_requests_sent,
                self._receiver_reports_sent,
                vp.rtcp_packets if vp else 0,
            )
            if self._talk_sender is not None:
                _LOGGER.info(
                    "[abb] talkback stats %s camera_index=%s: %s",
                    self._door.name,
                    self._camera_index if self._camera_index is not None else "default",
                    self._talk_sender.stats(),
                )
