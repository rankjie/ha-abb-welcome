"""Native ring-moment clip capture: RTP H.264 -> Annex-B -> mp4.

The gateway's ring INVITE carries real video (see :mod:`media_pipeline`),
but until now the only consumer was HA's stream/go2rtc pipeline, which
takes far longer to produce a first frame than a ring call typically
lives.  This module depacketizes the raw H.264 RTP video directly (no
go2rtc, no HA stream component) and remuxes it to mp4 with ffmpeg once
recording stops.

Kept intentionally free of Home Assistant imports (beyond the
``HomeAssistant`` type used for annotations) so it loads and unit-tests the
same way :mod:`media_pipeline` does — a plain ``importlib`` module load,
no HA test harness.  The one genuine HA dependency, the bundled ffmpeg
binary, is imported lazily inside :meth:`RingClipWriter.finalize` so that
importing this module never requires ``homeassistant`` to be installed.
"""

from __future__ import annotations

import asyncio
import struct
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .media_pipeline import _is_rtcp_packet, _rtp_payload
from .redaction import get_redacting_logger

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = get_redacting_logger(__name__)

_FINALIZE_TIMEOUT = 20.0
_ANNEX_B_START_CODE = b"\x00\x00\x00\x01"
# H.264 coded-slice NAL types (RFC 6184 / ITU-T H.264): one per picture for
# the single-slice-per-frame packetization ABB stations use.
_NAL_TYPE_NON_IDR_SLICE = 1
_NAL_TYPE_IDR_SLICE = 5
# Per-segment in-memory Annex-B buffer cap. RTP video is buffered in RAM
# (see RingClipWriter) rather than written per-packet, so a runaway or
# stuck call must not grow unbounded; a ring call this long is already
# far past MAX_RING_CLIP_SECONDS and something upstream has gone wrong.
_MAX_BUFFER_BYTES = 64 * 1024 * 1024
# Sane ffmpeg `-r` bounds: the measured fps is derived from wall-clock
# deltas between RTP packets, so a degenerate frames/elapsed ratio (e.g.
# one packet, or a near-zero elapsed time) must not reach ffmpeg raw.
_MIN_FPS = 1.0
_MAX_FPS = 30.0


class H264Depacketizer:
    """RFC 6184 RTP payload -> raw H.264 NAL units (no Annex-B start codes).

    Mirrors the NAL type dispatch in ``media_pipeline._h264_nal_metadata``:
    single-NAL (types 1-23, the only packetization observed on real ABB
    stations), STAP-A (24, aggregated NALs for other firmware), and FU-A
    (28, fragmented NALs for other firmware). RTCP is always checked and
    dropped first, since ``rtcp_mux``-less stations still land RTCP on the
    same socket the sink is fed from.
    """

    def __init__(self) -> None:
        self._have_seq = False
        self._last_seq = 0
        self._resyncing = False
        self._fu_buffer: bytearray | None = None
        self.packets = 0
        self.rtcp_dropped = 0
        self.seq_gaps = 0
        self.nals_out = 0
        self.dropped_while_resyncing = 0
        self.malformed = 0

    def push(self, packet: bytes) -> list[bytes]:
        """Feed one raw RTP datagram; return zero or more complete NAL units."""
        if _is_rtcp_packet(packet):
            self.rtcp_dropped += 1
            return []

        payload = _rtp_payload(packet)
        if not payload:
            self.malformed += 1
            return []

        seq = struct.unpack_from("!H", packet, 2)[0]
        if self._have_seq and seq != ((self._last_seq + 1) & 0xFFFF):
            self._on_gap()
        self._last_seq = seq
        self._have_seq = True
        self.packets += 1

        nal_type = payload[0] & 0x1F
        if 1 <= nal_type <= 23:
            nals = [payload]
        elif nal_type == 24:  # STAP-A: two-byte length followed by each NAL unit.
            nals = self._parse_stap_a(payload)
        elif nal_type == 28:  # FU-A: the FU header carries the original NAL type.
            nals = self._parse_fu_a(payload)
        else:
            # Reserved/unused RFC 6184 types (0, 25-27, 29-31): nothing to emit.
            return []

        return self._release(nals)

    def _on_gap(self) -> None:
        """Discard in-progress reassembly and wait for a fresh SPS/IDR."""
        self.seq_gaps += 1
        self._resyncing = True
        self._fu_buffer = None

    def _release(self, nals: list[bytes]) -> list[bytes]:
        """Apply the post-gap resync gate and update output counters."""
        if not self._resyncing:
            self.nals_out += len(nals)
            return nals

        released: list[bytes] = []
        for nal in nals:
            if (nal[0] & 0x1F) not in (7, _NAL_TYPE_IDR_SLICE):
                self.dropped_while_resyncing += 1
                continue
            self._resyncing = False
            released.append(nal)
        self.nals_out += len(released)
        return released

    @staticmethod
    def _parse_stap_a(payload: bytes) -> list[bytes]:
        nals: list[bytes] = []
        offset = 1
        while offset < len(payload):
            if offset + 2 > len(payload):
                return []
            size = struct.unpack_from("!H", payload, offset)[0]
            offset += 2
            if size == 0 or offset + size > len(payload):
                return []
            nals.append(payload[offset : offset + size])
            offset += size
        return nals

    def _parse_fu_a(self, payload: bytes) -> list[bytes]:
        if len(payload) < 2:
            return []
        indicator = payload[0]
        fu_header = payload[1]
        start = bool(fu_header & 0x80)
        end = bool(fu_header & 0x40)
        original_type = fu_header & 0x1F
        if not 1 <= original_type <= 23:
            self._fu_buffer = None
            return []

        if start:
            reconstructed_header = (indicator & 0xE0) | original_type
            self._fu_buffer = bytearray((reconstructed_header,))
            self._fu_buffer.extend(payload[2:])
        elif self._fu_buffer is not None:
            self._fu_buffer.extend(payload[2:])
        else:
            # Continuation/end fragment with no matching start — the start
            # fragment was lost or discarded across a sequence gap.
            return []

        if end and self._fu_buffer is not None:
            nal = bytes(self._fu_buffer)
            self._fu_buffer = None
            return [nal]
        return []


@dataclass(frozen=True)
class RingClipResult:
    """Outcome of remuxing one (possibly multi-segment) ring clip to mp4."""

    ok: bool
    output_path: Path
    frames: int
    nals: int
    bytes_written: int
    duration_s: float
    started_at: float | None
    segments: int
    fps: float
    error: str = ""


def _write_h264_file(path: Path, buffers: Sequence[bytes]) -> None:
    """Blocking: write concatenated Annex-B ``buffers`` to ``path``.

    Runs inside ``hass.async_add_executor_job``, never on the event loop.
    Callers only ever pass non-empty buffers, so an empty segment never
    creates a file on disk.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        for buffer in buffers:
            handle.write(buffer)


def _unlink_if_exists(path: Path) -> None:
    """Blocking best-effort delete; runs inside an executor job."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


class RingClipWriter:
    """Depacketizes RTP video into an in-memory Annex-B buffer, then to mp4.

    One instance covers one recording *segment* (one open media session).
    Register :meth:`on_video` as a coordinator packet sink; call
    :meth:`close` when the segment ends, then :meth:`finalize` (on the
    first segment) to remux — optionally concatenating later segments
    produced by a continuation re-dial.

    ``on_video`` runs on the event loop once per RTP packet, so it only
    ever appends to an in-memory buffer. All filesystem work (writing the
    concatenated ``.h264`` file, then cleanup) happens inside
    :meth:`finalize`, off the loop via ``hass.async_add_executor_job``.
    """

    def __init__(self, hass: HomeAssistant, target_dir: Path, name: str) -> None:
        self.hass = hass
        self.name = name
        target_dir = Path(target_dir)
        if not hass.config.is_allowed_path(str(target_dir)):
            raise PermissionError(
                f"ring clip directory is not an allowed Home Assistant path: "
                f"{target_dir}"
            )
        self.path = target_dir / f"{name}.h264"
        self._buffer = bytearray()
        self._buffer_capped = False
        self._depacketizer = H264Depacketizer()
        self.nals = 0
        self.frames = 0
        self.bytes_written = 0
        self.first_wall_time: float | None = None
        self.last_wall_time: float | None = None
        self._closed = False

    @property
    def elapsed_s(self) -> float:
        if self.first_wall_time is None or self.last_wall_time is None:
            return 0.0
        return max(0.0, self.last_wall_time - self.first_wall_time)

    def on_video(self, packet: bytes) -> None:
        """Packet-sink callback: feed one raw RTP video datagram."""
        if self._closed:
            return
        now = time.time()
        for nal in self._depacketizer.push(packet):
            self._write_nal(nal, now)

    def on_audio(self, packet: bytes) -> None:
        """Packet-sink callback: ring clips are video-only, audio is ignored."""

    def _write_nal(self, nal: bytes, now: float) -> None:
        if not nal or self._buffer_capped:
            return
        chunk = _ANNEX_B_START_CODE + nal
        if len(self._buffer) + len(chunk) > _MAX_BUFFER_BYTES:
            self._buffer_capped = True
            _LOGGER.warning(
                "[abb] ring clip: %s hit the %d MB in-memory buffer cap; "
                "dropping further video for this segment, keeping what was "
                "already captured",
                self.name,
                _MAX_BUFFER_BYTES // (1024 * 1024),
            )
            return
        self._buffer += chunk
        self.nals += 1
        self.bytes_written += len(chunk)
        if (nal[0] & 0x1F) in (_NAL_TYPE_NON_IDR_SLICE, _NAL_TYPE_IDR_SLICE):
            self.frames += 1
        if self.first_wall_time is None:
            self.first_wall_time = now
        self.last_wall_time = now

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True

    async def finalize(
        self,
        *,
        extra_segments: Sequence[RingClipWriter] = (),
        timeout: float = _FINALIZE_TIMEOUT,
    ) -> RingClipResult:
        """Concatenate segments (if any) and remux to mp4 via ffmpeg.

        Always closes this writer and every segment in ``extra_segments``
        first. Segments that captured zero bytes are dropped and never
        reach disk — this is what used to leave stray zero-byte
        ``.part2.h264`` files behind after a continuation re-dial got
        BYE'd before any video arrived. All filesystem work (writing the
        concatenated ``.h264`` file, and — on success — removing it) runs
        via ``hass.async_add_executor_job`` so this coroutine never blocks
        the event loop. On ffmpeg failure the ``.h264`` file is kept and
        ``ok`` is False; on success it is removed.
        """
        self.close()
        for segment in extra_segments:
            segment.close()

        segments = [self, *extra_segments]
        non_empty = [segment for segment in segments if segment.bytes_written > 0]
        total_nals = sum(segment.nals for segment in segments)
        total_frames = sum(segment.frames for segment in segments)
        total_bytes = sum(segment.bytes_written for segment in segments)
        starts = [s.first_wall_time for s in segments if s.first_wall_time is not None]
        ends = [s.last_wall_time for s in segments if s.last_wall_time is not None]
        started_at = min(starts) if starts else None
        duration_s = max(ends) - min(starts) if starts and ends else 0.0
        # Time actually spent RECEIVING video, which is not the window it spans:
        # the station hangs up the moment the door is opened, and the
        # continuation dial only gets media a few seconds later. That dead time
        # is real, but no frames exist for it, so counting it toward the frame
        # rate stretches the whole clip into a slideshow. Measured on a live
        # ring: 10 frames across a 6.34 s window of which only 1.70 s carried
        # video - 1.6 fps by the window, ~5.9 fps in truth.
        capture_s = sum(
            segment.elapsed_s
            for segment in segments
            if segment.bytes_written > 0 and segment.elapsed_s > 0
        )

        if not non_empty:
            return RingClipResult(
                ok=False,
                output_path=self.path,
                frames=0,
                nals=0,
                bytes_written=0,
                duration_s=0.0,
                started_at=None,
                segments=len(segments),
                fps=0,
                error="no video captured",
            )

        # Annex-B streams concatenate trivially at the byte level: each
        # segment starts with its own in-band SPS/PPS.
        buffers = [bytes(segment._buffer) for segment in non_empty]
        try:
            await self.hass.async_add_executor_job(
                _write_h264_file, self.path, buffers
            )
        except OSError as err:
            return RingClipResult(
                ok=False,
                output_path=self.path,
                frames=total_frames,
                nals=total_nals,
                bytes_written=total_bytes,
                duration_s=duration_s,
                started_at=started_at,
                segments=len(non_empty),
                fps=0,
                error=f"could not write segment file: {err}",
            )

        raw_fps = round(total_frames / capture_s, 2) if capture_s > 0 else total_frames
        fps = min(_MAX_FPS, max(_MIN_FPS, raw_fps))
        output_path = self.path.with_suffix(".mp4")

        # Deferred so importing this module never requires homeassistant.
        from homeassistant.components.ffmpeg import get_ffmpeg_manager

        argv = [
            get_ffmpeg_manager(self.hass).binary,
            "-hide_banner",
            "-loglevel",
            "error",
            "-nostdin",
            "-f",
            "h264",
            "-r",
            str(fps),
            "-i",
            str(self.path),
            "-c",
            "copy",
            "-movflags",
            "+faststart",
            str(output_path),
        ]

        def _failure(error: str) -> RingClipResult:
            return RingClipResult(
                ok=False,
                output_path=self.path,
                frames=total_frames,
                nals=total_nals,
                bytes_written=total_bytes,
                duration_s=duration_s,
                started_at=started_at,
                segments=len(non_empty),
                fps=fps,
                error=error,
            )

        process: asyncio.subprocess.Process | None = None
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.CancelledError:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            raise
        except TimeoutError:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            return _failure("ffmpeg remux timed out")
        except OSError as err:
            return _failure(f"ffmpeg failed to start: {err}")

        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace").strip()
            return _failure(f"ffmpeg exited {process.returncode}: {detail[:300]}")

        await self.hass.async_add_executor_job(_unlink_if_exists, self.path)

        return RingClipResult(
            ok=True,
            output_path=output_path,
            frames=total_frames,
            nals=total_nals,
            bytes_written=total_bytes,
            duration_s=duration_s,
            started_at=started_at,
            segments=len(non_empty),
            fps=fps,
        )
