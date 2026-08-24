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

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_FINALIZE_TIMEOUT = 20.0
_ANNEX_B_START_CODE = b"\x00\x00\x00\x01"
# H.264 coded-slice NAL types (RFC 6184 / ITU-T H.264): one per picture for
# the single-slice-per-frame packetization ABB stations use.
_NAL_TYPE_NON_IDR_SLICE = 1
_NAL_TYPE_IDR_SLICE = 5


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
    fps: int
    error: str = ""


class RingClipWriter:
    """Depacketizes RTP video into an Annex-B ``.h264`` file, then to mp4.

    One instance covers one recording *segment* (one open media session).
    Register :meth:`on_video` as a coordinator packet sink; call
    :meth:`close` when the segment ends, then :meth:`finalize` (on the
    first segment) to remux — optionally concatenating later segments
    produced by a continuation re-dial.
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
        target_dir.mkdir(parents=True, exist_ok=True)
        self.path = target_dir / f"{name}.h264"
        self._file = self.path.open("wb")
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
        if not nal:
            return
        chunk = _ANNEX_B_START_CODE + nal
        self._file.write(chunk)
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
        self._file.close()

    async def finalize(
        self,
        *,
        extra_segments: Sequence[RingClipWriter] = (),
        timeout: float = _FINALIZE_TIMEOUT,
    ) -> RingClipResult:
        """Concatenate segments (if any) and remux to mp4 via ffmpeg.

        Always closes this writer and every segment in ``extra_segments``
        first. On ffmpeg failure the ``.h264`` file is kept and ``ok`` is
        False; on success the ``.h264`` file is removed.
        """
        self.close()
        for segment in extra_segments:
            segment.close()

        segments = [self, *extra_segments]
        total_nals = sum(segment.nals for segment in segments)
        total_frames = sum(segment.frames for segment in segments)
        total_bytes = sum(segment.bytes_written for segment in segments)
        starts = [s.first_wall_time for s in segments if s.first_wall_time is not None]
        ends = [s.last_wall_time for s in segments if s.last_wall_time is not None]
        started_at = min(starts) if starts else None
        duration_s = max(ends) - min(starts) if starts and ends else 0.0

        if total_nals == 0:
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

        if extra_segments:
            # Annex-B streams concatenate trivially at the byte level: each
            # segment starts with its own in-band SPS/PPS.
            try:
                with self.path.open("ab") as combined:
                    for segment in extra_segments:
                        combined.write(segment.path.read_bytes())
            except OSError as err:
                return RingClipResult(
                    ok=False,
                    output_path=self.path,
                    frames=total_frames,
                    nals=total_nals,
                    bytes_written=total_bytes,
                    duration_s=duration_s,
                    started_at=started_at,
                    segments=len(segments),
                    fps=0,
                    error=f"segment concatenation failed: {err}",
                )
            # Each segment's own file is now fully redundant — its bytes
            # live in self.path regardless of what ffmpeg does next.
            for segment in extra_segments:
                try:
                    segment.path.unlink(missing_ok=True)
                except OSError:
                    pass

        fps = (
            max(1, round(total_frames / duration_s))
            if duration_s > 0
            else max(1, total_frames)
        )
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
                segments=len(segments),
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

        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass

        return RingClipResult(
            ok=True,
            output_path=output_path,
            frames=total_frames,
            nals=total_nals,
            bytes_written=total_bytes,
            duration_s=duration_s,
            started_at=started_at,
            segments=len(segments),
            fps=fps,
        )
