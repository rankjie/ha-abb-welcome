"""Secure media-source loading and FFmpeg decoding for talkback audio."""

from __future__ import annotations

import asyncio
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

from aiohttp import ClientError, ClientTimeout
from homeassistant.components.ffmpeg import get_ffmpeg_manager
from homeassistant.components.media_source import async_resolve_media
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.network import get_url

MAX_SOURCE_BYTES = 20 * 1024 * 1024
MAX_DECODED_BYTES = 30 * 8000 * 2
_FETCH_TIMEOUT = ClientTimeout(total=20)
_FFMPEG_TIMEOUT = 45
_TTS_PROXY_PREFIX = "/api/tts_proxy/"
_SUPPORTED_MEDIA_SOURCE_DOMAINS = {"media_source", "tts"}


@dataclass(frozen=True, slots=True)
class AudioSource:
    """A validated local file or bounded in-memory audio source."""

    path: str | None = None
    data: bytes | None = None


def _usable_local_path(raw_path: object) -> str | None:
    """Return a path only when it is a small, regular local file."""
    if raw_path is None:
        return None
    try:
        path = Path(raw_path)
        info = path.stat()
    except (OSError, TypeError, ValueError):
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
        return None
    return str(path)


def _is_safe_tts_proxy_url(url: str) -> bool:
    """Return whether a resolved URL is the HA-local TTS proxy route."""
    parsed = urlsplit(url)
    if not parsed.path.startswith(_TTS_PROXY_PREFIX):
        return False
    token = parsed.path.removeprefix(_TTS_PROXY_PREFIX)
    decoded_token = unquote(token)
    return (
        not parsed.scheme
        and not parsed.netloc
        and not parsed.fragment
        and bool(token)
        and token not in (".", "..")
        and decoded_token not in (".", "..")
        and "/" not in token
        and "/" not in decoded_token
        and "\\" not in decoded_token
    )


async def async_resolve_audio_source(
    hass: HomeAssistant, media_content_id: str
) -> AudioSource:
    """Resolve and load only local media or HA's local TTS proxy output."""
    media_uri = urlsplit(media_content_id)
    if (
        media_uri.scheme != "media-source"
        or media_uri.netloc not in _SUPPORTED_MEDIA_SOURCE_DOMAINS
    ):
        raise HomeAssistantError("The selected audio source is not supported")
    try:
        resolved = await async_resolve_media(hass, media_content_id, None)
    except Exception as err:  # Home Assistant media sources expose varied errors.
        raise HomeAssistantError("Unable to resolve the selected audio") from err

    mime_type = str(getattr(resolved, "mime_type", "") or "").lower()
    if not (mime_type.startswith("audio/") or mime_type == "application/ogg"):
        raise HomeAssistantError("The selected media is not audio")

    path = await hass.async_add_executor_job(
        _usable_local_path, getattr(resolved, "path", None)
    )
    if path is not None:
        return AudioSource(path=path)

    resolved_url = str(getattr(resolved, "url", "") or "")
    if not _is_safe_tts_proxy_url(resolved_url):
        raise HomeAssistantError("The selected audio source is not supported")

    try:
        base_url = get_url(
            hass,
            allow_internal=True,
            allow_external=False,
            allow_cloud=False,
            allow_ip=True,
        )
        request_url = urljoin(
            base_url.rstrip("/") + "/", resolved_url.lstrip("/")
        )
        session = async_get_clientsession(hass)
        async with session.get(
            request_url,
            allow_redirects=False,
            timeout=_FETCH_TIMEOUT,
        ) as response:
            if response.status != 200:
                raise HomeAssistantError("Unable to load the selected audio")
            content_length = response.content_length
            if content_length is not None and content_length > MAX_SOURCE_BYTES:
                raise HomeAssistantError("The selected audio is too large")
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.content.iter_chunked(64 * 1024):
                total += len(chunk)
                if total > MAX_SOURCE_BYTES:
                    raise HomeAssistantError("The selected audio is too large")
                chunks.append(chunk)
    except HomeAssistantError:
        raise
    except (ClientError, OSError, TimeoutError, ValueError) as err:
        raise HomeAssistantError("Unable to load the selected audio") from err

    data = b"".join(chunks)
    if not data:
        raise HomeAssistantError("The selected audio is empty")
    return AudioSource(data=data)


async def _read_limited(
    stream: asyncio.StreamReader, limit: int
) -> bytes:
    output = bytearray()
    while chunk := await stream.read(min(64 * 1024, limit + 1 - len(output))):
        output.extend(chunk)
        if len(output) > limit:
            raise HomeAssistantError("The decoded audio is too large")
    return bytes(output)


async def _discard_stream(stream: asyncio.StreamReader) -> None:
    while await stream.read(64 * 1024):
        pass


async def _write_stdin(
    stream: asyncio.StreamWriter | None, data: bytes | None
) -> None:
    if stream is None:
        return
    try:
        if data:
            stream.write(data)
            await stream.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        stream.close()


async def async_decode_audio(
    hass: HomeAssistant, source: AudioSource
) -> bytes:
    """Decode a validated audio source to bounded 8 kHz mono PCM16LE."""
    input_arg = source.path if source.path is not None else "pipe:0"
    argv = [
        get_ffmpeg_manager(hass).binary,
        "-hide_banner",
        "-loglevel",
        "error",
        "-nostdin",
        "-protocol_whitelist",
        "file,pipe",
        "-i",
        input_arg,
        "-vn",
        "-ac",
        "1",
        "-ar",
        "8000",
        "-t",
        "30",
        "-f",
        "s16le",
        "pipe:1",
    ]
    process: asyncio.subprocess.Process | None = None
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=(
                asyncio.subprocess.PIPE
                if source.path is None
                else asyncio.subprocess.DEVNULL
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert process.stdout is not None
        assert process.stderr is not None

        async def _communicate() -> tuple[bytes, int]:
            pcm, _, _, return_code = await asyncio.gather(
                _read_limited(process.stdout, MAX_DECODED_BYTES),
                _discard_stream(process.stderr),
                _write_stdin(process.stdin, source.data),
                process.wait(),
            )
            return pcm, return_code

        pcm, return_code = await asyncio.wait_for(
            _communicate(), timeout=_FFMPEG_TIMEOUT
        )
    except asyncio.CancelledError:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        raise
    except TimeoutError as err:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        raise HomeAssistantError("Audio decoding timed out") from err
    except HomeAssistantError:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        raise
    except (OSError, ValueError) as err:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        raise HomeAssistantError("Unable to decode the selected audio") from err

    if return_code != 0 or not pcm:
        raise HomeAssistantError("Unable to decode the selected audio")
    return pcm


async def async_prepare_talkback_audio(
    hass: HomeAssistant, media_content_id: str
) -> bytes:
    """Resolve and decode one media-source selection for talkback."""
    return await async_decode_audio(
        hass, await async_resolve_audio_source(hass, media_content_id)
    )
