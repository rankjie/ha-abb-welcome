"""Tests for secure media-source talkback audio playback."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


def _install_homeassistant_stubs() -> None:
    homeassistant = sys.modules.setdefault(
        "homeassistant", types.ModuleType("homeassistant")
    )
    homeassistant.__path__ = []
    components = sys.modules.setdefault(
        "homeassistant.components", types.ModuleType("homeassistant.components")
    )
    components.__path__ = []
    ffmpeg = types.ModuleType("homeassistant.components.ffmpeg")
    ffmpeg.get_ffmpeg_manager = lambda hass: hass.ffmpeg
    sys.modules[ffmpeg.__name__] = ffmpeg
    media_source = types.ModuleType("homeassistant.components.media_source")
    media_source.async_resolve_media = None
    sys.modules[media_source.__name__] = media_source
    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = object
    sys.modules[core.__name__] = core
    exceptions = types.ModuleType("homeassistant.exceptions")

    class HomeAssistantError(Exception):
        pass

    exceptions.HomeAssistantError = HomeAssistantError
    sys.modules[exceptions.__name__] = exceptions
    helpers = sys.modules.setdefault(
        "homeassistant.helpers", types.ModuleType("homeassistant.helpers")
    )
    helpers.__path__ = []
    aiohttp_client = types.ModuleType("homeassistant.helpers.aiohttp_client")
    aiohttp_client.async_get_clientsession = lambda hass: hass.session
    sys.modules[aiohttp_client.__name__] = aiohttp_client
    network = types.ModuleType("homeassistant.helpers.network")
    network.get_url = lambda hass, **kwargs: "http://127.0.0.1:8123"
    sys.modules[network.__name__] = network


def _load_audio() -> types.ModuleType:
    _install_homeassistant_stubs()
    pkg = sys.modules.setdefault("abb_welcome", types.ModuleType("abb_welcome"))
    pkg.__path__ = [str(_PKG_DIR)]
    full = "abb_welcome.talkback_audio"
    sys.modules.pop(full, None)
    spec = importlib.util.spec_from_file_location(full, _PKG_DIR / "talkback_audio.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full] = module
    spec.loader.exec_module(module)
    return module


audio = _load_audio()


class _Hass:
    ffmpeg = types.SimpleNamespace(binary="/configured/ffmpeg")

    async def async_add_executor_job(self, func, *args):
        return func(*args)


class _FakeResponseContent:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def iter_chunked(self, _size: int):
        for chunk in self._chunks:
            yield chunk


class _FakeResponse:
    status = 200
    content_length = None

    def __init__(self, chunks: list[bytes]) -> None:
        self.content = _FakeResponseContent(chunks)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


class _FakeSession:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response
        self.requests: list[tuple[str, dict]] = []

    def get(self, url: str, **kwargs):
        self.requests.append((url, kwargs))
        return self.response


def test_safe_tts_proxy_route_validation() -> None:
    assert audio._is_safe_tts_proxy_url("/api/tts_proxy/example.mp3")
    assert not audio._is_safe_tts_proxy_url("https://example.com/audio.mp3")
    assert not audio._is_safe_tts_proxy_url("//example.com/api/tts_proxy/x.mp3")
    assert not audio._is_safe_tts_proxy_url("/api/media/example.mp3")
    assert not audio._is_safe_tts_proxy_url("/api/tts_proxy/../secrets")
    assert not audio._is_safe_tts_proxy_url("/api/tts_proxy/%2e%2e")
    assert not audio._is_safe_tts_proxy_url("/api/tts_proxy/a%2fb")
    assert not audio._is_safe_tts_proxy_url("/api/tts_proxy/a%5cb")


def test_resolver_accepts_only_small_regular_audio_file(tmp_path, monkeypatch) -> None:
    source = tmp_path / "voice.mp3"
    source.write_bytes(b"audio")

    async def _resolve(_hass, media_id, target):
        assert media_id == "media-source://media_source/local/voice.mp3"
        assert target is None
        return types.SimpleNamespace(
            path=source, url="/media/local/voice.mp3", mime_type="audio/mpeg"
        )

    monkeypatch.setattr(audio, "async_resolve_media", _resolve)
    resolved = asyncio.run(
        audio.async_resolve_audio_source(
            _Hass(), "media-source://media_source/local/voice.mp3"
        )
    )
    assert resolved == audio.AudioSource(path=str(source))


def test_resolver_fetches_only_bounded_local_tts_proxy(monkeypatch) -> None:
    async def _resolve(_hass, _media_id, _target):
        return types.SimpleNamespace(
            path=None,
            url="/api/tts_proxy/safe-token.mp3",
            mime_type="audio/mpeg",
        )

    hass = _Hass()
    hass.session = _FakeSession(_FakeResponse([b"generated ", b"speech"]))
    monkeypatch.setattr(audio, "async_resolve_media", _resolve)

    resolved = asyncio.run(
        audio.async_resolve_audio_source(hass, "media-source://tts/generated")
    )

    assert resolved == audio.AudioSource(data=b"generated speech")
    assert hass.session.requests == [
        (
            "http://127.0.0.1:8123/api/tts_proxy/safe-token.mp3",
            {"allow_redirects": False, "timeout": audio._FETCH_TIMEOUT},
        )
    ]


def test_resolver_rejects_oversize_local_file(tmp_path, monkeypatch) -> None:
    source = tmp_path / "oversize.mp3"
    with source.open("wb") as source_file:
        source_file.truncate(audio.MAX_SOURCE_BYTES + 1)

    async def _resolve(*_args):
        return types.SimpleNamespace(
            path=source, url="/media/local/oversize.mp3", mime_type="audio/mpeg"
        )

    monkeypatch.setattr(audio, "async_resolve_media", _resolve)
    with pytest.raises(audio.HomeAssistantError, match="not supported"):
        asyncio.run(
            audio.async_resolve_audio_source(
                _Hass(), "media-source://media_source/local/oversize.mp3"
            )
        )


def test_resolver_fetches_only_bounded_tts_proxy(monkeypatch) -> None:
    class _Content:
        async def iter_chunked(self, _size):
            yield b"tts-"
            yield b"audio"

    class _Response:
        status = 200
        content_length = 9
        content = _Content()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    class _Session:
        def get(self, url, **kwargs):
            assert url == "http://127.0.0.1:8123/api/tts_proxy/token.mp3"
            assert kwargs["allow_redirects"] is False
            return _Response()

    async def _resolve(*_args):
        return types.SimpleNamespace(
            path=None, url="/api/tts_proxy/token.mp3", mime_type="application/ogg"
        )

    hass = _Hass()
    hass.session = _Session()
    monkeypatch.setattr(audio, "async_resolve_media", _resolve)
    resolved = asyncio.run(
        audio.async_resolve_audio_source(hass, "media-source://tts/message")
    )
    assert resolved == audio.AudioSource(data=b"tts-audio")


def test_resolver_rejects_non_audio_and_arbitrary_url(monkeypatch) -> None:
    async def _resolve_non_audio(*_args):
        return types.SimpleNamespace(
            path=None, url="/api/tts_proxy/x", mime_type="video/mp4"
        )

    monkeypatch.setattr(audio, "async_resolve_media", _resolve_non_audio)
    with pytest.raises(audio.HomeAssistantError, match="not audio"):
        asyncio.run(
            audio.async_resolve_audio_source(_Hass(), "media-source://tts/x")
        )

    async def _resolve_url(*_args):
        return types.SimpleNamespace(
            path=None, url="https://example.com/x.mp3", mime_type="audio/mpeg"
        )

    monkeypatch.setattr(audio, "async_resolve_media", _resolve_url)
    with pytest.raises(audio.HomeAssistantError, match="not supported"):
        asyncio.run(
            audio.async_resolve_audio_source(_Hass(), "media-source://tts/x")
        )

    with pytest.raises(audio.HomeAssistantError, match="not supported"):
        asyncio.run(
            audio.async_resolve_audio_source(
                _Hass(), "media-source://remote_provider/audio.mp3"
            )
        )
    with pytest.raises(audio.HomeAssistantError, match="not supported"):
        asyncio.run(
            audio.async_resolve_audio_source(_Hass(), "https://example.com/audio.mp3")
        )


class _FakeStream:
    def __init__(self, value: bytes = b"") -> None:
        self._value = value
        self.written = b""

    async def read(self, _amount: int) -> bytes:
        value, self._value = self._value, b""
        return value

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        pass


class _FakeProcess:
    def __init__(
        self, pcm: bytes, returncode: int = 0, *, wait_for_kill: bool = False
    ) -> None:
        self.stdin = _FakeStream()
        self.stdout = _FakeStream(pcm)
        self.stderr = _FakeStream(b"private ffmpeg detail")
        self._wait_returncode = returncode
        self.returncode = None
        self.killed = False
        self._wait_for_kill = wait_for_kill
        self._killed = asyncio.Event()

    async def wait(self) -> int:
        if self._wait_for_kill:
            await self._killed.wait()
        self.returncode = self._wait_returncode
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self._wait_returncode = -9
        self._killed.set()


def test_ffmpeg_uses_argv_protocol_limit_and_pipe(monkeypatch) -> None:
    captured = {}
    process = _FakeProcess(b"\0" * 320)

    async def _spawn(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)
    pcm = asyncio.run(
        audio.async_decode_audio(_Hass(), audio.AudioSource(data=b"input"))
    )
    assert pcm == b"\0" * 320
    assert captured["args"][0] == "/configured/ffmpeg"
    assert captured["args"][1:6] == (
        "-hide_banner", "-loglevel", "error", "-nostdin", "-protocol_whitelist"
    )
    assert "file,pipe" in captured["args"]
    assert ("-t", "30") == captured["args"][captured["args"].index("-t") :][:2]
    assert process.stdin.written == b"input"


def test_decoded_output_bound_kills_process(monkeypatch) -> None:
    process = _FakeProcess(
        b"x" * (audio.MAX_DECODED_BYTES + 1), wait_for_kill=True
    )

    async def _spawn(*_args, **_kwargs):
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)
    with pytest.raises(audio.HomeAssistantError, match="too large"):
        asyncio.run(audio.async_decode_audio(_Hass(), audio.AudioSource(data=b"input")))
    assert process.killed


def test_ffmpeg_timeout_kills_process(monkeypatch) -> None:
    process = _FakeProcess(b"", wait_for_kill=True)

    async def _spawn(*_args, **_kwargs):
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)
    monkeypatch.setattr(audio, "_FFMPEG_TIMEOUT", 0.001)
    with pytest.raises(audio.HomeAssistantError, match="timed out"):
        asyncio.run(audio.async_decode_audio(_Hass(), audio.AudioSource(data=b"input")))
    assert process.killed


def test_pcm_playback_pads_frames_and_rejects_busy(monkeypatch) -> None:
    intercom_name = "abb_welcome.intercom_dialer"
    pkg = sys.modules.setdefault("abb_welcome", types.ModuleType("abb_welcome"))
    pkg.__path__ = [str(_PKG_DIR)]
    for name in (intercom_name, "abb_welcome.media_pipeline"):
        sys.modules.pop(name, None)
    intercom_spec = importlib.util.spec_from_file_location(
        intercom_name, _PKG_DIR / "intercom_dialer.py"
    )
    intercom = importlib.util.module_from_spec(intercom_spec)
    sys.modules[intercom_name] = intercom
    intercom_spec.loader.exec_module(intercom)
    media_spec = importlib.util.spec_from_file_location(
        "abb_welcome.media_pipeline", _PKG_DIR / "media_pipeline.py"
    )
    media = importlib.util.module_from_spec(media_spec)
    sys.modules[media_spec.name] = media
    media_spec.loader.exec_module(media)
    session = media.StreamSession(
        dialer=object(),
        door=intercom.Door("door", "address"),
        gateway_host="192.0.2.1",
    )

    class _Sender:
        active = True
        max_queue_frames = 10
        interval = 0.02
        talking = False

        def __init__(self):
            self.fed = []

        @property
        def queue_frames(self):
            return 0

        def start_talk(self):
            self.talking = True

        def stop_talk(self):
            self.talking = False

        def feed_pcm16le(self, frame):
            self.fed.append(frame)

        async def drain(self, timeout):
            pass

        def stats(self):
            return {"talking": self.talking}

    sender = _Sender()
    session._talk_sender = sender
    stats = asyncio.run(session.send_talkback_pcm16le_audio(b"\x01\x02\x03"))
    assert stats["talking"] is False
    assert len(sender.fed) == 1
    assert len(sender.fed[0]) == 320
    assert sender.fed[0].startswith(b"\x01\x02\x03\x00")

    async def _busy():
        await session._talkback_playback_lock.acquire()
        try:
            with pytest.raises(RuntimeError, match="already in progress"):
                await session.send_talkback_pcm16le_audio(b"\0\0")
        finally:
            session._talkback_playback_lock.release()

    asyncio.run(_busy())

    async def _cancel_playback():
        entered_drain = asyncio.Event()

        async def _blocked_drain(timeout):
            entered_drain.set()
            await asyncio.Event().wait()

        sender.drain = _blocked_drain
        task = asyncio.create_task(session.send_talkback_pcm16le_audio(b"\0\0"))
        await entered_drain.wait()
        assert sender.talking
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not sender.talking

    asyncio.run(_cancel_playback())
