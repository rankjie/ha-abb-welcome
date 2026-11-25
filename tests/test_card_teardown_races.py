"""Offline regressions for disarm/re-arm stream teardown races.

The production coordinator and camera teardown method are compiled from their
real AST nodes.  Minimal fakes keep this independent of Home Assistant while
preserving the locking and predicate ordering that caused the regression.
"""

from __future__ import annotations

import ast
import asyncio
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_CAMERA_PATH = (
    Path(__file__).resolve().parent.parent
    / "custom_components"
    / "abb_welcome"
    / "camera.py"
)


class _Logger:
    def info(self, *_args: object, **_kwargs: object) -> None:
        pass


class _Session:
    def __init__(self, **_kwargs: Any) -> None:
        self.active = True
        self.close_calls = 0
        self.open_calls = 0
        self.handler_calls: list[dict[str, object]] = []
        self.talkback_ready = False
        self.previewing = False
        self.video_codec = "H264"
        self.video_fmtp = None

    def set_packet_handlers(self, **kwargs: object) -> None:
        self.handler_calls.append(kwargs)

    async def close(self) -> None:
        self.close_calls += 1
        self.active = False

    async def open(self) -> None:
        self.open_calls += 1
        self.active = True


class _RtspClient:
    def __init__(self, session_id: str = "client") -> None:
        self.session_id = session_id
        self.close_calls = 0
        self.writer = SimpleNamespace(is_closing=lambda: False)

    def close(self) -> None:
        self.close_calls += 1

    def push_rtp(self, _channel: int, _packet: bytes) -> bool:
        return True


class _Hass:
    def __init__(self) -> None:
        self.data: dict[str, object] = {}

    def async_create_background_task(self, coro, *, name: str):
        return asyncio.create_task(coro, name=name)


def _class_node(name: str) -> ast.ClassDef:
    parsed = ast.parse(_CAMERA_PATH.read_text(encoding="utf-8"), filename=str(_CAMERA_PATH))
    return next(
        node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == name
    )


def _load_coordinator() -> type[Any]:
    node = _class_node("StationStreamCoordinator")
    module = ast.Module(
        body=[
            ast.ImportFrom(module="__future__", names=[ast.alias("annotations")], level=0),
            node,
        ],
        type_ignores=[],
    )
    ast.fix_missing_locations(module)
    namespace: dict[str, Any] = {
        "asyncio": asyncio,
        "Any": Any,
        "Callable": Callable,
        "StreamSession": _Session,
        "_LOGGER": _Logger(),
        "_TEARDOWN_GRACE_SECONDS": 0.01,
        "is_pickup_allowed": lambda _hass, _entry_id: True,
        "is_preview_before_answer": lambda _hass, _entry_id: False,
        "VIDEO_RTP_CHANNEL": 0,
        "AUDIO_RTP_CHANNEL": 1,
        "_backchannel_owner": lambda sess: f"rtsp:{sess.session_id}",
    }
    exec(compile(module, str(_CAMERA_PATH), "exec"), namespace)  # noqa: S102
    return namespace["StationStreamCoordinator"]


def _load_force_teardown() -> Callable[[object], object]:
    camera = _class_node("ABBWelcomeCamera")
    method = next(
        node
        for node in camera.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_force_teardown"
    )
    module = ast.Module(body=[method], type_ignores=[])
    ast.fix_missing_locations(module)
    namespace: dict[str, Any] = {}
    exec(compile(module, str(_CAMERA_PATH), "exec"), namespace)  # noqa: S102
    return namespace["_force_teardown"]


def _coordinator() -> Any:
    cls = _load_coordinator()
    coordinator = cls(
        hass=_Hass(),
        entry_id="entry-a",
        dialer=SimpleNamespace(host="gateway.invalid"),
        incoming_listener=None,
        door=SimpleNamespace(station_id="door", address="1"),
        camera_index=None,
    )
    return coordinator


def test_force_close_predicate_false_has_no_stream_side_effects() -> None:
    async def scenario() -> None:
        coordinator = _coordinator()
        client = _RtspClient()
        coordinator._rtsp_play_sessions = [client]
        await coordinator.force_close(only_if=lambda: False)
        assert coordinator._stream_generation == 0
        assert coordinator._rtsp_play_sessions == [client]
        assert client.close_calls == 0
        assert coordinator.session.close_calls == 0

    asyncio.run(scenario())


def test_attach_waiting_on_lock_is_invalidated_by_new_stream_generation() -> None:
    async def scenario() -> None:
        coordinator = _coordinator()
        client = _RtspClient("old-client")
        await coordinator._stream_lock.acquire()
        attach = asyncio.create_task(coordinator.attach_rtsp_session(client))
        await asyncio.sleep(0)
        # Models force-close completing while the old attach was queued.
        coordinator._stream_generation += 1
        coordinator._stream_lock.release()
        assert await attach is False
        assert coordinator.session.open_calls == 0

    asyncio.run(scenario())


def test_attach_rejects_a_client_whose_writer_closed_while_waiting() -> None:
    async def scenario() -> None:
        coordinator = _coordinator()
        client = _RtspClient("closed-client")
        await coordinator._stream_lock.acquire()
        attach = asyncio.create_task(coordinator.attach_rtsp_session(client))
        await asyncio.sleep(0)
        client.writer.is_closing = lambda: True
        coordinator._stream_lock.release()
        assert await attach is False
        assert coordinator.session.open_calls == 0

    asyncio.run(scenario())


def test_rearm_before_queued_teardown_preserves_the_new_stream() -> None:
    async def scenario() -> None:
        coordinator = _coordinator()
        client = _RtspClient("new-client")
        coordinator._rtsp_play_sessions = [client]
        rtsp = SimpleNamespace(stop_calls=0, start_calls=0)

        async def stop() -> None:
            rtsp.stop_calls += 1

        async def start() -> None:
            rtsp.start_calls += 1

        rtsp.stop = stop
        rtsp.start = start
        writes: list[None] = []
        camera = SimpleNamespace(
            _coordinator=coordinator,
            _rtsp=rtsp,
            _stream_allowed=lambda: True,
            _register_with_go2rtc=lambda: None,
            async_write_ha_state=lambda: writes.append(None),
        )
        await _load_force_teardown()(camera)

        assert coordinator._rtsp_play_sessions == [client]
        assert client.close_calls == 0
        assert coordinator.session.close_calls == 0
        assert rtsp.stop_calls == 0
        assert rtsp.start_calls == 0
        assert len(writes) == 1

    asyncio.run(scenario())


def test_reconnect_waits_for_hangup_instead_of_cancelling_cleanup() -> None:
    async def scenario() -> None:
        coordinator = _coordinator()
        coordinator.session.active = True
        closing = asyncio.Event()
        finish_close = asyncio.Event()
        cancelled = False

        async def close() -> None:
            nonlocal cancelled
            closing.set()
            try:
                await finish_close.wait()
            except asyncio.CancelledError:
                cancelled = True
                raise
            coordinator.session.active = False

        coordinator.session.close = close
        close_task = asyncio.create_task(coordinator._delayed_close())
        coordinator._close_task = close_task
        async with asyncio.timeout(1):
            await closing.wait()
            attach = asyncio.create_task(coordinator.attach_rtsp_session(_RtspClient()))
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            finish_close.set()
            results = await asyncio.gather(close_task, attach, return_exceptions=True)
        assert cancelled is False
        assert results == [None, True]
        assert coordinator.session.open_calls == 1

    asyncio.run(scenario())
