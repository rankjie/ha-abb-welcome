"""Behavior tests for previewing a ringing call before answering it.

A previewed call is taken in SIP early media only: video arrives while the
door station keeps ringing at every other station.  It is answered when
talking starts, and it ends with the ring otherwise.
"""

from __future__ import annotations

import asyncio
import socket
import time
import types
import unittest
from unittest import mock

from test_sip_listener_routing import _request, _Writer, sip_listener
from test_talk_audio_file import _load_submodule

_CALL_ID = "dialog-routing-test"
_SDP = (
    "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n"
    "t=0 0\r\nm=audio 50690 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"
    "m=video 50668 RTP/AVP 102\r\na=rtpmap:102 H264/90000\r\n"
)


def _responses(wire: bytes) -> list[str]:
    """Split the listener's output into one string per SIP message."""
    text = wire.decode("utf-8")
    starts = [
        index
        for index in range(len(text))
        if text.startswith(("SIP/2.0 ", "BYE "), index)
        and (index == 0 or text[index - 1] == "\n")
    ]
    return [text[a:b] for a, b in zip(starts, starts[1:] + [len(text)])]


def _to_tag(message: str) -> str:
    return next(
        line.split(";tag=")[1]
        for line in message.splitlines()
        if line.startswith("To:")
    )


def _sdp(message: str) -> str:
    return message.split("\r\n\r\n", 1)[1]


class TestListenerPreview(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.listener = sip_listener.SipListener(
            "gateway.invalid", "ha", "secret", "example.invalid"
        )
        self.writer = _Writer()
        self.writer.is_closing = lambda: False
        self.listener._writer = self.writer
        invite = _request()
        invite.body = _SDP.encode()
        invite._received_at = time.time()
        self.listener._open_invites[_CALL_ID] = invite
        self.call = await self.listener.accept_pending_call(
            station_id="",
            media_ip="192.0.2.2",
            audio_port=40000,
            video_port=40002,
            preview=True,
        )

    async def _answer(self) -> bool:
        task = asyncio.ensure_future(self.listener.answer_previewed_call(_CALL_ID))
        await asyncio.sleep(0)
        dialog = self.listener._accepted_dialogs.get(_CALL_ID)
        if dialog is not None:
            dialog.ack_event.set()
        return await task

    async def test_preview_sends_early_media_without_answering(self) -> None:
        (progress,) = _responses(self.writer.data)
        self.assertTrue(progress.startswith("SIP/2.0 183 Session Progress"))
        self.assertIn("m=video 40002 RTP/AVP 102", progress)
        self.assertFalse(self.call.answered)

    async def test_answer_completes_the_previewed_dialog(self) -> None:
        self.assertTrue(await self._answer())

        progress, ok = _responses(self.writer.data)
        self.assertTrue(ok.startswith("SIP/2.0 200 OK"))
        self.assertEqual(_to_tag(ok), _to_tag(progress))
        self.assertEqual(_sdp(ok), _sdp(progress))
        self.assertTrue(self.call.answered)

    async def test_answering_twice_sends_one_200(self) -> None:
        await self._answer()
        self.assertTrue(await self._answer())
        self.assertEqual(self.writer.data.count(b"SIP/2.0 200 OK"), 1)

    async def test_cancel_ends_the_preview(self) -> None:
        await self.listener._dispatch(_request("CANCEL"), self.writer, "192.0.2.2", 5061)

        _progress, cancel_ok, terminated = _responses(self.writer.data)
        self.assertTrue(cancel_ok.startswith("SIP/2.0 200 OK"))
        self.assertIn("CSeq: 1 CANCEL", cancel_ok)
        self.assertTrue(terminated.startswith("SIP/2.0 487 Request Terminated"))
        self.assertIn("CSeq: 1 INVITE", terminated)
        self.assertEqual(_to_tag(terminated), self.call.local_tag)
        self.assertEqual(
            await self.listener.wait_accepted_call_end(_CALL_ID), "remote_cancel"
        )
        self.assertFalse(await self.listener.answer_previewed_call(_CALL_ID))

    async def test_cancel_after_answering_does_not_end_the_call(self) -> None:
        await self._answer()
        await self.listener._dispatch(_request("CANCEL"), self.writer, "192.0.2.2", 5061)

        self.assertNotIn(b"487", self.writer.data)
        self.assertIn(_CALL_ID, self.listener._accepted_dialogs)

    async def test_releasing_a_preview_ends_only_this_branch(self) -> None:
        await self.listener.hangup_accepted_call(_CALL_ID)

        _progress, released = _responses(self.writer.data)
        self.assertTrue(released.startswith("SIP/2.0 480 Temporarily Unavailable"))
        self.assertEqual(_to_tag(released), self.call.local_tag)
        self.assertEqual(
            await self.listener.wait_accepted_call_end(_CALL_ID), "local_release"
        )

    async def test_hanging_up_an_answered_preview_sends_bye(self) -> None:
        self.listener._local_ip, self.listener._local_port = "192.0.2.2", 5061
        await self._answer()
        await self.listener.hangup_accepted_call(_CALL_ID)

        self.assertTrue(_responses(self.writer.data)[-1].startswith("BYE "))
        self.assertNotIn(b"SIP/2.0 480", self.writer.data)


class _FakeListener:
    def __init__(self, *, answers: bool = True) -> None:
        self.answers = answers
        self.answered: list[str] = []
        self.previews: list[bool] = []

    async def answer_previewed_call(self, call_id: str) -> bool:
        self.answered.append(call_id)
        return self.answers

    def pending_call_for_station(self, station_id: str) -> bool:
        return True

    async def accept_pending_call(self, *, preview: bool, **_kwargs):
        self.previews.append(preview)
        return sip_listener.AcceptedIncomingCall(
            caller_uri="sip:door@example.invalid",
            caller_user="door",
            call_id=_CALL_ID,
            local_tag="local",
            remote_tag="remote",
            invite_cseq=1,
            remote_contact="",
            local_contact="",
            from_header="",
            to_header="",
            remote_sdp=None,
            audio_local_port=40000,
            video_local_port=40002,
            answered=not preview,
        )


class TestSessionPreview(unittest.IsolatedAsyncioTestCase):
    def _session(self, listener: _FakeListener, *, preview: bool = True):
        _load_submodule("intercom_dialer")
        mp = _load_submodule("media_pipeline")
        session = mp.StreamSession.__new__(mp.StreamSession)
        session._incoming_listener = listener
        session._door = types.SimpleNamespace(name="Door", station_id="door")
        session._pickup_allowed = lambda: True
        session._preview_incoming = lambda: preview
        session._media_ip = "192.0.2.2"
        session._previewing = False
        session._answer_lock = asyncio.Lock()
        session._accepted_incoming_call_id = None
        session._talk_sender = None
        session._talkback_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(session._talkback_sock.close)
        session._remote_audio_pt = 8
        session._audio_send_key = None
        session._endpoints = mp._MediaEndpoints(
            audio=mp._RemoteMediaEndpoints(
                rtp=("127.0.0.1", 9),
                rtcp=("127.0.0.1", 10),
                rtcp_mux=False,
                explicit_rtcp=False,
            ),
            video=None,
        )
        return session

    async def _take_call(self, session) -> None:
        await session._accept_incoming_call_if_pending(
            audio_port=40000, video_port=40002
        )

    async def test_ringing_call_is_previewed_when_the_option_is_on(self) -> None:
        listener = _FakeListener()
        session = self._session(listener, preview=True)
        await self._take_call(session)
        self.assertEqual(listener.previews, [True])
        self.assertTrue(session.previewing)
        self.assertFalse(session.talkback_ready)

    async def test_ringing_call_is_answered_when_the_option_is_off(self) -> None:
        listener = _FakeListener()
        session = self._session(listener, preview=False)
        await self._take_call(session)
        self.assertEqual(listener.previews, [False])
        self.assertFalse(session.previewing)

    async def test_answer_picks_up_and_makes_talkback_ready(self) -> None:
        listener = _FakeListener()
        session = self._session(listener)
        await self._take_call(session)

        await session.answer()
        self.addAsyncCleanup(session._talk_sender.stop)

        self.assertEqual(listener.answered, [_CALL_ID])
        self.assertFalse(session.previewing)
        self.assertTrue(session.talkback_ready)

    async def test_concurrent_answers_pick_up_once(self) -> None:
        listener = _FakeListener()
        session = self._session(listener)
        await self._take_call(session)

        await asyncio.gather(session.answer(), session.answer())
        self.addAsyncCleanup(session._talk_sender.stop)

        self.assertEqual(listener.answered, [_CALL_ID])

    async def test_answer_fails_when_the_ring_already_ended(self) -> None:
        session = self._session(_FakeListener(answers=False))
        await self._take_call(session)

        with self.assertRaises(RuntimeError):
            await session.answer()
        self.assertFalse(session.talkback_ready)


class _RingingGateway:
    """Stand-in for the SIP listener and the gateway's RTP ports on loopback."""

    def __init__(self) -> None:
        self.audio = self._udp()
        self.video = self._udp()
        self.ended = asyncio.Event()
        self.end_reason = ""
        self.hung_up: list[str] = []
        self.session_video_port = 0

    @staticmethod
    def _udp() -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.setblocking(False)
        return sock

    def close(self) -> None:
        self.audio.close()
        self.video.close()

    def audio_packets(self) -> list[bytes]:
        packets = []
        while True:
            try:
                packets.append(self.audio.recv(2048))
            except BlockingIOError:
                return packets

    def pending_call_for_station(self, station_id: str) -> bool:
        return True

    async def accept_pending_call(
        self, *, video_port: int, audio_port: int, preview: bool, **_kwargs
    ):
        self.session_video_port = video_port
        offer = (
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\n"
            f"t=0 0\r\nm=audio {self.audio.getsockname()[1]} RTP/AVP 8\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            f"m=video {self.video.getsockname()[1]} RTP/AVP 102\r\n"
            "a=rtpmap:102 H264/90000\r\n"
        )
        return sip_listener.AcceptedIncomingCall(
            caller_uri="sip:door@example.invalid",
            caller_user="door",
            call_id=_CALL_ID,
            local_tag="local",
            remote_tag="remote",
            invite_cseq=1,
            remote_contact="",
            local_contact="",
            from_header="",
            to_header="",
            remote_sdp=sip_listener.parse_sdp(offer.encode()),
            audio_local_port=audio_port,
            video_local_port=video_port,
            answered=not preview,
        )

    async def answer_previewed_call(self, call_id: str) -> bool:
        return not self.ended.is_set()

    async def wait_accepted_call_end(self, call_id: str) -> str:
        await self.ended.wait()
        return self.end_reason

    async def hangup_accepted_call(self, call_id: str) -> None:
        self.hung_up.append(call_id)

    def end(self, reason: str) -> None:
        self.end_reason = reason
        self.ended.set()


class TestPreviewMedia(unittest.IsolatedAsyncioTestCase):
    """A real StreamSession previewing a ring against loopback RTP."""

    async def asyncSetUp(self) -> None:
        _load_submodule("intercom_dialer")
        mp = _load_submodule("media_pipeline")
        self.gateway = _RingingGateway()
        self.addCleanup(self.gateway.close)
        self.video: list[bytes] = []
        self.ended: list[tuple[str, str]] = []
        self.session = mp.StreamSession(
            dialer=types.SimpleNamespace(host="127.0.0.1"),
            door=types.SimpleNamespace(name="Door", station_id="door"),
            gateway_host="127.0.0.1",
            incoming_listener=self.gateway,
            pickup_allowed=lambda: True,
            preview_incoming=lambda: True,
            on_call_ended=lambda call_id, reason: self.ended.append((call_id, reason)),
            on_video_packet=self.video.append,
        )
        await self.session.open()
        self.addAsyncCleanup(self.session.close)

    async def _settle(self, seconds: float = 0.3) -> None:
        await asyncio.sleep(seconds)

    async def test_video_flows_while_the_call_is_unanswered(self) -> None:
        packet = b"\x80\x66" + bytes(10) + b"\x65" + bytes(20)
        self.gateway.video.sendto(
            packet, ("127.0.0.1", self.gateway.session_video_port)
        )
        await self._settle(0.1)

        self.assertTrue(self.session.previewing)
        self.assertFalse(self.session.talkback_ready)
        self.assertEqual(len(self.video), 1)

    async def test_talkback_audio_starts_only_after_answering(self) -> None:
        await self._settle()
        before = self.gateway.audio_packets()
        await self.session.answer()
        await self._settle()
        after = self.gateway.audio_packets()

        # Unanswered, the audio leg carries only the few hole-punch packets;
        # answered, the talkback sender runs at 50 packets per second.
        self.assertLess(len(before), 10)
        self.assertGreater(len(after), 10)
        self.assertTrue(all(len(packet) == 172 for packet in after))
        self.assertTrue(self.session.talkback_ready)
        self.assertFalse(self.session.previewing)

    async def test_cancelled_ring_closes_the_session(self) -> None:
        self.gateway.end("remote_cancel")
        await self._settle(0.1)

        self.assertFalse(self.session.active)
        self.assertFalse(self.session.previewing)
        self.assertEqual(self.ended, [(_CALL_ID, "remote_cancel")])

    async def test_closing_a_preview_releases_the_call(self) -> None:
        await self.session.close()
        self.assertEqual(self.gateway.hung_up, [_CALL_ID])
        self.assertFalse(self.session.active)


class _FakeStreamSession:
    def __init__(self, *, previewing: bool) -> None:
        self.active = True
        self.previewing = previewing
        self.talkback_ready = not previewing
        self.talkback_talking = False
        self.answers = 0
        self.closed = 0
        self.fed: list[bytes] = []

    async def answer(self) -> None:
        self.answers += 1
        await asyncio.sleep(0)
        self.previewing = False
        self.talkback_ready = True

    async def close(self) -> None:
        self.closed += 1
        self.active = False

    def start_talkback(self) -> dict:
        self.talkback_talking = True
        return {}

    def stop_talkback(self) -> dict:
        self.talkback_talking = False
        return {}

    def talkback_stats(self) -> dict:
        return {}

    def set_packet_handlers(self, **_kwargs) -> None:
        return None

    def feed_talkback_pcma_rtp(self, packet: bytes) -> int:
        self.fed.append(packet)
        return 1


class TestCoordinatorPreview(unittest.IsolatedAsyncioTestCase):
    def _coordinator(self, *, previewing: bool):
        _load_submodule("intercom_dialer")
        _load_submodule("media_pipeline")
        self.camera = _load_submodule("camera")
        self.streaming_state = _load_submodule("streaming_state")
        coordinator = self.camera.StationStreamCoordinator.__new__(
            self.camera.StationStreamCoordinator
        )
        self.session = _FakeStreamSession(previewing=previewing)
        self.tasks: list[asyncio.Task] = []

        def _background(coro, *, name: str = ""):
            task = asyncio.create_task(coro)
            self.tasks.append(task)
            return task

        coordinator.hass = types.SimpleNamespace(
            data={}, async_create_background_task=_background
        )
        coordinator.entry_id = "entry"
        coordinator.session = self.session
        coordinator.door = types.SimpleNamespace(station_id="1", address="1")
        coordinator._stream_lock = asyncio.Lock()
        coordinator._talkback_owner = ""
        coordinator._active_file_playbacks = 0
        coordinator._state_callbacks = []
        coordinator._rtsp_play_sessions = []
        coordinator._close_task = None
        coordinator._answer_task = None
        return coordinator

    async def _run_delayed_close(self, coordinator) -> None:
        with mock.patch.object(self.camera, "_TEARDOWN_GRACE_SECONDS", 0):
            await coordinator._delayed_close()

    async def test_previewed_ring_stays_up_without_viewers(self) -> None:
        coordinator = self._coordinator(previewing=True)
        await self._run_delayed_close(coordinator)
        self.assertEqual(self.session.closed, 0)

    async def test_answered_call_closes_without_viewers(self) -> None:
        coordinator = self._coordinator(previewing=False)
        await self._run_delayed_close(coordinator)
        self.assertEqual(self.session.closed, 1)

    async def test_previewed_call_reports_that_talking_can_start(self) -> None:
        coordinator = self._coordinator(previewing=True)
        self.assertTrue(coordinator.talkback_ready)
        self.assertTrue(coordinator.previewing)

    async def test_microphone_audio_answers_the_previewed_call(self) -> None:
        coordinator = self._coordinator(previewing=True)
        rtsp_session = types.SimpleNamespace(session_id="00000001")

        coordinator.feed_backchannel_rtp(rtsp_session, b"early-1")
        coordinator.feed_backchannel_rtp(rtsp_session, b"early-2")
        await asyncio.gather(*self.tasks)
        coordinator.feed_backchannel_rtp(rtsp_session, b"voice")

        self.assertEqual(self.session.answers, 1)
        self.assertEqual(self.session.fed, [b"voice"])
        self.assertTrue(self.session.talkback_talking)

    async def test_talk_stop_closes_an_answered_call_nobody_watches(self) -> None:
        coordinator = self._coordinator(previewing=False)
        coordinator.start_talkback("service-1")
        with mock.patch.object(self.camera, "_TEARDOWN_GRACE_SECONDS", 0):
            coordinator.stop_talkback("service-1")
            await asyncio.gather(*self.tasks)
        self.assertEqual(self.session.closed, 1)

    async def test_talk_stop_keeps_a_watched_call_open(self) -> None:
        coordinator = self._coordinator(previewing=False)
        coordinator._rtsp_play_sessions = [object()]
        coordinator.start_talkback("service-1")
        coordinator.stop_talkback("service-1")
        self.assertEqual(self.tasks, [])

    def _arm(self, coordinator, reason: str):
        state = self.streaming_state.get_state(coordinator.hass, "entry")
        state.armed = True
        state.reason = reason
        return state

    async def test_cancelled_ring_ends_the_ring_arm(self) -> None:
        coordinator = self._coordinator(previewing=True)
        state = self._arm(coordinator, self.streaming_state.ARM_REASON_RING)
        coordinator._on_gateway_call_ended("call", "remote_cancel")
        self.assertFalse(state.armed)

    async def test_cancelled_ring_keeps_a_manual_arm(self) -> None:
        coordinator = self._coordinator(previewing=True)
        state = self._arm(coordinator, self.streaming_state.ARM_REASON_MANUAL)
        coordinator._on_gateway_call_ended("call", "remote_cancel")
        self.assertTrue(state.armed)

    async def test_hung_up_call_keeps_the_ring_arm(self) -> None:
        coordinator = self._coordinator(previewing=False)
        state = self._arm(coordinator, self.streaming_state.ARM_REASON_RING)
        coordinator._on_gateway_call_ended("call", "remote_bye")
        self.assertTrue(state.armed)



class TestPreviewOption(unittest.TestCase):
    """Bridges read the option from the camera state, so a change must show."""

    def setUp(self) -> None:
        self.streaming_state = _load_submodule("streaming_state")
        self.hass = types.SimpleNamespace(data={})
        self.signals: list[str] = []
        patcher = mock.patch.object(
            self.streaming_state,
            "async_dispatcher_send",
            lambda hass, signal: self.signals.append(signal),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _set(self, enabled: bool) -> None:
        self.streaming_state.set_preview_before_answer(self.hass, "entry", enabled)

    def test_option_is_off_until_set(self) -> None:
        self.assertFalse(
            self.streaming_state.is_preview_before_answer(self.hass, "entry")
        )

    def test_a_change_is_stored_and_announced_once(self) -> None:
        self._set(True)
        self._set(True)
        self.assertTrue(
            self.streaming_state.is_preview_before_answer(self.hass, "entry")
        )
        self.assertEqual(
            self.signals,
            [self.streaming_state.signal_preview_before_answer_changed("entry")],
        )

    def test_turning_it_off_again_is_announced(self) -> None:
        self._set(True)
        self._set(False)
        self.assertFalse(
            self.streaming_state.is_preview_before_answer(self.hass, "entry")
        )
        self.assertEqual(len(self.signals), 2)


if __name__ == "__main__":
    unittest.main()
