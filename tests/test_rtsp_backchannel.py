"""Behavior tests for talkback over the RTSP ONVIF audio backchannel.

go2rtc asks for the backchannel on DESCRIBE and then sends the browser's
microphone RTP as interleaved frames on the control connection.  Those packets
must reach the door station's talkback leg, and only from the track and client
that negotiated it.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import types
import unittest

from test_talk_audio_file import _load_submodule

_REQUIRE = "Require: www.onvif.org/ver20/backchannel\r\n"


def _rtp(payload: bytes, *, payload_type: int = 8) -> bytes:
    return struct.pack("!BBHII", 0x80, payload_type, 1, 160, 0x1234) + payload


def _frame(channel: int, packet: bytes) -> bytes:
    return struct.pack("!cBH", b"$", channel, len(packet)) + packet


class _RtspClient:
    def __init__(self, reader, writer, base: str) -> None:
        self._reader = reader
        self._writer = writer
        self._base = base
        self._cseq = 0

    async def request(self, method: str, path: str = "", headers: str = "") -> str:
        self._cseq += 1
        self._writer.write(
            f"{method} {self._base}{path} RTSP/1.0\r\n"
            f"CSeq: {self._cseq}\r\n{headers}\r\n".encode()
        )
        await self._writer.drain()
        head = (await self._reader.readuntil(b"\r\n\r\n")).decode()
        for line in head.split("\r\n"):
            if line.lower().startswith("content-length:"):
                body = await self._reader.readexactly(int(line.split(":")[1]))
                return head + body.decode()
        return head

    async def send(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def setup(self, track: int, channels: str) -> str:
        return await self.request(
            "SETUP",
            f"trackID={track}",
            f"Transport: RTP/AVP/TCP;unicast;interleaved={channels}\r\n",
        )


class TestRtspBackchannel(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        rtsp = _load_submodule("rtsp_server")
        self.describe_requests: list[bool] = []
        self.received: list[bytes] = []

        async def on_describe(backchannel: bool) -> str:
            self.describe_requests.append(backchannel)
            return "v=0\r\n"

        async def on_play(sess) -> None:
            return None

        async def on_teardown(sess) -> None:
            return None

        self.server = rtsp.RtspServer(
            host="127.0.0.1",
            on_describe=on_describe,
            on_play=on_play,
            on_teardown=on_teardown,
            on_backchannel_rtp=lambda sess, packet: self.received.append(packet),
        )
        await self.server.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", self.server.port)
        self.writer = writer
        self.client = _RtspClient(reader, writer, self.server.url)

    async def asyncTearDown(self) -> None:
        self.writer.close()
        await self.server.stop()

    async def test_negotiated_backchannel_rtp_is_delivered(self) -> None:
        await self.client.request("DESCRIBE", headers=_REQUIRE)
        await self.client.setup(0, "0-1")
        await self.client.setup(1, "2-3")
        response = await self.client.setup(2, "4-5")
        self.assertIn("interleaved=4-5", response)
        await self.client.request("PLAY")

        voice = _rtp(b"\x55" * 160)
        await self.client.send(
            _frame(5, b"rtcp-report")
            + _frame(0, b"not-talkback")
            + _frame(4, voice)
        )
        # The reply proves every frame before it was consumed as a frame.
        self.assertIn("200 OK", await self.client.request("GET_PARAMETER"))

        self.assertEqual(self.describe_requests, [True])
        self.assertEqual(self.received, [voice])

    async def test_client_that_did_not_require_backchannel_cannot_talk(self) -> None:
        await self.client.request("DESCRIBE")
        await self.client.setup(0, "0-1")
        await self.client.setup(2, "4-5")
        await self.client.request("PLAY")

        await self.client.send(_frame(4, _rtp(b"\x55" * 160)))
        self.assertIn("200 OK", await self.client.request("GET_PARAMETER"))

        self.assertEqual(self.describe_requests, [False])
        self.assertEqual(self.received, [])


class TestPcmaTalkFeed(unittest.TestCase):
    def setUp(self) -> None:
        _load_submodule("intercom_dialer")
        self.mp = _load_submodule("media_pipeline")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(self.sock.close)
        self.sender = self.mp._PCMATalkSender(self.sock, ("127.0.0.1", 9))

    def test_pcma_is_reframed_to_outgoing_packet_size(self) -> None:
        self.sender.start_talk()
        self.assertEqual(self.sender.feed_pcma(b"\x01" * 80), 0)
        self.assertEqual(self.sender.feed_pcma(b"\x02" * 240), 2)
        self.assertEqual(
            list(self.sender._queued_pcma),
            [b"\x01" * 80 + b"\x02" * 80, b"\x02" * 160],
        )

    def test_pcma_is_dropped_while_not_talking(self) -> None:
        self.assertEqual(self.sender.feed_pcma(b"\x01" * 160), 0)
        self.assertEqual(self.sender.queue_frames, 0)

    def test_oldest_frames_are_dropped_when_the_queue_is_full(self) -> None:
        self.sender.start_talk()
        limit = self.sender.max_queue_frames
        for index in range(limit + 2):
            self.sender.feed_pcma(bytes([index]) * 160)
        self.assertEqual(self.sender.queue_frames, limit)
        self.assertEqual(self.sender._queued_pcma[0], bytes([2]) * 160)

    def test_session_queues_only_pcma_rtp_payloads(self) -> None:
        session = self.mp.StreamSession.__new__(self.mp.StreamSession)
        session._talk_sender = self.sender
        self.sender._active = True
        self.sender.start_talk()

        self.assertEqual(session.feed_talkback_pcma_rtp(_rtp(b"\x05" * 160)), 1)
        self.assertEqual(
            session.feed_talkback_pcma_rtp(_rtp(b"\x06" * 160, payload_type=111)),
            0,
        )
        self.assertEqual(session.feed_talkback_pcma_rtp(b"\x80\x08"), 0)
        self.assertEqual(list(self.sender._queued_pcma), [b"\x05" * 160])


class _FakeStreamSession:
    def __init__(self) -> None:
        self.active = True
        self.previewing = False
        self.talkback_ready = True
        self.talkback_talking = False
        self.fed: list[bytes] = []

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

    def feed_talkback_pcm16le(self, pcm: bytes) -> dict:
        return {}


class TestBackchannelTalkOwnership(unittest.TestCase):
    def setUp(self) -> None:
        _load_submodule("intercom_dialer")
        _load_submodule("media_pipeline")
        camera = _load_submodule("camera")
        self.coordinator = camera.StationStreamCoordinator.__new__(
            camera.StationStreamCoordinator
        )
        self.session = _FakeStreamSession()
        self.coordinator.session = self.session
        self.coordinator.door = types.SimpleNamespace(station_id="1", address="1")
        self.coordinator._talkback_owner = ""
        self.coordinator._active_file_playbacks = 0
        self.coordinator._state_callbacks = []
        self.coordinator._rtsp_play_sessions = []
        self.coordinator._schedule_close = lambda: None
        self.rtsp_session = types.SimpleNamespace(session_id="00000001")

    def _feed(self, packet: bytes = b"voice") -> None:
        self.coordinator.feed_backchannel_rtp(self.rtsp_session, packet)

    def test_backchannel_starts_talking_and_forwards(self) -> None:
        self._feed(b"one")
        self._feed(b"two")
        self.assertTrue(self.session.talkback_talking)
        self.assertEqual(self.session.fed, [b"one", b"two"])

    def test_talk_service_session_takes_over_until_it_stops(self) -> None:
        self._feed(b"before")
        self.coordinator.start_talkback("scrypted-1")
        self._feed(b"during")
        self.coordinator.stop_talkback("scrypted-1")
        self._feed(b"after")
        self.assertEqual(self.session.fed, [b"before", b"after"])
        self.assertTrue(self.session.talkback_talking)

    def test_backchannel_resumes_after_a_tone_stopped_the_talk(self) -> None:
        self._feed(b"before")
        self.session.talkback_talking = False
        self._feed(b"after")
        self.assertTrue(self.session.talkback_talking)
        self.assertEqual(self.session.fed, [b"before", b"after"])

    def test_audio_file_playback_is_not_interrupted(self) -> None:
        self.coordinator._active_file_playbacks = 1
        self._feed()
        self.assertEqual(self.session.fed, [])
        self.assertEqual(self.coordinator.talkback_owner, "")

    def test_packets_before_the_call_is_up_are_dropped(self) -> None:
        self.session.talkback_ready = False
        self._feed()
        self.assertEqual(self.session.fed, [])

    def test_closing_the_rtsp_session_releases_the_talk(self) -> None:
        self._feed()
        self.coordinator.detach_rtsp_session(self.rtsp_session)
        self.assertFalse(self.session.talkback_talking)
        self.assertEqual(self.coordinator.talkback_owner, "")

    def test_closing_the_rtsp_session_leaves_another_talker_alone(self) -> None:
        self.coordinator.start_talkback("scrypted-1")
        self.coordinator.detach_rtsp_session(self.rtsp_session)
        self.assertTrue(self.session.talkback_talking)
        self.assertEqual(self.coordinator.talkback_owner, "scrypted-1")


if __name__ == "__main__":
    unittest.main()
