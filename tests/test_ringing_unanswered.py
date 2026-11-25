"""Which rings the door button treats as ringing and unanswered.

A press during such a ring unlocks with a plain MESSAGE, so a ring must count
only while the gateway is sure to end it with a CANCEL that HA receives.
"""

from __future__ import annotations

import asyncio
import time
import unittest
from unittest import mock

from test_call_preview import _CALL_ID, _SDP
from test_sip_listener_routing import _request, _Writer, sip_listener

_STATION = "100000002"
_OTHER_STATION = "100000001"
_TOO_OLD = sip_listener._RING_WINDOW_SECONDS + 1


def _ring(method: str = "INVITE", station: str = _STATION):
    frame = _request(method)
    frame.headers = [
        ("From", f"<sip:{station}@example.invalid>;tag=remote")
        if name == "From"
        else (name, value)
        for name, value in frame.headers
    ]
    return frame


class TestStationRingingUnanswered(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.listener = sip_listener.SipListener(
            "gateway.invalid", "ha", "secret", "example.invalid"
        )
        self.writer = _Writer()
        self.writer.is_closing = lambda: False
        self.listener._writer = self.writer
        invite = _ring()
        invite.body = _SDP.encode()
        invite._received_at = time.time()
        self.listener._open_invites[_CALL_ID] = invite

    async def _preview(self):
        return await self.listener.accept_pending_call(
            station_id=_STATION,
            media_ip="192.0.2.2",
            audio_port=40000,
            video_port=40002,
            preview=True,
        )

    async def test_a_pending_ring_counts_only_for_its_station(self) -> None:
        self.assertTrue(self.listener.is_station_ringing_unanswered(_STATION))
        self.assertFalse(self.listener.is_station_ringing_unanswered(_OTHER_STATION))
        self.assertFalse(self.listener.is_station_ringing_unanswered(""))

    async def test_a_ring_that_ha_previews_still_counts(self) -> None:
        await self._preview()
        self.assertFalse(self.listener.has_pending_call_for_station(_STATION))
        self.assertTrue(self.listener.is_station_ringing_unanswered(_STATION))
        self.assertFalse(self.listener.is_station_ringing_unanswered(_OTHER_STATION))

    async def test_a_ring_that_ha_answered_does_not_count(self) -> None:
        await self._preview()
        task = asyncio.ensure_future(self.listener.answer_previewed_call(_CALL_ID))
        await asyncio.sleep(0)
        self.listener._accepted_dialogs[_CALL_ID].ack_event.set()
        self.assertTrue(await task)
        self.assertFalse(self.listener.is_station_ringing_unanswered(_STATION))

    async def test_a_cancelled_preview_does_not_count(self) -> None:
        await self._preview()
        await self.listener._dispatch(_ring("CANCEL"), self.writer, "192.0.2.2", 5061)
        self.assertFalse(self.listener.is_station_ringing_unanswered(_STATION))

    async def test_a_cancelled_pending_ring_does_not_count(self) -> None:
        await self.listener._dispatch(_ring("CANCEL"), self.writer, "192.0.2.2", 5061)
        self.assertFalse(self.listener.is_station_ringing_unanswered(_STATION))

    async def test_a_ring_that_ha_released_does_not_count(self) -> None:
        # HA gets no CANCEL after its 480, so it cannot tell when this ring ends.
        await self._preview()
        await self.listener.hangup_accepted_call(_CALL_ID)
        self.assertFalse(self.listener.is_station_ringing_unanswered(_STATION))

    async def test_a_ring_older_than_the_ring_window_does_not_count(self) -> None:
        self.listener._open_invites[_CALL_ID]._received_at = time.time() - _TOO_OLD
        self.assertFalse(self.listener.is_station_ringing_unanswered(_STATION))

    async def test_a_preview_older_than_the_ring_window_does_not_count(self) -> None:
        await self._preview()
        self.listener._accepted_dialogs[_CALL_ID].invite._received_at = time.time() - _TOO_OLD
        self.assertFalse(self.listener.is_station_ringing_unanswered(_STATION))

    async def test_a_lost_connection_forgets_its_rings(self) -> None:
        writer = mock.Mock()
        writer.get_extra_info.return_value = ("192.0.2.2", 5061)
        writer.wait_closed = mock.AsyncMock()
        with mock.patch.object(
            sip_listener.asyncio,
            "open_connection",
            mock.AsyncMock(return_value=(mock.Mock(), writer)),
        ), mock.patch.object(
            self.listener,
            "_do_register",
            mock.AsyncMock(side_effect=ConnectionResetError),
        ), self.assertRaises(ConnectionResetError):
            await self.listener._connect_register_and_read()
        self.assertFalse(self.listener.is_station_ringing_unanswered(_STATION))
