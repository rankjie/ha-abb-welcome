"""The camera still image: a live frame of a ring, else the last screenshot.

Live players show the still as a poster while the call is being set up, so a
user who does not want an old screenshot there can turn it off in the options.
While the station rings, a live frame shows who is ringing now.
"""

from __future__ import annotations

import types
import unittest
from unittest import mock

from test_talk_audio_file import _load_submodule

_ENTRY_ID = "entry-1"
_STATION_ID = "100000001"


class TestCameraStillImage(unittest.IsolatedAsyncioTestCase):
    def _camera(
        self,
        entry_options: dict,
        *,
        ringing: bool = False,
        previewing: bool = False,
        preview_before_answer: bool = True,
        frame=None,
        camera_index=None,
    ):
        _load_submodule("intercom_dialer")
        _load_submodule("media_pipeline")
        camera_mod = _load_submodule("camera")
        test = self
        self.ringing = ringing
        patcher = mock.patch.multiple(
            camera_mod,
            is_stream_allowed=lambda *_a: test.ringing or previewing,
            is_preview_before_answer=lambda *_a: preview_before_answer,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.frame_requests = []

        class _Resp:
            status = 200 if frame is not None else 500

            async def read(self):
                return frame

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc):
                return False

        class _Session:
            def get(self, url, **kwargs):
                test.frame_requests.append((url, kwargs["params"]))
                return _Resp()

        go2rtc = types.SimpleNamespace(url="http://go2rtc/", session=_Session())
        screenshot = types.SimpleNamespace(event_id="old", image_data=b"jpeg-bytes")
        self.screenshots = {_STATION_ID: screenshot}
        coordinator = types.SimpleNamespace(
            data=types.SimpleNamespace(latest_screenshots_by_station=self.screenshots)
        )
        cam = camera_mod.ABBWelcomeCamera.__new__(camera_mod.ABBWelcomeCamera)
        cam.hass = types.SimpleNamespace(
            data={
                camera_mod.DOMAIN: {
                    _ENTRY_ID: {
                        "coordinator": coordinator,
                        **entry_options,
                    }
                },
                "go2rtc": go2rtc,
            }
        )
        cam._entry_id = _ENTRY_ID
        cam._door = types.SimpleNamespace(station_id=_STATION_ID, name="Klatka")
        cam._stream_name = "abb_klatka"
        cam._camera_index = camera_index

        class _StreamCoordinator:
            has_pending_call = property(lambda _self: test.ringing)

        cam._coordinator = _StreamCoordinator()
        cam._coordinator.previewing = previewing
        return cam

    async def test_live_frame_while_the_ring_is_previewed(self) -> None:
        # A previewed ring is no longer a pending INVITE but still rings.
        cam = self._camera({}, previewing=True, frame=b"live-frame")
        self.assertEqual(await cam.async_camera_image(), b"live-frame")

    async def test_live_frame_while_the_station_rings(self) -> None:
        cam = self._camera({}, ringing=True, frame=b"live-frame")
        self.assertEqual(await cam.async_camera_image(), b"live-frame")
        self.assertEqual(
            self.frame_requests,
            [("http://go2rtc/api/frame.jpeg", {"src": "abb_klatka"})],
        )

    async def test_no_frame_when_opening_the_stream_would_answer(self) -> None:
        # Without preview-before-answer, opening the stream picks up the ring.
        cam = self._camera(
            {}, ringing=True, preview_before_answer=False, frame=b"live-frame"
        )
        self.assertEqual(await cam.async_camera_image(), b"jpeg-bytes")
        self.assertEqual(self.frame_requests, [])

    async def test_no_old_screenshot_when_the_live_frame_fails(self) -> None:
        cam = self._camera({}, ringing=True, frame=None)
        self.assertIsNone(await cam.async_camera_image())

    async def test_ring_frame_stays_until_the_ring_screenshot_arrives(self) -> None:
        cam = self._camera({}, ringing=True, frame=b"live-frame")
        await cam.async_camera_image()
        self.ringing = False
        # The ring is over, the portal still has only the earlier visitor.
        self.assertEqual(await cam.async_camera_image(), b"live-frame")
        self.screenshots[_STATION_ID] = types.SimpleNamespace(
            event_id="new", image_data=b"ring-screenshot"
        )
        self.assertEqual(await cam.async_camera_image(), b"ring-screenshot")
        self.assertEqual(len(self.frame_requests), 1)

    async def test_ring_frame_stays_past_a_screenshot_taken_during_the_ring(
        self,
    ) -> None:
        # A screenshot that arrives while the station still rings is older than
        # the next live frame, so the live frame stays the still after the ring.
        cam = self._camera({}, ringing=True, frame=b"live-frame")
        await cam.async_camera_image()
        self.screenshots[_STATION_ID] = types.SimpleNamespace(
            event_id="during", image_data=b"ring-screenshot"
        )
        await cam.async_camera_image()
        self.ringing = False
        self.assertEqual(await cam.async_camera_image(), b"live-frame")

    async def test_empty_live_frame_is_no_frame(self) -> None:
        # go2rtc answers 200 with no body when it cannot open the source.
        cam = self._camera({}, ringing=True, frame=b"")
        self.assertIsNone(await cam.async_camera_image())
        self.ringing = False
        self.assertEqual(await cam.async_camera_image(), b"jpeg-bytes")

    async def test_sub_camera_takes_no_frame_on_a_pending_ring(self) -> None:
        # Only the default camera may take the INVITE; a sub-camera would dial.
        cam = self._camera({}, ringing=True, frame=b"live-frame", camera_index=2)
        self.assertEqual(await cam.async_camera_image(), b"jpeg-bytes")
        self.assertEqual(self.frame_requests, [])

    async def test_failed_live_frame_keeps_no_ring_frame(self) -> None:
        cam = self._camera({}, ringing=True, frame=None)
        await cam.async_camera_image()
        self.ringing = False
        self.assertEqual(await cam.async_camera_image(), b"jpeg-bytes")

    async def test_no_stream_opened_when_not_ringing(self) -> None:
        self.assertEqual(await self._camera({}).async_camera_image(), b"jpeg-bytes")
        self.assertEqual(self.frame_requests, [])

    async def test_last_station_screenshot_is_the_still_by_default(self) -> None:
        self.assertEqual(await self._camera({}).async_camera_image(), b"jpeg-bytes")

    async def test_live_frame_during_a_ring_even_with_the_option_off(self) -> None:
        # The option hides old screenshots; a live frame of the ring is current.
        cam = self._camera(
            {"camera_still_image": False}, ringing=True, frame=b"live-frame"
        )
        self.assertEqual(await cam.async_camera_image(), b"live-frame")

    async def test_no_still_when_the_option_is_off(self) -> None:
        cam = self._camera({"camera_still_image": False})
        self.assertIsNone(await cam.async_camera_image())


if __name__ == "__main__":
    unittest.main()
