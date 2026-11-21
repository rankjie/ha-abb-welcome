"""The camera still image is the last station screenshot unless turned off.

Live players show the still as a poster while the call is being set up, so a
user who does not want an old screenshot there can turn it off in the options.
"""

from __future__ import annotations

import types
import unittest

from test_talk_audio_file import _load_submodule

_ENTRY_ID = "entry-1"
_STATION_ID = "100000001"


class TestCameraStillImage(unittest.IsolatedAsyncioTestCase):
    def _camera(self, entry_options: dict):
        _load_submodule("intercom_dialer")
        _load_submodule("media_pipeline")
        camera_mod = _load_submodule("camera")
        screenshot = types.SimpleNamespace(image_data=b"jpeg-bytes")
        coordinator = types.SimpleNamespace(
            data=types.SimpleNamespace(
                latest_screenshots_by_station={_STATION_ID: screenshot}
            )
        )
        cam = camera_mod.ABBWelcomeCamera.__new__(camera_mod.ABBWelcomeCamera)
        cam.hass = types.SimpleNamespace(
            data={
                camera_mod.DOMAIN: {
                    _ENTRY_ID: {"coordinator": coordinator, **entry_options}
                }
            }
        )
        cam._entry_id = _ENTRY_ID
        cam._door = types.SimpleNamespace(station_id=_STATION_ID)
        return cam

    async def test_last_station_screenshot_is_the_still_by_default(self) -> None:
        self.assertEqual(await self._camera({}).async_camera_image(), b"jpeg-bytes")

    async def test_no_still_when_the_option_is_off(self) -> None:
        cam = self._camera({"camera_still_image": False})
        self.assertIsNone(await cam.async_camera_image())


if __name__ == "__main__":
    unittest.main()
