"""Card-owned streaming lease contracts, isolated from Home Assistant imports."""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import sys
import types
from pathlib import Path

import pytest

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


class _Hass:
    def __init__(self) -> None:
        self.data: dict = {}
        self.signals: list[str] = []

    def async_create_background_task(self, coro, *, name: str):
        return asyncio.create_task(coro, name=name)


@pytest.fixture
def streaming_state(monkeypatch):
    """Load the real state module with per-test HA stubs and no module leaks."""
    homeassistant = types.ModuleType("homeassistant")
    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = object
    core.callback = lambda function: function
    helpers = types.ModuleType("homeassistant.helpers")
    dispatcher = types.ModuleType("homeassistant.helpers.dispatcher")
    dispatcher.async_dispatcher_send = lambda hass, signal: hass.signals.append(signal)
    homeassistant.core = core
    homeassistant.helpers = helpers
    helpers.dispatcher = dispatcher
    monkeypatch.setitem(sys.modules, "homeassistant", homeassistant)
    monkeypatch.setitem(sys.modules, "homeassistant.core", core)
    monkeypatch.setitem(sys.modules, "homeassistant.helpers", helpers)
    monkeypatch.setitem(sys.modules, "homeassistant.helpers.dispatcher", dispatcher)

    package_name = "abb_card_streaming_leases_test"
    package = types.ModuleType(package_name)
    package.__path__ = [str(_PACKAGE_ROOT)]
    const = types.ModuleType(f"{package_name}.const")
    const.DOMAIN = "abb_welcome"
    const.DEFAULT_ALLOW_PICKUP = True
    const.DEFAULT_CAMERA_STILL_IMAGE = True
    const.DEFAULT_PREVIEW_BEFORE_ANSWER = False
    redaction = types.ModuleType(f"{package_name}.redaction")
    redaction.get_redacting_logger = logging.getLogger
    monkeypatch.setitem(sys.modules, package_name, package)
    monkeypatch.setitem(sys.modules, const.__name__, const)
    monkeypatch.setitem(sys.modules, redaction.__name__, redaction)

    name = f"{package_name}.streaming_state"
    spec = importlib.util.spec_from_file_location(
        name, _PACKAGE_ROOT / "streaming_state.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def test_card_owner_requires_entry_and_station(streaming_state) -> None:
    async def scenario() -> None:
        hass = _Hass()
        with pytest.raises(ValueError):
            streaming_state.arm(
                hass,
                "",
                reason=streaming_state.ARM_REASON_MANUAL,
                duration=1,
                station_id="door",
                owner_token="card-a",
            )
        with pytest.raises(ValueError):
            streaming_state.arm(
                hass,
                "entry-a",
                reason=streaming_state.ARM_REASON_MANUAL,
                duration=1,
                station_id="",
                owner_token="card-a",
            )
        assert streaming_state.release_manual_arm(
            hass, "entry-a", station_id="door", owner_token=""
        ) is False
        assert hass.data == {}

    asyncio.run(scenario())


def test_two_card_leases_release_independently(streaming_state) -> None:
    async def scenario() -> None:
        hass = _Hass()
        for token in ("card-a", "card-b"):
            streaming_state.arm(
                hass,
                "entry-a",
                reason=streaming_state.ARM_REASON_MANUAL,
                duration=1,
                station_id="door",
                owner_token=token,
            )
        state = streaming_state.get_state(hass, "entry-a")
        assert state.armed is True
        assert state.reason == streaming_state.ARM_REASON_MANUAL
        assert state.target_station_id == "door"
        assert streaming_state.release_manual_arm(
            hass, "entry-a", station_id="door", owner_token="card-a"
        ) is True
        assert streaming_state.is_stream_allowed(hass, "entry-a", "door") is True
        assert streaming_state.release_manual_arm(
            hass, "entry-a", station_id="door", owner_token="card-b"
        ) is True
        assert streaming_state.is_armed(hass, "entry-a") is False
        assert streaming_state.release_manual_arm(
            hass, "entry-a", station_id="door", owner_token="card-b"
        ) is False

    asyncio.run(scenario())


def test_card_release_cannot_disarm_switch_or_ring_arm(streaming_state) -> None:
    async def scenario() -> None:
        hass = _Hass()
        # A legacy switch/manual arm has no owner and must survive card traffic.
        streaming_state.arm(
            hass,
            "entry-a",
            reason=streaming_state.ARM_REASON_MANUAL,
            duration=1,
            station_id="door",
        )
        streaming_state.arm(
            hass,
            "entry-a",
            reason=streaming_state.ARM_REASON_MANUAL,
            duration=1,
            station_id="door",
            owner_token="card-a",
        )
        assert streaming_state.release_manual_arm(
            hass, "entry-a", station_id="door", owner_token="card-a"
        ) is False
        state = streaming_state.get_state(hass, "entry-a")
        assert (state.armed, state.reason, state.target_station_id) == (
            True,
            streaming_state.ARM_REASON_MANUAL,
            "door",
        )

        # A ring supersedes old card owners.  A new card during a ring is only
        # a consumer, never a new owner that can release the ring arm.
        streaming_state.arm(
            hass,
            "entry-a",
            reason=streaming_state.ARM_REASON_RING,
            duration=1,
            station_id="door",
        )
        assert streaming_state.release_manual_arm(
            hass, "entry-a", station_id="door", owner_token="card-a"
        ) is False
        streaming_state.arm(
            hass,
            "entry-a",
            reason=streaming_state.ARM_REASON_MANUAL,
            duration=1,
            station_id="door",
            owner_token="card-b",
        )
        assert streaming_state.release_manual_arm(
            hass, "entry-a", station_id="door", owner_token="card-b"
        ) is False
        state = streaming_state.get_state(hass, "entry-a")
        assert (state.armed, state.reason, state.target_station_id) == (
            True,
            streaming_state.ARM_REASON_RING,
            "door",
        )

    asyncio.run(scenario())


def test_card_cannot_retarget_an_active_station(streaming_state) -> None:
    async def scenario() -> None:
        hass = _Hass()
        streaming_state.arm(
            hass,
            "entry-a",
            reason=streaming_state.ARM_REASON_MANUAL,
            duration=1,
            station_id="front",
            owner_token="card-front",
        )
        state = streaming_state.get_state(hass, "entry-a")
        with pytest.raises(ValueError):
            streaming_state.arm(
                hass,
                "entry-a",
                reason=streaming_state.ARM_REASON_MANUAL,
                duration=1,
                station_id="back",
                owner_token="card-back",
            )
        assert (state.armed, state.reason, state.target_station_id) == (
            True,
            streaming_state.ARM_REASON_MANUAL,
            "front",
        )
        assert streaming_state.release_manual_arm(
            hass, "entry-a", station_id="back", owner_token="card-back"
        ) is False
        assert streaming_state.release_manual_arm(
            hass, "entry-a", station_id="front", owner_token="card-front"
        ) is True
        assert streaming_state.is_armed(hass, "entry-a") is False

    asyncio.run(scenario())


def test_card_leases_expire_independently_without_refreshing_older_owners(
    streaming_state,
) -> None:
    async def scenario() -> None:
        hass = _Hass()
        streaming_state.arm(
            hass,
            "entry-a",
            reason=streaming_state.ARM_REASON_MANUAL,
            duration=0.03,
            station_id="door",
            owner_token="card-a",
        )
        await asyncio.sleep(0.015)
        streaming_state.arm(
            hass,
            "entry-a",
            reason=streaming_state.ARM_REASON_MANUAL,
            duration=0.07,
            station_id="door",
            owner_token="card-b",
        )
        await asyncio.sleep(0.03)
        # card-a has expired, but card-b's independent lease remains live.
        assert streaming_state.is_stream_allowed(hass, "entry-a", "door") is True
        assert streaming_state.release_manual_arm(
            hass, "entry-a", station_id="door", owner_token="card-a"
        ) is False
        await asyncio.sleep(0.05)
        assert streaming_state.is_armed(hass, "entry-a") is False

    asyncio.run(scenario())


def test_renew_extends_one_lease_and_never_revives_an_expired_owner(
    streaming_state, monkeypatch
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(
        streaming_state, "time", types.SimpleNamespace(monotonic=lambda: clock[0])
    )

    async def scenario() -> None:
        hass = _Hass()

        def arm(token, *, renew=False):
            streaming_state.arm(
                hass,
                "entry-a",
                reason=streaming_state.ARM_REASON_MANUAL,
                duration=180,
                station_id="door",
                owner_token=token,
                renew=renew,
            )

        arm("a")
        arm("b")
        clock[0] += 120
        arm("a", renew=True)
        state = streaming_state.get_state(hass, "entry-a")
        assert state.owner_leases == {"a": 1300, "b": 1180}
        clock[0] += 61
        with pytest.raises(ValueError, match="lease expired"):
            arm("b", renew=True)
        assert state.until_monotonic == 1300
        assert state.owner_leases["b"] == 1180
        assert streaming_state.release_manual_arm(
            hass, "entry-a", station_id="door", owner_token="a"
        )
        with pytest.raises(ValueError, match="lease expired"):
            arm("a", renew=True)
        streaming_state.disarm(hass, "entry-a")
        with pytest.raises(ValueError, match="lease expired"):
            arm("a", renew=True)
        assert not state.armed

    asyncio.run(scenario())


def test_renew_of_borrowed_ring_does_not_extend_it(streaming_state, monkeypatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(
        streaming_state, "time", types.SimpleNamespace(monotonic=lambda: clock[0])
    )

    async def scenario() -> None:
        hass = _Hass()
        streaming_state.arm(
            hass, "entry-a", reason=streaming_state.ARM_REASON_RING,
            duration=30, station_id="door",
        )
        state = streaming_state.get_state(hass, "entry-a")
        task = state.auto_disarm_task
        kwargs = {
            "reason": streaming_state.ARM_REASON_MANUAL,
            "duration": 180, "station_id": "door", "owner_token": "a", "renew": True,
        }
        streaming_state.arm(hass, "entry-a", **kwargs)
        assert state.auto_disarm_task is task
        assert state.until_monotonic == 1030
        assert not state.owner_leases
        clock[0] += 30
        with pytest.raises(ValueError, match="lease expired"):
            streaming_state.arm(hass, "entry-a", **kwargs)
        streaming_state.disarm(hass, "entry-a")

    asyncio.run(scenario())
