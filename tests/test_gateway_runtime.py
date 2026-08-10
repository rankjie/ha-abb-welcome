"""Focused contract tests for the gateway runtime introduced by PR1.

The production modules are loaded directly under an isolated package name so
these tests do not execute the integration package or require Home Assistant.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path
from typing import Any

_PKG_DIR = (
    Path(__file__).resolve().parent.parent
    / "custom_components"
    / "abb_welcome"
)
_PKG_NAME = "_abb_gateway_runtime_test"


def _load_module(name: str) -> types.ModuleType:
    """Load one integration module without importing ``abb_welcome.__init__``."""
    full_name = f"{_PKG_NAME}.{name}"
    module = sys.modules.get(full_name)
    if module is not None:
        return module

    spec = importlib.util.spec_from_file_location(
        full_name,
        _PKG_DIR / f"{name}.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


_package = types.ModuleType(_PKG_NAME)
_package.__path__ = [str(_PKG_DIR)]
sys.modules.setdefault(_PKG_NAME, _package)
gateway_profile = _load_module("gateway_profile")
gateway_runtime = _load_module("gateway_runtime")


def _runtime(unlock_adapter: Any, *, sip_client: Any | None = None) -> Any:
    """Build the smallest valid entry runtime for an unlock test."""
    return gateway_runtime.GatewayRuntime(
        profile=gateway_profile.get_gateway_profile(
            gateway_profile.GATEWAY_KIND_MRANGE
        ),
        coordinator=object(),
        unlock_adapter=unlock_adapter,
        sip_client=sip_client,
    )


def test_runtime_delegates_to_the_selected_async_unlock_adapter() -> None:
    class SelectedAdapter:
        def __init__(self) -> None:
            self.calls: list[tuple[Any, Any, dict[str, Any]]] = []

        async def async_unlock(
            self,
            hass: Any,
            runtime: Any,
            door: dict[str, Any],
        ) -> bool:
            self.calls.append((hass, runtime, door))
            return True

    adapter = SelectedAdapter()
    runtime = _runtime(adapter)
    hass = object()
    door = {"id": "door-1"}

    result = asyncio.run(runtime.async_unlock(hass, door))

    assert result is True
    assert adapter.calls == [(hass, runtime, door)]


def test_mrange_adapter_runs_sync_client_once_in_executor_and_returns_bool() -> None:
    class SipClient:
        def __init__(self) -> None:
            self.doors: list[dict[str, Any]] = []

        def unlock_door(self, door: dict[str, Any]) -> str:
            self.doors.append(door)
            return "confirmed"

    class Hass:
        def __init__(self) -> None:
            self.executor_calls = 0

        async def async_add_executor_job(
            self,
            target: Any,
            *args: Any,
        ) -> Any:
            self.executor_calls += 1
            return target(*args)

    client = SipClient()
    hass = Hass()
    adapter = gateway_runtime.MRangeUnlockAdapter()
    runtime = _runtime(adapter, sip_client=client)
    door = {"id": "door-2"}

    result = asyncio.run(runtime.async_unlock(hass, door))

    assert result is True
    assert isinstance(result, bool)
    assert hass.executor_calls == 1
    assert client.doors == [door]


def test_mrange_adapter_fails_closed_without_client_or_executor_call() -> None:
    class Hass:
        def __init__(self) -> None:
            self.executor_calls = 0

        async def async_add_executor_job(self, *_args: Any) -> Any:
            self.executor_calls += 1
            raise AssertionError("executor must not run without a SIP client")

    hass = Hass()
    adapter = gateway_runtime.MRangeUnlockAdapter()
    runtime = _runtime(adapter)

    result = asyncio.run(runtime.async_unlock(hass, {"id": "door-3"}))

    assert result is False
    assert isinstance(result, bool)
    assert hass.executor_calls == 0
