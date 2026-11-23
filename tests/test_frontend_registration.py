"""Lifecycle contracts for the bundled Lovelace module registration.

This module deliberately installs its minimal Home Assistant import surface per
test.  ``monkeypatch`` restores every ``sys.modules`` entry, so it does not
leak fake HA modules into the upstream test suite.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


class _StaticPathConfig:
    def __init__(self, url_path: str, path: str, cache_headers: bool) -> None:
        self.url_path = url_path
        self.path = path
        self.cache_headers = cache_headers


@pytest.fixture
def frontend(monkeypatch):
    """Load frontend.py against private HA fakes that pytest will undo."""
    homeassistant = types.ModuleType("homeassistant")
    components = types.ModuleType("homeassistant.components")
    ha_frontend = types.ModuleType("homeassistant.components.frontend")
    http = types.ModuleType("homeassistant.components.http")
    ha_frontend.add_extra_js_url = MagicMock()
    http.StaticPathConfig = _StaticPathConfig
    homeassistant.components = components
    components.frontend = ha_frontend
    components.http = http
    monkeypatch.setitem(sys.modules, "homeassistant", homeassistant)
    monkeypatch.setitem(sys.modules, "homeassistant.components", components)
    monkeypatch.setitem(sys.modules, "homeassistant.components.frontend", ha_frontend)
    monkeypatch.setitem(sys.modules, "homeassistant.components.http", http)

    name = "abb_frontend_registration_test.frontend"
    package = types.ModuleType("abb_frontend_registration_test")
    package.__path__ = [str(_PACKAGE_ROOT)]
    monkeypatch.setitem(sys.modules, "abb_frontend_registration_test", package)
    spec = importlib.util.spec_from_file_location(name, _PACKAGE_ROOT / "frontend.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


class _RecordingHass:
    def __init__(self) -> None:
        self.data: dict = {}
        self.static_calls: list[list] = []
        self.http = types.SimpleNamespace(async_register_static_paths=self._register_static)

    async def _register_static(self, configs) -> None:
        self.static_calls.append(list(configs))

    async def async_add_executor_job(self, func, *args):
        return func(*args)


def test_register_serves_content_versioned_card_url(frontend) -> None:
    hass = _RecordingHass()
    result = asyncio.run(frontend.async_register_frontend(hass, "entry-a"))
    assert result is True
    assert len(hass.static_calls) == 1
    (config,) = hass.static_calls[0]
    assert config.url_path == "/abb_welcome/frontend"
    assert config.path.endswith("custom_components/abb_welcome/frontend")
    assert config.cache_headers is True
    frontend.ha_frontend.add_extra_js_url.assert_called_once_with(
        hass,
        f"/abb_welcome/frontend/abb-welcome-intercom-card.js?v={frontend._frontend_version()}",
    )


def test_frontend_version_fingerprints_card(frontend, tmp_path) -> None:
    (tmp_path / frontend.CARD_FILENAME).write_text("card-a")
    with (
        patch.object(frontend, "_FRONTEND_DIR", tmp_path),
        patch.object(frontend, "_manifest_version", return_value="1.6.0"),
    ):
        first = frontend._frontend_version()
        (tmp_path / frontend.CARD_FILENAME).write_text("card-b")
        card_changed = frontend._frontend_version()
    assert first.startswith("1.6.0-")
    assert len(first.rsplit("-", 1)[1]) == 8
    assert first != card_changed


def test_register_is_idempotent_across_entries(frontend) -> None:
    hass = _RecordingHass()
    assert asyncio.run(frontend.async_register_frontend(hass, "entry-a")) is True
    assert asyncio.run(frontend.async_register_frontend(hass, "entry-a")) is True
    assert asyncio.run(frontend.async_register_frontend(hass, "entry-b")) is True
    assert len(hass.static_calls) == 1
    frontend.ha_frontend.add_extra_js_url.assert_called_once()


def test_concurrent_entry_setup_registers_once(frontend) -> None:
    hass = _RecordingHass()
    route_entered = asyncio.Event()
    release_route = asyncio.Event()

    async def delayed_register(configs) -> None:
        hass.static_calls.append(list(configs))
        route_entered.set()
        await release_route.wait()

    hass.http.async_register_static_paths = delayed_register

    async def register_both() -> tuple[bool, bool]:
        first = asyncio.create_task(frontend.async_register_frontend(hass, "entry-a"))
        await route_entered.wait()
        second = asyncio.create_task(frontend.async_register_frontend(hass, "entry-b"))
        release_route.set()
        return tuple(await asyncio.gather(first, second))

    assert asyncio.run(register_both()) == (True, True)
    assert len(hass.static_calls) == 1
    frontend.ha_frontend.add_extra_js_url.assert_called_once()


def test_unload_removes_module_only_after_last_entry(frontend) -> None:
    hass = _RecordingHass()
    remove_url = MagicMock()
    frontend.ha_frontend.remove_extra_js_url = remove_url
    asyncio.run(frontend.async_register_frontend(hass, "entry-a"))
    asyncio.run(frontend.async_register_frontend(hass, "entry-b"))
    registered_url = frontend.ha_frontend.add_extra_js_url.call_args.args[1]
    assert asyncio.run(frontend.async_unregister_frontend(hass, "entry-a")) is True
    remove_url.assert_not_called()
    assert asyncio.run(frontend.async_unregister_frontend(hass, "entry-b")) is True
    remove_url.assert_called_once_with(hass, registered_url)
    assert asyncio.run(frontend.async_unregister_frontend(hass, "entry-b")) is True
    remove_url.assert_called_once()


def test_unregister_failure_is_contained_and_retryable(frontend) -> None:
    hass = _RecordingHass()
    remove_url = MagicMock(side_effect=[RuntimeError("frontend busy"), None])
    frontend.ha_frontend.remove_extra_js_url = remove_url
    assert asyncio.run(frontend.async_register_frontend(hass, "entry-a")) is True
    assert asyncio.run(frontend.async_unregister_frontend(hass, "entry-a")) is False
    assert asyncio.run(frontend.async_unregister_frontend(hass, "entry-a")) is True
    assert remove_url.call_count == 2


def test_unregister_before_register_is_a_noop(frontend) -> None:
    hass = _RecordingHass()
    frontend.ha_frontend.remove_extra_js_url = MagicMock()
    assert asyncio.run(frontend.async_unregister_frontend(hass, "missing-entry")) is True
    frontend.ha_frontend.remove_extra_js_url.assert_not_called()
    assert frontend.DATA_FRONTEND not in hass.data


def test_registration_failures_are_contained_and_retryable(frontend) -> None:
    hass = _RecordingHass()
    frontend.ha_frontend.add_extra_js_url = MagicMock(
        side_effect=[RuntimeError("frontend unavailable"), None]
    )
    assert asyncio.run(frontend.async_register_frontend(hass, "entry-a")) is False
    assert asyncio.run(frontend.async_register_frontend(hass, "entry-a")) is True
    assert len(hass.static_calls) == 1
    assert frontend.ha_frontend.add_extra_js_url.call_count == 2


def test_static_route_failure_is_contained_and_retryable(frontend) -> None:
    hass = _RecordingHass()
    attempts = 0

    async def register_with_one_failure(configs) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("HTTP frontend unavailable")
        hass.static_calls.append(list(configs))

    hass.http.async_register_static_paths = register_with_one_failure
    assert asyncio.run(frontend.async_register_frontend(hass, "entry-a")) is False
    assert asyncio.run(frontend.async_register_frontend(hass, "entry-a")) is True
    assert attempts == 2
    assert len(hass.static_calls) == 1


def test_legacy_static_registration_and_inert_unload(frontend) -> None:
    class _LegacyHass(_RecordingHass):
        def __init__(self) -> None:
            super().__init__()
            self.legacy_static_calls: list[tuple[str, str, bool]] = []
            self.http = types.SimpleNamespace(
                register_static_path=lambda url, path, cache: self.legacy_static_calls.append(
                    (url, path, cache)
                )
            )

    hass = _LegacyHass()
    with patch.object(frontend, "StaticPathConfig", None):
        assert asyncio.run(frontend.async_register_frontend(hass, "entry-a")) is True
        assert asyncio.run(frontend.async_unregister_frontend(hass, "entry-a")) is True
        assert asyncio.run(frontend.async_register_frontend(hass, "entry-a")) is True
    assert len(hass.legacy_static_calls) == 1
    assert frontend.ha_frontend.add_extra_js_url.call_count == 1


def test_manifest_failure_is_contained_and_retryable(frontend) -> None:
    hass = _RecordingHass()
    version = str(json.loads((_PACKAGE_ROOT / "manifest.json").read_text())["version"])
    with patch.object(
        frontend,
        "_manifest_version",
        side_effect=[OSError("manifest unavailable"), version],
    ):
        assert asyncio.run(frontend.async_register_frontend(hass, "entry-a")) is False
        assert asyncio.run(frontend.async_register_frontend(hass, "entry-a")) is True
    frontend.ha_frontend.add_extra_js_url.assert_called_once()
