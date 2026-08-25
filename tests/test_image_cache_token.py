"""Screenshot URL cache invalidation tests."""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import sys
import types
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


class _ImageEntity:
    def __init__(self, hass) -> None:
        self.hass = hass
        self.access_tokens: list[str] = []
        self.async_update_token()

    @property
    def entity_picture(self) -> str:
        return f"/api/image_proxy/image.test?token={self.access_tokens[-1]}"

    def async_update_token(self) -> None:
        self.access_tokens.append(f"token-{len(self.access_tokens) + 1}")


def _install_stubs() -> None:
    homeassistant = types.ModuleType("homeassistant")
    components = types.ModuleType("homeassistant.components")
    image_component = types.ModuleType("homeassistant.components.image")
    image_component.ImageEntity = _ImageEntity
    config_entries = types.ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = type("ConfigEntry", (), {})
    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = type("HomeAssistant", (), {})
    core.callback = lambda function: function
    helpers = types.ModuleType("homeassistant.helpers")
    entity_platform = types.ModuleType("homeassistant.helpers.entity_platform")
    entity_platform.AddEntitiesCallback = object

    sys.modules.update(
        {
            "homeassistant": homeassistant,
            "homeassistant.components": components,
            "homeassistant.components.image": image_component,
            "homeassistant.config_entries": config_entries,
            "homeassistant.core": core,
            "homeassistant.helpers": helpers,
            "homeassistant.helpers.entity_platform": entity_platform,
        }
    )


def _load_image_module():
    _install_stubs()
    package = types.ModuleType("abb_image_cache_test")
    package.__path__ = [str(_PKG_DIR)]
    sys.modules[package.__name__] = package

    const = types.ModuleType(f"{package.__name__}.const")
    const.DOMAIN = "abb_welcome"
    coordinator = types.ModuleType(f"{package.__name__}.coordinator")
    coordinator.ABBWelcomeCoordinator = object
    device = types.ModuleType(f"{package.__name__}.device")
    device.gateway_device_info = lambda _data: {}
    redaction = types.ModuleType(f"{package.__name__}.redaction")
    redaction.get_redacting_logger = logging.getLogger
    sys.modules.update(
        {
            const.__name__: const,
            coordinator.__name__: coordinator,
            device.__name__: device,
            redaction.__name__: redaction,
        }
    )

    name = f"{package.__name__}.image"
    spec = importlib.util.spec_from_file_location(name, _PKG_DIR / "image.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


image = _load_image_module()


class _Coordinator:
    def __init__(self) -> None:
        self.data = types.SimpleNamespace(
            latest_screenshot=b"first",
            latest_screenshot_event_id="event-1",
            events=[
                types.SimpleNamespace(
                    event_id="event-1",
                    timestamp="2026-08-25T12:00:00Z",
                )
            ],
        )


def test_new_screenshot_changes_entity_picture_url_immediately() -> None:
    coordinator = _Coordinator()
    entity = image.ABBWelcomeScreenshotImage(object(), coordinator, "gateway", {})
    initial_url = entity.entity_picture

    entity._sync_from_coordinator()
    first_url = entity.entity_picture

    coordinator.data.latest_screenshot = b"second"
    coordinator.data.latest_screenshot_event_id = "event-2"
    coordinator.data.events.insert(
        0,
        types.SimpleNamespace(
            event_id="event-2",
            timestamp="2026-08-25T12:01:00Z",
        ),
    )
    entity._sync_from_coordinator()
    second_url = entity.entity_picture

    assert first_url != initial_url
    assert second_url != first_url
    assert asyncio.run(entity.async_image()) == b"second"


def test_same_screenshot_does_not_rotate_token_again() -> None:
    coordinator = _Coordinator()
    entity = image.ABBWelcomeScreenshotImage(object(), coordinator, "gateway", {})

    entity._sync_from_coordinator()
    token_count = len(entity.access_tokens)
    entity._sync_from_coordinator()

    assert len(entity.access_tokens) == token_count
