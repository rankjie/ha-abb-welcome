"""Standalone tests for profile-driven runtime behavior and device metadata."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


def _load(package: str, module: str):
    full_name = f"{package}.{module}"
    spec = importlib.util.spec_from_file_location(
        full_name, _PKG_DIR / f"{module}.py"
    )
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


package = types.ModuleType("abb_runtime_test")
package.__path__ = [str(_PKG_DIR)]
sys.modules["abb_runtime_test"] = package
const = _load("abb_runtime_test", "const")


def test_legacy_entries_default_to_web_admin() -> None:
    capabilities = const.gateway_capabilities({})
    assert const.gateway_profile({}) == const.GATEWAY_PROFILE_WEB_ADMIN
    assert capabilities.probe_port == 443
    assert capabilities.admin_available is True
    assert capabilities.topology_refresh is True
    assert capabilities.model == "IP Gateway (MRANGE)"


def test_app_managed_capabilities_and_refresh_policy() -> None:
    data = {const.CONF_GATEWAY_PROFILE: const.GATEWAY_PROFILE_APP_MANAGED}
    capabilities = const.gateway_capabilities(data)
    assert capabilities.probe_port == 5061
    assert capabilities.approval_method == "automatic_acl"
    assert capabilities.admin_available is False
    assert capabilities.topology_refresh is False
    assert "M2240x / ASI22" in capabilities.model
    assert capabilities.default_unlock_strategy == const.UNLOCK_STRATEGY_STANDARD
    assert "re-pair" in const.topology_refresh_error(data)
    assert const.topology_refresh_error({}) is None
    assert const.topology_refresh_action({}) == (
        const.TOPOLOGY_REFRESH_ACTION_REFRESH
    )
    assert const.topology_refresh_action(data) == (
        const.TOPOLOGY_REFRESH_ACTION_SKIP
    )
    assert const.topology_refresh_action(data, explicitly_targeted=True) == (
        const.TOPOLOGY_REFRESH_ACTION_ERROR
    )


def test_device_info_uses_app_managed_model() -> None:
    registry = types.ModuleType("homeassistant.helpers.device_registry")
    registry.DeviceInfo = lambda **kwargs: kwargs
    sys.modules.setdefault("homeassistant", types.ModuleType("homeassistant"))
    helpers = sys.modules.setdefault(
        "homeassistant.helpers", types.ModuleType("homeassistant.helpers")
    )
    helpers.device_registry = registry
    sys.modules["homeassistant.helpers.device_registry"] = registry
    device = _load("abb_runtime_test", "device")
    info = device.gateway_device_info(
        {
            const.CONF_GATEWAY_PROFILE: const.GATEWAY_PROFILE_APP_MANAGED,
            "gateway_uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        }
    )
    assert info["model"] == "Wi-Fi Indoor Station (M2240x / ASI22)"
