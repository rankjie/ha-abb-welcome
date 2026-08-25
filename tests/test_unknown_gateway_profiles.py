"""Standalone tests for persisted gateway-profile resolution."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"
_PACKAGE = "abb_unknown_profile_test"

package = types.ModuleType(_PACKAGE)
package.__path__ = [str(_PKG_DIR)]
sys.modules[_PACKAGE] = package
spec = importlib.util.spec_from_file_location(
    f"{_PACKAGE}.const", _PKG_DIR / "const.py"
)
const = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = const
spec.loader.exec_module(const)


@pytest.mark.parametrize(
    "data",
    [{}, {const.CONF_GATEWAY_PROFILE: None}, {const.CONF_GATEWAY_PROFILE: ""}],
)
def test_legacy_entries_default_to_web_admin(data: dict[str, object]) -> None:
    assert const.gateway_profile(data) == const.GATEWAY_PROFILE_WEB_ADMIN


@pytest.mark.parametrize("profile", ["future_gateway", 42])
def test_explicit_unknown_profile_fails_closed(profile: object) -> None:
    with pytest.raises(ValueError, match="Unsupported ABB Welcome gateway profile"):
        const.gateway_profile({const.CONF_GATEWAY_PROFILE: profile})
