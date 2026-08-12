"""Safe unlock routing tests for app-managed and legacy gateways."""

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


package = types.ModuleType("abb_unlock_test")
package.__path__ = [str(_PKG_DIR)]
sys.modules["abb_unlock_test"] = package
const = _load("abb_unlock_test", "const")
_load("abb_unlock_test", "redaction")
sip_client = _load("abb_unlock_test", "sip_client")

BACK = {
    "name": "Synthetic Back",
    "station_id": "station-back",
    "address": "sip:station-back@example.invalid",
    "index": 0,
}
FRONT = {
    "name": "Synthetic Front",
    "station_id": "station-front",
    "address": "sip:station-front@example.invalid",
    "index": 1,
}


def _app_data(doors: list[dict]) -> dict:
    return {
        const.CONF_GATEWAY_PROFILE: const.GATEWAY_PROFILE_APP_MANAGED,
        "doors": doors,
    }


def _client(doors: list[dict], *, strategy: str, default: str = ""):
    return sip_client.SIPClient(
        host="192.0.2.10",
        username="synthetic-user",
        password="synthetic-password",
        domain="example.invalid",
        doors=doors,
        unlock_strategy=strategy,
        default_unlock_station_id=default,
        legacy_first_door_hybrid=False,
    )


def test_explicit_hybrid_routing_is_independent_of_door_order() -> None:
    options = {
        const.CONF_UNLOCK_STRATEGY: const.UNLOCK_STRATEGY_HYBRID,
        const.CONF_DEFAULT_UNLOCK_STATION_ID: "station-front",
    }
    for doors in ([BACK, FRONT], [FRONT, BACK]):
        strategy, default = const.normalized_unlock_routing(
            _app_data(list(doors)), options
        )
        client = _client(list(doors), strategy=strategy, default=default)
        assert client._use_fast_route(client._normalize_door(FRONT, None)) is True
        assert client._use_fast_route(client._normalize_door(BACK, None)) is False


def test_missing_invalid_or_stale_app_default_is_all_standard() -> None:
    data = _app_data([BACK, FRONT])
    for selected in ("", "station-missing"):
        strategy, default = const.normalized_unlock_routing(
            data,
            {
                const.CONF_UNLOCK_STRATEGY: const.UNLOCK_STRATEGY_HYBRID,
                const.CONF_DEFAULT_UNLOCK_STATION_ID: selected,
            },
        )
        assert strategy == const.UNLOCK_STRATEGY_STANDARD
        assert default == ""
        client = _client([BACK, FRONT], strategy=strategy, default=default)
        assert client._use_fast_route(client._normalize_door(FRONT, None)) is False
        assert client._use_fast_route(client._normalize_door(BACK, None)) is False


def test_app_global_fast_is_safe_for_one_door_only() -> None:
    options = {const.CONF_UNLOCK_STRATEGY: const.UNLOCK_STRATEGY_FAST}
    assert const.normalized_unlock_routing(_app_data([FRONT]), options) == (
        const.UNLOCK_STRATEGY_FAST,
        "",
    )
    assert const.normalized_unlock_routing(_app_data([BACK, FRONT]), options) == (
        const.UNLOCK_STRATEGY_STANDARD,
        "",
    )


def test_web_admin_legacy_hybrid_still_uses_first_stored_door() -> None:
    data = {"doors": [BACK, FRONT]}
    strategy, default = const.normalized_unlock_routing(
        data, {const.CONF_UNLOCK_STRATEGY: const.UNLOCK_STRATEGY_HYBRID}
    )
    client = sip_client.SIPClient(
        host="192.0.2.10",
        username="synthetic-user",
        password="synthetic-password",
        domain="example.invalid",
        doors=[BACK, FRONT],
        unlock_strategy=strategy,
        default_unlock_station_id=default,
        legacy_first_door_hybrid=True,
    )
    assert client._use_fast_route(client._normalize_door(BACK, None)) is True
    assert client._use_fast_route(client._normalize_door(FRONT, None)) is False
