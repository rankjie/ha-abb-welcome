"""Behavior contract for gateway profiles introduced by the PR1 refactor.

The module is loaded directly so these focused unit tests do not require a
Home Assistant installation.  PR1 intentionally contains only the existing
MRANGE profile; device-specific adapters are added by later PRs.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import is_dataclass
from pathlib import Path

import pytest

_FILE = (
    Path(__file__).resolve().parent.parent
    / "custom_components"
    / "abb_welcome"
    / "gateway_profile.py"
)

_spec = importlib.util.spec_from_file_location("abb_gateway_profile", _FILE)
gateway_profile = importlib.util.module_from_spec(_spec)
# Register before exec so dataclass annotation resolution can find the module.
sys.modules["abb_gateway_profile"] = gateway_profile
_spec.loader.exec_module(gateway_profile)

MRANGE_KIND = "mrange_ip_gateway"


def test_registry_exposes_the_behavior_preserving_mrange_profile() -> None:
    profile = gateway_profile.get_gateway_profile(MRANGE_KIND)

    assert isinstance(profile, gateway_profile.GatewayProfile)
    assert is_dataclass(profile)
    assert profile.kind == MRANGE_KIND
    assert profile.name == "ABB Welcome Gateway"
    assert profile.manufacturer == "ABB / Busch-Jaeger"
    assert profile.model == "IP Gateway (MRANGE)"


def test_mrange_capabilities_are_nonempty_typed_and_immutable() -> None:
    profile = gateway_profile.get_gateway_profile(MRANGE_KIND)

    assert isinstance(profile.capabilities, frozenset)
    assert profile.capabilities
    assert all(
        isinstance(capability, gateway_profile.GatewayCapability)
        for capability in profile.capabilities
    )
    assert not hasattr(profile.capabilities, "add")


def test_supports_matches_capability_membership() -> None:
    profile = gateway_profile.get_gateway_profile(MRANGE_KIND)

    for capability in gateway_profile.GatewayCapability:
        assert profile.supports(capability) is (
            capability in profile.capabilities
        )


@pytest.mark.parametrize(
    "kind_data",
    [
        pytest.param({}, id="missing"),
        pytest.param({"gateway_kind": None}, id="none"),
        pytest.param({"gateway_kind": ""}, id="empty"),
    ],
)
def test_legacy_missing_or_empty_kind_resolves_to_mrange_without_mutation(
    kind_data: dict[str, object],
) -> None:
    data = {"gateway_ip": "192.0.2.10", **kind_data}
    before = dict(data)

    assert gateway_profile.resolve_gateway_kind(data) == MRANGE_KIND
    assert data == before


def test_explicit_known_kind_is_preserved_without_mutation() -> None:
    data = {"gateway_kind": MRANGE_KIND, "gateway_ip": "192.0.2.10"}
    before = dict(data)

    assert gateway_profile.resolve_gateway_kind(data) == MRANGE_KIND
    assert data == before


@pytest.mark.parametrize("kind", [None, "", "unknown_gateway"])
def test_direct_lookup_fails_closed_for_missing_or_unknown_kind(
    kind: str | None,
) -> None:
    with pytest.raises(ValueError):
        gateway_profile.get_gateway_profile(kind)


def test_unknown_explicit_kind_fails_closed() -> None:
    with pytest.raises(ValueError, match="unknown_gateway"):
        gateway_profile.resolve_gateway_kind({"gateway_kind": "unknown_gateway"})
