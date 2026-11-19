"""Tests for app-managed ACL identity and surveillance SIP targeting."""

from __future__ import annotations

import base64
import importlib.util
import sys
import types
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"
_PACKAGE = "abb_surveillance_target_test"


def _load(module: str):
    full_name = f"{_PACKAGE}.{module}"
    if full_name in sys.modules:
        return sys.modules[full_name]
    spec = importlib.util.spec_from_file_location(
        full_name, _PKG_DIR / f"{module}.py"
    )
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


package = types.ModuleType(_PACKAGE)
package.__path__ = [str(_PKG_DIR)]
sys.modules[_PACKAGE] = package
_load("const")
_load("redaction")
_load("text")
portal = _load("portal")
intercom = _load("intercom_dialer")


def _acl_payload(*, local_id: str | None) -> tuple[str, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encrypted_password = private_key.public_key().encrypt(
        b"synthetic-password", padding.PKCS1v15()
    )
    network = ["[network]", "domain=sip.example.invalid"]
    if local_id is not None:
        network.append(f"localid={local_id}")
    ini = "\n".join(
        [
            *network,
            "",
            "[outdoorstation_1]",
            "name=Synthetic Door",
            "address=sip:door@sip.example.invalid;transport=tls",
            "type=1",
        ]
    )
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return base64.b64encode(encrypted_password).decode() + "\n" + ini, private_pem


def test_acl_network_localid_is_persisted_per_door() -> None:
    payload, private_key = _acl_payload(local_id="synthetic-local-client")

    _, _, doors = portal.parse_acl_update(payload, private_key)

    assert doors == [
        {
            "name": "Synthetic Door",
            "address": "sip:door@sip.example.invalid;transport=tls",
            "station_id": "door",
            "local_id": "synthetic-local-client",
            "type": "1",
        }
    ]


@pytest.mark.parametrize(
    ("users", "unlockable"),
    [
        ("[user_1]\nuser=test-ha\nopendoor=yes", True),
        ("[user_1]\nusername=test-ha\nopendoor=no", False),
        ("[user_1]\nuser=another-client\nopendoor=yes", False),
        ("[user_1]\nuser=test-ha\nopendoor=yes\n[user_2]\nuser=test-ha\nopendoor=no", False),
        ("[DEFAULT]\nopendoor=yes\n[user_1]\nuser=test-ha", False),
    ],
)
def test_globalip_pairing_limits_unlock_to_the_paired_user(users, unlockable):
    payload, key = _acl_payload(local_id=None)
    payload = payload.replace("[network]", "[network]\nsystemtype=GlobalIP")
    _, _, doors = portal.parse_acl_update(payload + "\n" + users, key, "test-ha")
    assert len(doors) == 1
    assert (doors[0].get("can_unlock") is not False) is unlockable


def test_app_managed_target_uses_exact_acl_uri_and_display_name() -> None:
    door = intercom.Door(
        name="Synthetic Door",
        address="sip:door@sip.example.invalid;transport=tls",
        local_id='client "north"\\panel',
        exact_target=True,
    )

    request_uri, to_header = intercom._door_sip_target(door)

    assert request_uri == "sip:door@sip.example.invalid;transport=tls"
    assert to_header == (
        '"client \\"north\\"\\\\panel" '
        "<sip:door@sip.example.invalid;transport=tls>"
    )


def test_legacy_target_behavior_is_unchanged() -> None:
    plain = intercom.Door("Synthetic Door", "sip:door@sip.example.invalid")
    parameterized = intercom.Door(
        "Synthetic Door", "sip:door@sip.example.invalid;user=phone"
    )

    assert intercom._door_sip_target(plain) == (
        "sip:door@sip.example.invalid;user=phone",
        "<sip:door@sip.example.invalid;user=phone>",
    )
    assert intercom._door_sip_target(parameterized) == (
        "sip:door@sip.example.invalid;user=phone",
        "<sip:door@sip.example.invalid;user=phone>",
    )


def test_app_managed_target_without_legacy_localid_still_uses_exact_uri() -> None:
    payload, private_key = _acl_payload(local_id=None)
    _, _, doors = portal.parse_acl_update(payload, private_key)
    assert "local_id" not in doors[0]

    door = intercom.Door(
        name=doors[0]["name"],
        address=doors[0]["address"],
        local_id=doors[0].get("local_id", ""),
        exact_target=True,
    )
    assert intercom._door_sip_target(door) == (
        "sip:door@sip.example.invalid;transport=tls",
        "<sip:door@sip.example.invalid;transport=tls>",
    )


def test_display_name_strips_header_control_characters() -> None:
    door = intercom.Door(
        name="Synthetic Door",
        address="sip:door@sip.example.invalid",
        local_id="client\r\nInjected: value",
        exact_target=True,
    )

    _, to_header = intercom._door_sip_target(door)

    assert "\r" not in to_header
    assert "\n" not in to_header
    assert to_header == '"client  Injected: value" <sip:door@sip.example.invalid>'


@pytest.mark.parametrize(
    ("body", "system_type"),
    [
        ("[network]\nsystemtype=GlobalIP\ndomain=sip.example.invalid", "GlobalIP"),
        ("[network]\ndomain=sip.example.invalid", ""),
        ("[outdoorstation_1]\nname=Door", ""),
        ("not an ini section", ""),
        ("", ""),
    ],
)
def test_acl_system_type_reads_the_network_section(body, system_type) -> None:
    assert portal.acl_system_type("encrypted-password\n" + body) == system_type
