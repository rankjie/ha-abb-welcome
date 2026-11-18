"""Portal discovery, ACL polling, and ACL parsing for app-managed pairing."""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"
_PACKAGE = "abb_portal_poll_test"
package = types.ModuleType(_PACKAGE)
package.__path__ = [str(_PKG_DIR)]
sys.modules[_PACKAGE] = package


def _load(name):
    full_name = f"{_PACKAGE}.{name}"
    spec = importlib.util.spec_from_file_location(full_name, _PKG_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


_load("const")
_load("redaction")
_load("text")
portal = _load("portal")

OWN = "11111111-1111-4111-8111-111111111111"
PANEL = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
OTHER = "22222222-2222-4222-8222-222222222222"
NEWER_THAN = "2026-11-17T10:00:00+0000"
URL = "https://api.example.invalid"


class _Response:
    def __init__(self, status: int, body: object) -> None:
        self.status_code = status
        self._body = body
        self.content = json.dumps(body).encode() if body is not None else b"<html>"

    def json(self):
        if self._body is None:
            raise ValueError("not JSON")
        return self._body


class _Session:
    def __init__(self, responses) -> None:
        self._responses = iter(responses)
        self.params: list[object] = []

    def get(self, url, params, timeout):
        self.params.append(params)
        response = next(self._responses)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self) -> None:
        pass


@pytest.fixture
def session(monkeypatch):
    holder: dict[str, _Session] = {}

    def install(*responses):
        holder["session"] = _Session(responses)
        monkeypatch.setattr(
            portal, "_mtls_session", lambda *_args: (holder["session"], [])
        )
        return holder["session"]

    return install


def _events(*events):
    return _Response(200, {"events": list(events), "total_count": len(events)})


def _acl_event(payload="QUNM", **fields):
    return {"type": portal.EVENT_TYPE_ACL_UPDATE, "payload": payload, **fields}


def _poll(attempts, target=PANEL, newer_than=NEWER_THAN):
    return portal.poll_acl_update(
        URL, b"cert", b"key", OWN, attempts, 0, None, target, newer_than
    )


def test_poll_alternates_with_the_official_panel_query(session) -> None:
    fake = session(_events(), _events(), _events())

    assert _poll(3) is None

    inbox, device, inbox_again = fake.params
    assert inbox["type"] == portal.EVENT_TYPE_ACL_UPDATE
    assert "portal_client" not in inbox
    assert inbox_again == inbox
    assert device == (
        f"type={portal.EVENT_TYPE_ACL_UPDATE}&portal_client={PANEL}"
        f"&newer_than={NEWER_THAN}"
    )
    # The official app sends "+0000" unencoded; requests must keep it raw.
    prepared = requests.Request("GET", f"{URL}/event", params=device).prepare()
    assert prepared.url.endswith(f"newer_than={NEWER_THAN}")


def test_web_admin_poll_keeps_the_single_inbox_query(session) -> None:
    fake = session(_events(), _events())

    assert _poll(2, target="", newer_than="") is None

    assert [type(params) for params in fake.params] == [dict, dict]


@pytest.mark.parametrize(
    "fields",
    [
        {"destination": [OWN.upper()]},
        {"destination": OWN},
        {"destinations": [OTHER, OWN]},
    ],
    ids=["uppercase-list", "string", "plural-key"],
)
def test_poll_accepts_an_acl_addressed_to_us(session, fields) -> None:
    session(_events(_acl_event(**fields)))

    assert _poll(1) == "ACL"


def test_poll_ignores_acls_for_other_clients(session) -> None:
    session(
        _events(_acl_event(destination=[OTHER])),
        _events(_acl_event(destination=f"x{OWN}y", sender=PANEL)),
    )

    assert _poll(2) is None


def test_sender_only_acl_is_accepted_only_from_the_device_query(session) -> None:
    from_panel = _acl_event(sender=PANEL.upper())
    session(_events(from_panel), _events(from_panel))

    assert _poll(2) == "ACL"


def test_device_query_takes_its_newest_event_from_the_end(session) -> None:
    older = _acl_event(payload="T0xE", destination=[OWN])
    newer = _acl_event(payload="TkVX", destination=[OWN])
    session(_events(), _events(older, newer))

    assert _poll(2) == "NEW"


def test_inbox_query_takes_its_newest_event_first(session) -> None:
    newer = _acl_event(payload="TkVX", destination=[OWN])
    older = _acl_event(payload="T0xE", destination=[OWN])
    session(_events(newer, older))

    assert _poll(1) == "NEW"


def test_sender_only_acl_from_inbox_query_is_ignored(session) -> None:
    session(_events(_acl_event(sender=PANEL)))

    assert _poll(1) is None


@pytest.mark.parametrize("status", [401, 403, 404])
def test_poll_stops_when_the_portal_rejects_the_client(session, status) -> None:
    fake = session(_Response(status, {}), _events())

    with pytest.raises(portal.PortalError, match=f"HTTP {status}"):
        _poll(2)
    assert len(fake.params) == 1


def test_poll_retries_transient_failures(session) -> None:
    session(
        requests.ConnectionError("offline"),
        _Response(503, {}),
        _events(_acl_event(destination=[OWN])),
    )

    assert _poll(3) == "ACL"


def test_poll_rejects_a_non_json_response(session) -> None:
    session(_Response(200, None))

    with pytest.raises(portal.PortalError, match="not JSON"):
        _poll(1)


def test_empty_acl_addressed_to_us_is_a_revoke(session) -> None:
    session(_events(_acl_event(payload="", destination=[OWN])))

    with pytest.raises(portal.AclRevokedError):
        _poll(1)


def _discovery(entries):
    payload = base64.b64encode(json.dumps(entries).encode()).decode().rstrip("=")
    return _events({"type": portal.EVENT_TYPE_DISCOVERY, "payload": payload})


def test_discovery_lists_pairable_devices_after_an_empty_start(session) -> None:
    fake = session(
        _events(),
        _discovery(
            {
                PANEL.upper(): {"type": "COM.ABB.ISPF.CLIENT.WELCOME.PANEL", "name": "Hall"},
                OTHER: {"type": "com.abb.ispf.client.globalip.gateway", "name": ""},
                OWN: {"type": portal.CLIENT_TYPE, "name": "ha-1"},
                "33333333-3333-4333-8333-333333333333": {
                    "type": "com.abb.ispf.client.welcome.gateway",
                    "name": "_no_app gateway",
                },
            }
        ),
    )

    devices = portal.list_pairable_devices(URL, b"cert", b"key", attempts=3, interval=0)

    assert devices == {
        PANEL: ("com.abb.ispf.client.welcome.panel", "Hall"),
        OTHER: ("com.abb.ispf.client.globalip.gateway", ""),
    }
    assert len(fake.params) == 2


def test_discovery_returns_nothing_when_no_event_appears(session) -> None:
    session(_events(), _events())

    assert portal.list_pairable_devices(URL, b"cert", b"key", attempts=2, interval=0) == {}


def test_discovery_failure_is_reported(session) -> None:
    session(_Response(500, {}))

    with pytest.raises(portal.PortalError, match="HTTP 500"):
        portal.list_pairable_devices(URL, b"cert", b"key", attempts=2, interval=0)


def test_acl_values_with_percent_signs_parse_literally() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    password = base64.b64encode(
        key.public_key().encrypt(b"synthetic-password", padding.PKCS1v15())
    ).decode()
    payload = "\n".join(
        [
            password,
            "[network]",
            "domain=sip.example.invalid",
            "[outdoorstation_1]",
            "name=Door 100%",
            "address=sip:door@sip.example.invalid",
        ]
    )
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    _, _, doors = portal.parse_acl_update(payload, pem)

    assert doors[0]["name"] == "Door 100%"


def _pairing_record(system_type, permission, *, user_key="username"):
    body = (
        "opaque-first-line\n[network]\n"
        f"systemtype={system_type}\n[user_1]\nuser=other\nopendoor=yes\n"
        f"[user_2]\n{user_key}=ha-client\nopendoor={permission}\n"
    )
    return base64.b64encode(body.encode()).decode().rstrip("=")


def _read_pairing():
    return portal.read_pairing_diagnostics(
        URL, b"cert", b"key", OWN, PANEL, "ha-client"
    )


@pytest.mark.parametrize(
    ("family", "permission", "user_key", "expected"),
    [
        (
            "GlobalIP",
            "no",
            "user",
            {"system_type": "GlobalIP", "open_door_permission": "no"},
        ),
        (
            "mrange",
            "yes",
            "username",
            {"system_type": "mrange", "open_door_permission": "yes"},
        ),
        (
            "private text",
            "other text",
            "user",
            {"system_type": "unknown", "open_door_permission": "unknown"},
        ),
    ],
)
def test_download_reads_only_own_pairing_metadata(
    session, family, permission, user_key, expected
):
    payload = _pairing_record(family, permission, user_key=user_key)
    fake = session(
        _events(
            _acl_event(destination=OTHER, sender=PANEL),
            _acl_event(destination=OWN, sender=OTHER),
            _acl_event(sender=PANEL),
            _acl_event(payload, destinations=[OWN.upper()], source=PANEL.upper()),
        )
    )
    assert _read_pairing() == {"status": "found", **expected}
    assert len(fake.params) == 1
    assert fake.params[0]["type"] == portal.EVENT_TYPE_ACL_UPDATE
    assert fake.params[0]["portal_client"] == PANEL
    assert fake.params[0]["order"] == "desc"


@pytest.mark.parametrize(
    ("response", "status"),
    [
        (_events(_acl_event(destination=OTHER, sender=PANEL)), "not_found"),
        (
            _events(
                _acl_event("", destination=OWN, sender=PANEL),
                _acl_event(
                    _pairing_record("GlobalIP", "yes"), destination=OWN, sender=PANEL
                ),
            ),
            "revoked",
        ),
        (
            _events(_acl_event("broken!", destination=OWN, sender=PANEL)),
            "invalid_record",
        ),
        (_Response(403, {}), "portal_unavailable"),
        (requests.Timeout(), "portal_unavailable"),
    ],
)
def test_unavailable_pairing_metadata_has_no_inferred_permission(
    session, response, status
):
    session(response)
    assert _read_pairing() == {"status": status}


@pytest.mark.parametrize(
    "users",
    [
        "[user_1]\nuser=other\nopendoor=yes",
        "[user_1]\nuser=ha-client\nopendoor=yes\n[user_2]\nuser=ha-client\nopendoor=no",
    ],
)
def test_missing_or_ambiguous_client_grant_stays_unknown(session, users):
    payload = base64.b64encode(f"opaque\n[network]\n{users}\n".encode()).decode()
    session(_events(_acl_event(payload, destination=OWN, sender=PANEL)))
    assert _read_pairing() == {
        "status": "found",
        "system_type": "unknown",
        "open_door_permission": "unknown",
    }
