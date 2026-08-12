"""Standalone tests for gateway profiles and privacy redaction."""

from __future__ import annotations

import importlib.util
import logging
import sys
import types
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


def _package(name: str) -> types.ModuleType:
    pkg = types.ModuleType(name)
    pkg.__path__ = [str(_PKG_DIR)]
    sys.modules[name] = pkg
    return pkg


def _load(package: str, module: str):
    full_name = f"{package}.{module}"
    spec = importlib.util.spec_from_file_location(
        full_name, _PKG_DIR / f"{module}.py"
    )
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


_package("abb_profile_test")
redaction = _load("abb_profile_test", "redaction")


def test_recursive_redaction_handles_nested_dicts_and_lists() -> None:
    value = {
        "gateway_ip": "192.0.2.10",
        "nested": [
            {
                "gateway_uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "default_unlock_station_id": "station-front",
                "doors": [
                    {
                        "name": "Private front door",
                        "station_id": "100000001",
                        "address": "sip:100000001@192.0.2.10",
                    }
                ],
            }
        ],
        "certificate_pem": "-----BEGIN CERTIFICATE-----\nsecret\n-----END CERTIFICATE-----",
        "ipv6_peer": "[2001:db8::10]",
    }
    result = redaction.redact_log_value(value)
    rendered = repr(result)
    for private_value in (
        "192.0.2.10",
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "Private front door",
        "100000001",
        "secret",
        "2001:db8::10",
        "station-front",
    ):
        assert private_value not in rendered


def test_log_filter_redacts_identifiers_and_exception_messages() -> None:
    record = logging.LogRecord(
        "abb",
        logging.ERROR,
        __file__,
        1,
        "SIP call_id=%s peer=%s failed: %s",
        (
            "private-call-id",
            "192.0.2.10",
            RuntimeError("request to 192.0.2.10 failed"),
        ),
        None,
    )
    assert redaction.ABBWelcomeRedactionFilter().filter(record)
    rendered = record.getMessage()
    assert "private-call-id" not in rendered
    assert "192.0.2.10" not in rendered
    assert rendered.count("<redacted>") == 3


def test_log_filter_redacts_camera_unlock_and_rtsp_template_arguments() -> None:
    cases = [
        (
            (
                "[abb] camera %s: RTSP server ready url=%s stream=%s "
                "camera_index=%s camera_count=%d"
            ),
            (
                "Outdoor Station 1-1",
                "rtsp://127.0.0.1:12345/",
                "abb_100000001",
                "default",
                1,
            ),
            ("Outdoor Station 1-1", "rtsp://127.0.0.1:12345/", "abb_100000001"),
        ),
        (
            "Fast unlock succeeded for %s",
            ("Outdoor Station 2-1",),
            ("Outdoor Station 2-1",),
        ),
        (
            "Invite unlock failed for %s: %s",
            ("Outdoor Station 2-1", "SIP/2.0 403 private-station"),
            ("Outdoor Station 2-1", "private-station"),
        ),
        (
            "BYE result for %s: %s",
            ("Outdoor Station 2-1", "SIP/2.0 200 private-call"),
            ("Outdoor Station 2-1", "private-call"),
        ),
        (
            "Call teardown issue after unlock for %s: %s",
            ("Outdoor Station 2-1", RuntimeError("private-call-id")),
            ("Outdoor Station 2-1", "private-call-id"),
        ),
        (
            "[abb] talkback stats %s camera_index=%s: %s",
            (
                "Outdoor Station 2-1",
                "default",
                {"packets": 42, "owner": "private-owner"},
            ),
            ("Outdoor Station 2-1", "private-owner"),
        ),
        (
            "[abb-rtsp] %s connected",
            ((("192.0.2.44", 54321)),),
            ("192.0.2.44", "54321"),
        ),
        (
            "[abb] incoming call pickup allowed for entry %s",
            ("private-entry-id",),
            ("private-entry-id",),
        ),
        (
            "[abb] Screenshot event %s captured at %s",
            ("private-event-id", "2026-07-31T22:17:27+00:00"),
            ("private-event-id", "2026-07-31T22:17:27+00:00"),
        ),
    ]
    filter_ = redaction.ABBWelcomeRedactionFilter()
    for message, args, private_values in cases:
        record = logging.LogRecord(
            "abb",
            logging.INFO,
            __file__,
            1,
            message,
            args,
            None,
        )
        assert filter_.filter(record)
        rendered = record.getMessage()
        for private_value in private_values:
            assert private_value not in rendered
        assert "<redacted>" in rendered

    # Fixed state values remain useful even though the SIP context is sensitive.
    state_record = logging.LogRecord(
        "abb",
        logging.INFO,
        __file__,
        1,
        "[abb] SIP listener state: %s -> %s",
        ("connecting", "registered"),
        None,
    )
    assert filter_.filter(state_record)
    assert state_record.getMessage().endswith("connecting -> registered")


def test_sensitive_portal_trace_bodies_are_suppressed() -> None:
    portal = _load("abb_profile_test", "portal")
    payload = (
        '{"payload":"acl-secret","uuid":'
        '"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}'
    )
    assert portal._trace_body("acl-poll[1]", payload) == (
        "<redacted-sensitive-payload>"
    )
    assert portal._trace_body("connect", payload) == (
        "<redacted-sensitive-payload>"
    )
    headers = portal._redact_headers(
        {
            "Cookie": "session=secret",
            "Set-Cookie": "session=secret",
            "Authorization": "Digest secret",
        }
    )
    assert set(headers.values()) == {"***"}
    local_url = portal._redact_body(
        "https://gateway.private.local/path?peer=[2001:db8::10]"
    )
    assert "gateway.private.local" not in local_url
    assert "2001:db8::10" not in local_url


def test_diagnostics_redaction_uses_nested_lists_and_dicts() -> None:
    config_entries = types.ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = type("ConfigEntry", (), {})
    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = type("HomeAssistant", (), {})
    sys.modules.setdefault("homeassistant", types.ModuleType("homeassistant"))
    sys.modules["homeassistant.config_entries"] = config_entries
    sys.modules["homeassistant.core"] = core
    diagnostics = _load("abb_profile_test", "diagnostics")
    private = {
        "doors": [
            {
                "name": "Private front door",
                "station_id": "100000001",
                "address": "sip:100000001@192.0.2.10",
            }
        ],
        "nested": {
            "default_unlock_station_id": "station-front",
            "own_portal_uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "peer": "[2001:db8::10]",
        },
    }
    rendered = repr(diagnostics._redact(private))
    assert "Private front door" not in rendered
    assert "100000001" not in rendered
    assert "192.0.2.10" not in rendered
    assert "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" not in rendered
    assert "2001:db8::10" not in rendered
    assert "station-front" not in rendered
