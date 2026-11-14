"""Gateway admin credentials must never reach the Home Assistant log."""

from __future__ import annotations

import importlib.util
import io
import logging
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"
_spec = importlib.util.spec_from_file_location(
    "abb_credential_redaction_test", _PKG_DIR / "redaction.py"
)
assert _spec is not None and _spec.loader is not None
redaction = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = redaction
_spec.loader.exec_module(redaction)

SECRET = "GwS3cret!Pw"
SECRET_QUOTED = "GwS3cret%21Pw"


class _Gateway(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # noqa: D401 - silence test server
        pass

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self.send_response(200)
        self.send_header("Content-Length", "1")
        self.end_headers()
        self.wfile.write(b"1")


@pytest.fixture
def gateway():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture
def urllib3_debug_log():
    """Capture urllib3 at DEBUG as ``logger: default: debug`` would."""
    logger = logging.getLogger("urllib3.connectionpool")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    old_level, old_filters = logger.level, list(logger.filters)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    yield stream
    logger.removeHandler(handler)
    logger.setLevel(old_level)
    logger.filters = old_filters


def _login(base: str) -> None:
    requests.get(
        f"{base}/cgi-bin/checklogin.cgi",
        params={"name": "admin", "pwd": SECRET},
        timeout=5,
    )


def test_urllib3_request_line_leaks_without_filter(gateway, urllib3_debug_log):
    """Documents the original problem the filter fixes."""
    logging.getLogger("urllib3.connectionpool").filters = []
    _login(gateway)
    assert SECRET_QUOTED in urllib3_debug_log.getvalue()


def test_urllib3_request_line_is_redacted(gateway, urllib3_debug_log):
    redaction.get_redacting_logger("custom_components.abb_welcome.test")
    _login(gateway)
    text = urllib3_debug_log.getvalue()
    assert "checklogin.cgi" in text  # the line is still logged
    assert SECRET_QUOTED not in text and SECRET not in text
    assert f"pwd={redaction.REDACTED}" in text


def test_filter_is_installed_once():
    redaction.install_dependency_redaction()
    redaction.install_dependency_redaction()
    filters = logging.getLogger("urllib3.connectionpool").filters
    assert sum(
        isinstance(item, redaction.CredentialRedactionFilter) for item in filters
    ) == 1


def test_connection_error_message_is_redacted():
    """requests puts the full URL, query included, into the exception text."""
    with pytest.raises(requests.RequestException) as err:
        requests.get(
            "http://127.0.0.1:1/cgi-bin/checklogin.cgi",
            params={"name": "admin", "pwd": SECRET},
            timeout=2,
        )
    assert SECRET_QUOTED in str(err.value)
    cleaned = redaction.redact_url_credentials(str(err.value))
    assert SECRET_QUOTED not in cleaned
    assert SECRET_QUOTED not in redaction.redact_log_value(str(err.value))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/x?name=admin&pwd=abc", f"/x?name=admin&pwd={redaction.REDACTED}"),
        ("password=abc&op=1", f"password={redaction.REDACTED}&op=1"),
        ("PWD=abc def", f"PWD={redaction.REDACTED} def"),
        ("op=6&passwd=a%26b", f"op=6&passwd={redaction.REDACTED}"),
        ("keypass=1&compass=2", "keypass=1&compass=2"),
    ],
)
def test_redact_url_credentials(raw: str, expected: str):
    assert redaction.redact_url_credentials(raw) == expected
