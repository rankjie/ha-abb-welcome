"""Device-list fetch: web UI login over HTTPS, then an http://<gateway IP>/ Referer."""

from __future__ import annotations

import ast
import logging
import re
import socket
import types

import pytest
from pathlib import Path

_SOURCE = (
    Path(__file__).resolve().parent.parent
    / "custom_components"
    / "abb_welcome"
    / "__init__.py"
)
_RAW = "outdoorstation_0+1+Front door+1;outdoorstation_1+2+Gate+0"


class _Response:
    def __init__(self, content=b"1"):
        self.status_code = 200
        self.content = content


class _Session:
    calls: list[tuple[str, dict]] = []
    logins: list[tuple] = []
    # Device-list answer per Referer scheme.
    answers: dict[str, bytes] = {}
    login_error: Exception | None = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        scheme = kwargs["headers"]["Referer"].split(":", 1)[0]
        return _Response(self.answers.get(scheme, _RAW.encode()))


class _GatewayAdminError(Exception):
    pass


def _login(*args):
    _Session.logins.append(args)
    if _Session.login_error is not None:
        raise _Session.login_error
    return _Session()


def _fetch(monkeypatch_resolve=None):
    node = next(
        n
        for n in ast.parse(_SOURCE.read_text()).body
        if isinstance(n, ast.FunctionDef) and n.name == "_fetch_gateway_device_list"
    )
    namespace = {
        "requests": types.SimpleNamespace(RequestException=OSError),
        "_gateway_login": _login,
        "GatewayAdminError": _GatewayAdminError,
        "socket": types.SimpleNamespace(
            gethostbyname=monkeypatch_resolve or socket.gethostbyname,
            error=OSError,
        ),
        "decode_gateway_text": lambda raw: raw.decode(),
        "_GATEWAY_ADMIN_TIMEOUT": 5,
        "_GATEWAY_ERROR_CODE_RE": re.compile(r"-?\d+"),
        "_LOGGER": logging.getLogger(__name__),
    }
    module = ast.Module(body=[node], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(_SOURCE), "exec"), namespace)
    return namespace["_fetch_gateway_device_list"]


def _referers():
    return [
        kwargs["headers"]["Referer"]
        for url, kwargs in _Session.calls
        if "adduser.cgi" in url
    ]


def _reset(answers=None, login_error=None):
    _Session.calls = []
    _Session.logins = []
    _Session.answers = answers or {}
    _Session.login_error = login_error


def test_referer_is_http_with_the_gateway_ip():
    _reset()
    assert _fetch()("192.168.1.185", "secret") == _RAW
    assert _Session.logins == [("192.168.1.185", "admin", "secret")]
    assert [url for url, _ in _Session.calls] == [
        "https://192.168.1.185/cgi-bin/adduser.cgi"
    ]
    assert _referers() == ["http://192.168.1.185/config.html"]


def test_referer_uses_the_resolved_ip_for_a_hostname():
    _reset()
    fetch = _fetch(monkeypatch_resolve=lambda host: "192.168.1.185")
    assert fetch("abbwelcome.lan", "secret") == _RAW
    urls = [url for url, _ in _Session.calls]
    assert all(url.startswith("https://abbwelcome.lan/") for url in urls)
    assert _referers() == ["http://192.168.1.185/config.html"]


def test_unresolvable_host_keeps_the_given_name():
    def fail(_host):
        raise OSError("no such host")

    _reset()
    _fetch(monkeypatch_resolve=fail)("gw.invalid", "secret")
    assert _referers() == ["http://gw.invalid/config.html"]


def test_https_referer_is_tried_when_the_http_one_is_refused():
    _reset({"http": b"-8"})
    assert _fetch()("192.168.1.185", "secret") == _RAW
    assert _referers() == [
        "http://192.168.1.185/config.html",
        "https://192.168.1.185/config.html",
    ]


def test_refused_device_list_fails_without_retrying_over_http():
    _reset({"http": b"-8", "https": b"-8"})
    with pytest.raises(RuntimeError, match="answered -8"):
        _fetch()("192.168.1.185", "secret")
    assert len(_Session.logins) == 1
    assert all(url.startswith("https://") for url, _ in _Session.calls)


@pytest.mark.parametrize(
    "error", [_GatewayAdminError("Gateway login failed"), OSError("timed out")]
)
def test_failed_login_is_reported_without_a_plain_http_retry(error):
    _reset(login_error=error)
    with pytest.raises(RuntimeError, match=str(error)):
        _fetch()("192.168.1.185", "secret")
    assert len(_Session.logins) == 1
    assert _Session.calls == []
