"""Device-list fetch: the Referer carries the origin the login gave the gateway."""

from __future__ import annotations

import ast
import re
import types
from pathlib import Path

import pytest

_SOURCE = (
    Path(__file__).resolve().parent.parent
    / "custom_components"
    / "abb_welcome"
    / "__init__.py"
)
_RAW = "outdoorstation_0+1+Front door+1;outdoorstation_1+2+Gate+0"


class _GatewayAdminError(Exception):
    pass


class _Session:
    def __init__(self, status=200, content=_RAW.encode()):
        self.calls: list[tuple[str, dict]] = []
        self._response = types.SimpleNamespace(status_code=status, content=content)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self._response


def _fetch(login):
    node = next(
        n
        for n in ast.parse(_SOURCE.read_text()).body
        if isinstance(n, ast.FunctionDef) and n.name == "_fetch_gateway_device_list"
    )
    namespace = {
        "requests": types.SimpleNamespace(RequestException=OSError),
        "_gateway_login": login,
        "GatewayAdminError": _GatewayAdminError,
        "decode_gateway_text": lambda raw: raw.decode(),
        "_GATEWAY_ADMIN_TIMEOUT": 5,
        "_GATEWAY_ERROR_CODE_RE": re.compile(r"-?\d+"),
    }
    module = ast.Module(body=[node], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(_SOURCE), "exec"), namespace)
    return namespace["_fetch_gateway_device_list"]


@pytest.mark.parametrize("host", ["192.168.1.185", "abbwelcome.lan"])
def test_device_list_uses_the_configured_host_over_https(host):
    session, logins = _Session(), []
    fetch = _fetch(lambda *args: logins.append(args) or session)
    assert fetch(host, "secret") == _RAW
    assert logins == [(host, "admin", "secret")]
    [(url, kwargs)] = session.calls
    assert url == f"https://{host}/cgi-bin/adduser.cgi"
    assert kwargs["headers"] == {"Referer": f"https://{host}/config.html"}


@pytest.mark.parametrize(
    "session, message",
    [
        (_Session(content=b"-8"), "answered -8"),
        (_Session(status=500), "HTTP 500"),
    ],
)
def test_refused_device_list_is_reported(session, message):
    with pytest.raises(RuntimeError, match=message):
        _fetch(lambda *_args: session)("192.168.1.185", "secret")
    assert len(session.calls) == 1


@pytest.mark.parametrize(
    "error", [_GatewayAdminError("Gateway login failed"), OSError("timed out")]
)
def test_failed_login_is_reported_without_a_plain_http_retry(error):
    def login(*_args):
        raise error

    with pytest.raises(RuntimeError, match=str(error)):
        _fetch(login)("192.168.1.185", "secret")
