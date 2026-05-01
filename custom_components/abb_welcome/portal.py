"""ABB Welcome cloud-portal pairing client.

Implements the pairing flow that was verified end-to-end on 2026-04-16
against api.eu.mybuildings.abb.com and a local ABB Welcome IP gateway.

Flow:
  1. Generate RSA keypair + CSR (CN=portal_username).
  2. POST /certificate/request (JSON, HTTP Digest auth) -> signed cert.
  3. Compute SHA-1 fingerprint, GRUU (first 5 chars lowercase),
     SIP username (= portal_username + "_" + GRUU), and own_portal_uuid
     (extracted from the cert SAN).
  4. GET /event?type=...discovery using mutual TLS with the new cert,
     decode the base64 JSON payload, find the entry with
     type == com.abb.ispf.client.welcome.gateway.
  5. POST /event with type=...welcome.connect, destination=[gateway_uuid],
     source=own_uuid, plus client-side id+timestamp.  Payload content does
     not affect the integrity code — the gateway re-derives it from the
     cert it received via mTLS.
  6. Compute the integrity code:
        decorated = ":".join(sha1[i:i+2] for i in range(0, 40, 2))   # uppercase
        rand_str  = f"{rand:04d}"      # any value 0000..9999
        hhhh      = MD5(rand_str + ":" + decorated).hexdigest().upper()[:4]
        code      = rand_str + hhhh    # 8 hex chars (display: "NNNN HHHH")
     The gateway form accepts the 8-char form (spaces stripped client-side).
  7. User opens gateway web admin -> App Management -> Handle pending
     -> sets permissions -> types the integrity code.
  8. Gateway pushes a com.abb.ispf.event.welcome.acl-update event addressed
     to our UUID.  Poll /event?type=...acl-update (no portal_client filter,
     it does not mean what you think it does).
  9. Decode the event payload (base64): line 0 is base64 of an
     RSA-PKCS1v15-encrypted SIP password, lines 1+ are an INI config
     describing network domain, outdoor stations, and SIP users.
"""

from __future__ import annotations

import base64
import configparser
import hashlib
import json as _json
import logging
import random
import re
import tempfile
import time
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from .const import (
    CLIENT_TYPE,
    DEFAULT_PORTAL_URL,
    EVENT_TYPE_ACL_UPDATE,
    EVENT_TYPE_CONNECT,
    EVENT_TYPE_DISCOVERY,
    GATEWAY_CLIENT_TYPE,
    GEO_URL,
)

_LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30

# All log messages from this module are prefixed with [abb] so users can grep
# Home Assistant logs easily.  Use `_log(level, msg, *args)` to keep the prefix
# consistent across the file.
LOG_PREFIX = "[abb] "


def _log(level: int, msg: str, *args: Any) -> None:
    _LOGGER.log(level, LOG_PREFIX + msg, *args)


# ---------------------------------------------------------------------------
# HTTP diagnostic logging.  Every outbound request in this module funnels
# through ``_http_trace`` so a single ``logging.getLogger("custom_components."
# "abb_welcome.portal").setLevel(DEBUG)`` produces a complete request/response
# capture for every call (gateway CGI, MyBuildings portal, GEO).
# ---------------------------------------------------------------------------

_TRUNCATE_LIMIT = 800
_REDACT_JSON_RE = re.compile(
    r'("(?:password|securitycode|client-csr)"\s*:\s*)"[^"]*"'
)
_REDACT_FORM_RE = re.compile(r'(password=)[^&\s]*')


def _redact_body(text: str) -> str:
    """Mask passwords / integrity codes / CSRs in a body string."""
    if not text:
        return text
    text = _REDACT_JSON_RE.sub(r'\1"***"', text)
    text = _REDACT_FORM_RE.sub(r'\1***', text)
    return text


def _truncate(text: str, limit: int = _TRUNCATE_LIMIT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"…(+{len(text) - limit} more bytes)"


def _http_trace(resp: requests.Response, label: str = "") -> None:
    """Emit a DEBUG-level full request/response trace for ``resp``.

    Logs request method/URL, request headers (Authorization redacted, Cookie
    intact so session loss is visible), request body (secrets redacted,
    truncated), then response status, headers (including ``Set-Cookie``),
    and body (redacted, truncated).  Early-exits cheaply when DEBUG is off.
    """
    if not _LOGGER.isEnabledFor(logging.DEBUG):
        return
    req = resp.request
    tag = f"[{label}] " if label else ""

    body: Any = req.body
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            body = repr(body)
    body_text = body or ""

    req_headers = dict(req.headers)
    if "Authorization" in req_headers:
        scheme = req_headers["Authorization"].split(" ", 1)[0]
        req_headers["Authorization"] = f"{scheme} ***"

    _log(logging.DEBUG, "%s>> %s %s", tag, req.method, req.url)
    _log(logging.DEBUG, "%s>> req headers: %s", tag, req_headers)
    if body_text:
        _log(logging.DEBUG, "%s>> req body: %s",
             tag, _truncate(_redact_body(str(body_text))))

    _log(logging.DEBUG, "%s<< HTTP %d %s (%d bytes)",
         tag, resp.status_code, resp.reason or "", len(resp.content))
    _log(logging.DEBUG, "%s<< resp headers: %s", tag, dict(resp.headers))
    try:
        resp_text = resp.text
    except Exception as err:  # noqa: BLE001
        resp_text = f"<undecodable: {err}>"
    _log(logging.DEBUG, "%s<< resp body: %s",
         tag, _truncate(_redact_body(resp_text)))


class PortalError(Exception):
    """Raised when a portal API call fails."""


def generate_keypair_and_csr(username: str) -> tuple[bytes, bytes, rsa.RSAPrivateKey]:
    """Generate an RSA-2048 keypair and a CSR with subject CN=username.

    Returns ``(private_key_pem, csr_pem, private_key_object)``.
    """
    _log(logging.INFO, "[step 1/8] Generating RSA-2048 keypair + CSR (CN=%s)", username)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)]))
        .sign(priv, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    _log(logging.DEBUG, "Generated keypair (%d-byte priv) and CSR (%d-byte PEM)",
                  len(priv_pem), len(csr_pem))
    return priv_pem, csr_pem, priv


def resolve_portal_url(username: str) -> str:
    """Look up the regional portal URL via the GEO service."""
    sha = hashlib.sha256(username.encode()).hexdigest()
    _log(logging.INFO, "[step 2/8] GEO lookup for username sha256=%s", sha)
    try:
        resp = requests.get(
            f"{GEO_URL}/api/config/services",
            params={"by_username_sha256": sha},
            timeout=10,
        )
        _http_trace(resp, "geo")
        _log(logging.DEBUG, "GEO -> HTTP %d (%d bytes)", resp.status_code, len(resp.content))
        resp.raise_for_status()
        api_hosts = resp.json().get("api") or []
        if api_hosts:
            url = f"https://{api_hosts[0]}"
            _log(logging.INFO, "Portal URL resolved: %s", url)
            return url
        _log(logging.WARNING, "GEO returned empty api host list; falling back to %s", DEFAULT_PORTAL_URL)
    except (requests.RequestException, ValueError) as err:
        _log(logging.WARNING, "GEO lookup failed (%s); falling back to %s", err, DEFAULT_PORTAL_URL)
    return DEFAULT_PORTAL_URL


def request_certificate(
    portal_url: str,
    username: str,
    password: str,
    csr_pem: bytes,
    client_name: str,
) -> bytes:
    """Submit the CSR to the portal and return the signed cert (PEM)."""
    csr_b64 = base64.b64encode(csr_pem).decode()
    url = f"{portal_url}/certificate/request"
    _log(logging.INFO, 
        "[step 3/8] POST %s (HTTP Digest auth, client-name=%s, client-type=%s)",
        url, client_name, CLIENT_TYPE,
    )
    resp = requests.post(
        url,
        auth=requests.auth.HTTPDigestAuth(username, password),
        json={
            "client-csr": csr_b64,
            "client-name": client_name,
            "client-type": CLIENT_TYPE,
        },
        timeout=DEFAULT_TIMEOUT,
    )
    _http_trace(resp, "cert/request")
    _log(logging.INFO, "Cert response: HTTP %d (%d bytes)", resp.status_code, len(resp.content))
    if resp.status_code == 401:
        raise PortalError("Portal authentication failed (HTTP 401) — check MyBuildings username/password")
    if resp.status_code not in (200, 201):
        _log(logging.ERROR, "Cert request failed body: %s", resp.text[:500])
        raise PortalError(
            f"Certificate request failed: HTTP {resp.status_code} {resp.text[:200]}"
        )

    body = resp.text.strip()
    if body.startswith("-----BEGIN"):
        _log(logging.DEBUG, "Cert returned as raw PEM (%d bytes)", len(body))
        return body.encode()

    # Fallback for environments that JSON-wrap the cert.
    try:
        data = resp.json()
        cert_field = data.get("client-certificate") or data.get("certificate") or ""
        if cert_field.startswith("-----BEGIN"):
            return cert_field.encode()
        return base64.b64decode(cert_field)
    except (ValueError, KeyError) as err:
        raise PortalError(f"Could not parse certificate response: {err}") from err


def derive_identity(cert_pem: bytes, portal_username: str) -> dict[str, str]:
    """Derive SIP username, GRUU and own_portal_uuid from a signed cert."""
    _log(logging.INFO, "[step 4/8] Deriving identity from certificate")
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    sha1 = hashlib.sha1(der).hexdigest().upper()
    gruu = sha1[:5].lower()

    own_uuid = ""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for uri in san.value.get_values_for_type(x509.UniformResourceIdentifier):
            if "/api/client/" in uri:
                own_uuid = uri.rsplit("/", 1)[-1]
                break
    except x509.ExtensionNotFound:
        pass
    if not own_uuid:
        raise PortalError("Could not extract own_portal_uuid from certificate SAN")

    sip_username = f"{portal_username}_{gruu}"
    _log(logging.INFO,
        "Identity: sip_username=%s gruu=%s own_portal_uuid=%s sha1=%s",
        sip_username, gruu, own_uuid, sha1[:16] + "...",
    )
    return {
        "fingerprint_sha1": sha1,
        "gruu": gruu,
        "sip_username": sip_username,
        "own_portal_uuid": own_uuid,
    }


def compute_integrity_code(fingerprint_sha1: str, rand: int | None = None) -> tuple[str, str]:
    """Return (eight_char_code, display_code) where display = ``NNNN HHHH``.

    ``fingerprint_sha1`` must be the 40-char uppercase hex SHA-1 of the
    cert DER.  ``rand`` is any integer 0..9999 — picked at random when None.
    """
    if rand is None:
        rand = random.randint(0, 9999)
    if not 0 <= rand <= 9999:
        raise ValueError("rand must be in 0..9999")
    if len(fingerprint_sha1) != 40:
        raise ValueError("fingerprint must be 40 hex chars")

    decorated = ":".join(fingerprint_sha1[i : i + 2] for i in range(0, 40, 2))
    rand_str = f"{rand:04d}"
    hhhh = hashlib.md5(f"{rand_str}:{decorated}".encode()).hexdigest().upper()[:4]
    eight = f"{rand_str}{hhhh}"
    display = f"{rand_str} {hhhh}"
    _log(logging.INFO, "[step 5/8] Computed integrity code: %s (gateway will recompute and verify)", display)
    return eight, display


def _mtls_session(cert_pem: bytes, key_pem: bytes) -> tuple[requests.Session, list[str]]:
    """Create a requests Session using client cert + key files for mTLS.

    Returns (session, list_of_temp_paths_to_clean_up).
    """
    cert_file = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    cert_file.write(cert_pem)
    cert_file.close()
    key_file = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    key_file.write(key_pem)
    key_file.close()
    session = requests.Session()
    session.cert = (cert_file.name, key_file.name)
    return session, [cert_file.name, key_file.name]


def _cleanup(paths: list[str]) -> None:
    for p in paths:
        try:
            Path(p).unlink(missing_ok=True)
        except OSError:
            pass


def discover_gateway(
    portal_url: str, cert_pem: bytes, key_pem: bytes
) -> tuple[str, str]:
    """Return (gateway_uuid, gateway_name) from the latest discovery event.

    Raises PortalError when no gateway entry is present.
    """
    session, temps = _mtls_session(cert_pem, key_pem)
    try:
        resp = session.get(
            f"{portal_url}/event",
            params={
                "type": EVENT_TYPE_DISCOVERY,
                "pagination_limit": 1,
                "pagination_page": 1,
                "order": "desc",
            },
            timeout=DEFAULT_TIMEOUT,
        )
        _http_trace(resp, "discovery")
        resp.raise_for_status()
        events = (resp.json() or {}).get("events") or []
        if not events:
            raise PortalError(
                "No discovery events visible — the portal account may not be "
                "linked to any IP gateway yet."
            )
        payload_b64 = events[0].get("payload", "")
        pad = "=" * (-len(payload_b64) % 4)
        entries: dict[str, dict[str, Any]] = {}
        try:
            import json
            entries = json.loads(base64.b64decode(payload_b64 + pad))
        except (ValueError, UnicodeDecodeError) as err:
            raise PortalError(f"Could not decode discovery payload: {err}") from err

        for uid, info in entries.items():
            if info.get("type") == GATEWAY_CLIENT_TYPE:
                return uid, info.get("name", "ABB Welcome Gateway")
        raise PortalError(
            "Discovery event has no gateway entry "
            f"(type={GATEWAY_CLIENT_TYPE} not found)"
        )
    finally:
        session.close()
        _cleanup(temps)


def send_connect_event(
    portal_url: str,
    cert_pem: bytes,
    key_pem: bytes,
    gateway_uuid: str,
    own_uuid: str,
    integrity_code: str,
) -> None:
    """POST a welcome.connect event so the gateway shows a pending request.

    The integrity code is included for traceability/debug, but the gateway
    derives the expected code from our cert independently.
    """
    body = {
        "id": str(uuid.uuid4()),
        "type": EVENT_TYPE_CONNECT,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "destination": [gateway_uuid],
        "source": own_uuid,
        "payload": integrity_code,
    }
    _log(logging.INFO,
        "[step 6/8] POST %s/event type=%s destination=[%s] source=%s",
        portal_url, EVENT_TYPE_CONNECT, gateway_uuid, own_uuid,
    )
    _log(logging.DEBUG, "Connect event body id=%s timestamp=%s", body["id"], body["timestamp"])
    session, temps = _mtls_session(cert_pem, key_pem)
    try:
        resp = session.post(
            f"{portal_url}/event", json=body, timeout=DEFAULT_TIMEOUT
        )
        _http_trace(resp, "connect")
        _log(logging.INFO, "Connect event response: HTTP %d", resp.status_code)
        if resp.status_code not in (200, 201):
            _log(logging.ERROR, "Connect event failure body: %s", resp.text[:500])
            raise PortalError(
                f"Connect event rejected: HTTP {resp.status_code} {resp.text[:200]}"
            )
    finally:
        session.close()
        _cleanup(temps)


def poll_acl_update(
    portal_url: str,
    cert_pem: bytes,
    key_pem: bytes,
    own_uuid: str,
    attempts: int = 30,
    interval: float = 3.0,
) -> str | None:
    """Poll until an ACL-update addressed to ``own_uuid`` arrives.

    Returns the base64-decoded payload as text, or None on timeout.
    """
    _log(logging.INFO,
        "[step 8/8] Polling /event?type=%s for own_uuid=%s (max %d attempts, %.1fs interval)",
        EVENT_TYPE_ACL_UPDATE, own_uuid, attempts, interval,
    )
    session, temps = _mtls_session(cert_pem, key_pem)
    try:
        for n in range(1, attempts + 1):
            try:
                resp = session.get(
                    f"{portal_url}/event",
                    params={
                        "type": EVENT_TYPE_ACL_UPDATE,
                        "order": "desc",
                        "pagination_limit": 5,
                        "pagination_page": 1,
                    },
                    timeout=DEFAULT_TIMEOUT,
                )
                _http_trace(resp, f"acl-poll[{n}]")
                resp.raise_for_status()
                events = (resp.json() or {}).get("events") or []
            except (requests.RequestException, ValueError) as err:
                _log(logging.DEBUG, "Poll attempt %d transport error: %s", n, err)
                events = []
            _log(logging.DEBUG, "Poll attempt %d: %d events visible", n, len(events))
            for evt in events:
                dest = evt.get("destination") or []
                if own_uuid in dest:
                    payload_b64 = evt.get("payload", "")
                    pad = "=" * (-len(payload_b64) % 4)
                    raw = base64.b64decode(payload_b64 + pad)
                    _log(logging.INFO,
                        "ACL-update arrived (event id=%s, %d-byte payload) on attempt %d",
                        evt.get("id"), len(raw), n,
                    )
                    return raw.decode("utf-8", errors="replace")
            time.sleep(interval)
        _log(logging.WARNING, "ACL-update polling timed out after %d attempts", attempts)
        return None
    finally:
        session.close()
        _cleanup(temps)


def parse_acl_update(
    payload: str, private_key_pem: bytes
) -> tuple[str, str, list[dict[str, str]]]:
    """Decode an ACL-update payload.

    Returns ``(sip_password, sip_domain, doors)`` where each door is
    ``{"name", "address", "station_id"}``.
    """
    _log(logging.INFO, "Parsing ACL-update payload (%d bytes)", len(payload))
    lines = payload.splitlines()
    if not lines:
        raise PortalError("Empty ACL-update payload")

    encrypted_b64 = lines[0].strip()
    # The gateway pads the payload with NUL bytes — strip them before parsing.
    rest = "\n".join(lines[1:]).replace("\x00", "").rstrip()

    priv = serialization.load_pem_private_key(private_key_pem, password=None)
    try:
        sip_password = priv.decrypt(
            base64.b64decode(encrypted_b64), padding.PKCS1v15()
        ).decode().strip()
    except Exception as err:  # noqa: BLE001
        raise PortalError(f"SIP password decryption failed: {err}") from err
    _log(logging.INFO, "SIP password decrypted (%d chars; value redacted)", len(sip_password))

    config = configparser.ConfigParser()
    try:
        config.read_string(rest)
    except configparser.Error as err:
        raise PortalError(f"Could not parse ACL-update INI body: {err}") from err

    sip_domain = (
        config.get("network", "domain", fallback="")
        if config.has_section("network")
        else ""
    )

    doors: list[dict[str, str]] = []
    for sec in config.sections():
        if not sec.startswith("outdoorstation_"):
            continue
        address = config.get(sec, "address", fallback="")
        if not address:
            continue
        station_id = (
            address.split(":", 1)[-1].split("@", 1)[0] if ":" in address else ""
        )
        doors.append(
            {
                "name": config.get(sec, "name", fallback=sec),
                "address": address,
                "station_id": station_id,
            }
        )

    _log(logging.INFO, "ACL-update parsed: sip_domain=%s, %d door(s)", sip_domain, len(doors))
    for d in doors:
        _log(logging.DEBUG, "  door: %s -> %s", d["name"], d["address"])

    if not sip_domain or not doors:
        raise PortalError("ACL-update payload missing network domain or doors")
    return sip_password, sip_domain, doors


def default_client_name() -> str:
    """Return the friendly device label registered with the portal."""
    return f"ha-{int(time.time())}"


# ---------------------------------------------------------------------------
# Gateway-side automated approval (uses the gateway's local web admin CGI).
# ---------------------------------------------------------------------------

DEFAULT_GATEWAY_PERMISSIONS: dict[str, str] = {
    "conversation": "yes",
    "surveillance": "yes",
    "opendoor": "yes",
    "switchlight": "yes",
    "accesshistory": "yes",
    "deletehistory": "yes",
    "updatenotify": "yes",
}


class GatewayAdminError(Exception):
    """Raised when a call to the gateway's local admin CGI fails."""


# Body-encoding variants tried by ``_gw_post`` in order.  The first one is
# what rankjie's gateway accepts (verified live) and what we observe in
# Chrome dev-tools captures: ``application/x-www-form-urlencoded`` Content-Type
# with a literal JSON string body.  Other firmware revisions appear to be
# stricter — falling back to real ``op=...&...`` form encoding or to a true
# ``application/json`` request body keeps the integration working without
# requiring users to capture cURLs.
_GW_BODY_VARIANTS: tuple[tuple[str, str], ...] = (
    ("application/x-www-form-urlencoded", "json-literal"),
    ("application/x-www-form-urlencoded", "form"),
    ("application/json", "json"),
)


def _encode_gw_body(body: dict, variant: str) -> str:
    if variant == "form":
        return urllib.parse.urlencode(body)
    # "json-literal" and "json" both serialise as a JSON string; only the
    # Content-Type header changes between them.
    return _json.dumps(body)


def _gw_post(
    session: requests.Session,
    gateway_ip: str,
    path: str,
    body: dict,
    timeout: float = 15,
) -> dict:
    """POST a body to a gateway CGI endpoint with automatic encoding fallback.

    Tries body shapes in this order until one returns a non-empty JSON object:

      1. ``Content-Type: application/x-www-form-urlencoded`` + JSON-literal
         body (the shape we observe in Chrome dev-tools captures and the only
         shape that works on rankjie's gateway).
      2. Same Content-Type + actual ``op=...&key=value`` form encoding.
      3. ``Content-Type: application/json`` + JSON body.

    HTTP/transport errors and non-200 responses raise ``GatewayAdminError``
    immediately (no fallback — that's a real failure, not a content-type
    mismatch).  Self-signed gateway certs mean verification stays disabled.
    """
    last_status = 0
    last_text = ""
    last_parsed: dict = {}
    op_label = body.get("op", "?")

    for content_type, variant in _GW_BODY_VARIANTS:
        headers = {
            "Content-Type": content_type,
            "Origin": f"https://{gateway_ip}",
            "Referer": f"https://{gateway_ip}/config.html?v=0.1",
        }
        data = _encode_gw_body(body, variant)
        resp = session.post(
            f"https://{gateway_ip}{path}",
            data=data,
            headers=headers,
            timeout=timeout,
            verify=False,
        )
        _http_trace(resp, f"gw{path}?op={op_label}[{variant}]")
        if resp.status_code != 200:
            raise GatewayAdminError(
                f"{path} returned HTTP {resp.status_code}: {resp.text[:200]}"
            )

        text = resp.text.strip()
        if not text:
            parsed: dict = {}
        else:
            try:
                parsed = resp.json()
            except ValueError:
                # Some endpoints return a bare scalar like "1" or "FALSE".
                parsed = {"_raw": text}

        last_status, last_text, last_parsed = resp.status_code, text, parsed

        if parsed:
            if variant != "json-literal":
                _log(logging.WARNING,
                    "Gateway %s op=%s succeeded with fallback body encoding %r "
                    "(default 'json-literal' returned empty). Your gateway "
                    "firmware appears stricter than the reference build — "
                    "future calls will retry from the default each time.",
                    path, op_label, variant,
                )
            return parsed

        _log(logging.DEBUG,
            "Gateway %s op=%s returned empty body with encoding %r; trying next variant",
            path, op_label, variant,
        )

    _log(logging.WARNING,
        "Gateway %s op=%s returned empty body with all encodings tried "
        "(last HTTP %d, body=%r). Likely cause: session not authenticated "
        "(no auth cookie) — enable DEBUG on custom_components.abb_welcome.portal "
        "to inspect Set-Cookie from /cgi-bin/checklogin.cgi.",
        path, op_label, last_status, last_text,
    )
    return last_parsed


def _gateway_login(
    gateway_ip: str, admin_username: str, admin_password: str
) -> requests.Session:
    """Authenticate to the gateway web admin and return the live session."""
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _log(logging.INFO,
        "Logging into gateway https://%s/cgi-bin/checklogin.cgi as %s",
        gateway_ip, admin_username,
    )
    session = requests.Session()
    resp = session.post(
        f"https://{gateway_ip}/cgi-bin/checklogin.cgi",
        data=_json.dumps(
            {
                "username": admin_username,
                "password": urllib.parse.quote(admin_password, safe=""),
            }
        ),
        headers={"Content-Type": "application/json"},
        timeout=15,
        verify=False,
    )
    _http_trace(resp, "checklogin")
    body = resp.text.strip()
    _log(logging.DEBUG, "Gateway login response: HTTP %d body=%r", resp.status_code, body)
    if resp.status_code != 200 or body not in ("1", "2"):
        session.close()
        raise GatewayAdminError(
            f"Gateway login failed (HTTP {resp.status_code}, body {body!r})"
        )
    cookie_names = list(session.cookies.keys())
    _log(logging.INFO,
        "Gateway login OK (server returned %r); session cookies: %s",
        body, cookie_names or "(none)",
    )
    if not cookie_names:
        _log(logging.WARNING,
            "checklogin.cgi returned %r but did NOT set any session cookies. "
            "Subsequent CGI calls will be unauthenticated and will likely "
            "return empty bodies. Enable DEBUG logging on "
            "custom_components.abb_welcome.portal to inspect the Set-Cookie "
            "response header and request shape.",
            body,
        )
    return session


def gateway_local_info(
    gateway_ip: str,
    admin_password: str,
    *,
    admin_username: str = "admin",
) -> dict[str, Any]:
    """Return ``{"uuid", "portalname", "regstate", "constate"}`` from the gateway.

    This sidesteps the cloud discovery race — useful for new clients that
    aren't yet visible in any portal discovery event.
    """
    _log(logging.INFO, "Fetching gateway info via op=6 (uuid + portalname + regstate)")
    session = _gateway_login(gateway_ip, admin_username, admin_password)
    try:
        info = _gw_post(session, gateway_ip, "/cgi-bin/portalclient.cgi", {"op": "6"})
        _log(logging.INFO, "Gateway op=6 returned: %s", info)
        if "uuid" not in info:
            raise GatewayAdminError(
                f"Gateway op=6 response missing uuid: {info!r}"
            )
        return info
    finally:
        session.close()


def gateway_authorize(
    gateway_ip: str,
    admin_password: str,
    client_name: str,
    integrity_code: str,
    *,
    admin_username: str = "admin",
    permissions: dict[str, str] | None = None,
    request_pause: float = 0.5,
) -> str:
    """Approve our pending pairing request on the gateway automatically.

    Returns the ``sid`` (e.g. ``"user_6"``) that was paired.

    Raises ``GatewayAdminError`` on any step failure.
    """
    perms = dict(DEFAULT_GATEWAY_PERMISSIONS)
    if permissions:
        perms.update(permissions)

    _log(logging.INFO, "[step 7/8] Auto-approving pairing on gateway as friendlyname=%s", client_name)
    session = _gateway_login(gateway_ip, admin_username, admin_password)
    try:
        time.sleep(request_pause)

        # 2. Find our pending sid by friendlyname.
        _log(logging.INFO, "Listing apps via op=10 to find pending entry")
        listing = _gw_post(session, gateway_ip, "/cgi-bin/portalclient.cgi", {"op": "10"})
        apps = listing.get("apps") or []
        _log(logging.DEBUG, "Gateway lists %d apps", len(apps))
        for app in apps:
            _log(logging.DEBUG, "  app: sid=%s friendlyname=%s state=%s uuid=%s",
                 app.get("sid"), app.get("friendlyname"), app.get("state"), app.get("uuid"))
        sid = ""
        for app in apps:
            if app.get("friendlyname") == client_name and app.get("state") == "unpaired":
                sid = app.get("sid", "")
                break
        if not sid:
            raise GatewayAdminError(
                f"No pending app named {client_name!r} on the gateway "
                "(connect event may not have arrived yet — try again)"
            )
        _log(logging.INFO, "Found pending app: sid=%s friendlyname=%s", sid, client_name)
        time.sleep(request_pause)

        # 3. Save permissions for the pending entry (op=2).
        perms_body = {"op": "2", "sid": sid, "state": "unpaired", **perms}
        _log(logging.INFO, "Setting permissions via op=2 for sid=%s: %s", sid, perms)
        perms_result = _gw_post(
            session, gateway_ip, "/cgi-bin/portalclient.cgi", perms_body
        )
        _log(logging.DEBUG, "op=2 returned %r", perms_result)
        if perms_result.get("result") != 1:
            raise GatewayAdminError(
                f"Setting permissions failed: gateway returned {perms_result!r}"
            )
        time.sleep(request_pause)

        # 4. Submit the integrity code (op=3).
        _log(logging.INFO, "Submitting integrity code via op=3 for sid=%s", sid)
        code_body = {"op": "3", "sid": sid, "securitycode": integrity_code}
        code_result = _gw_post(
            session, gateway_ip, "/cgi-bin/portalclient.cgi", code_body
        )
        _log(logging.DEBUG, "op=3 returned %r", code_result)
        if code_result.get("result") != 1:
            raise GatewayAdminError(
                f"Integrity code rejected: gateway returned {code_result!r}"
            )
        _log(logging.INFO, "Gateway accepted integrity code; sid=%s now paired", sid)
        return sid
    finally:
        session.close()
