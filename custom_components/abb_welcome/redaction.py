"""Logging helpers that prevent private installation data from escaping."""

from __future__ import annotations

import logging
import re
from typing import Any

REDACTED = "<redacted>"

_SENSITIVE_KEYS = {
    "abb_encrypt_key",
    "address",
    "authorization",
    "body",
    "call_id",
    "certificate",
    "client-certificate",
    "client-csr",
    "client_name",
    "cookie",
    "crypto_inline_key",
    "crypto_key",
    "destination",
    "default_unlock_station_id",
    "door",
    "gateway_ip",
    "gateway_uuid",
    "host",
    "local_id",
    "local_name",
    "local_send_keys",
    "inline_key",
    "media_crypto_key",
    "name",
    "own_portal_uuid",
    "password",
    "payload",
    "peer",
    "private_key_pem",
    "sender",
    "sdp_crypto",
    "set-cookie",
    "sid",
    "sip_domain",
    "sip_password",
    "sip_username",
    "source",
    "station",
    "station_id",
    "username",
    "uuid",
}
_SENSITIVE_MESSAGE_WORDS = re.compile(
    r"\b(address|body|bye|call[_ -]?id|caller|camera|certificate|client|"
    r"cookie|dialer|door|entry|event|fingerprint|gateway|hangup|host|identity|invite|ip|"
    r"media|payload|peer|rtp|rtsp|session|sid|sip|source|station|stream|"
    r"talkback|teardown|unlock|username|uuid)\b",
    re.IGNORECASE,
)
_SAFE_STATUS_VALUES = {
    "aes_cm_128_hmac_sha1_80",
    "audio",
    "any",
    "connecting",
    "default",
    "delete",
    "describe",
    "disconnected",
    "get",
    "none",
    "patch",
    "play",
    "post",
    "put",
    "registered",
    "rtp/avp",
    "rtp/avpf",
    "setup",
    "standard",
    "stopped",
    "tcp",
    "teardown",
    "tls",
    "udp",
    "unknown",
    "video",
}
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(
    r"\[(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\]"
    r"|(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)
_SIP_RE = re.compile(r"sip:[^\s@;>]+@[^\s;>]+", re.IGNORECASE)
_PEM_RE = re.compile(
    r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL
)
_ABB_ENCRYPT_KEY_RE = re.compile(
    r"(a=abb_encrypt_key\s*:\s*)[^\r\n]*", re.IGNORECASE
)
_SDP_CRYPTO_INLINE_RE = re.compile(
    r"(a=crypto:\d+\s+\S+\s+inline:)[^\s\r\n]+", re.IGNORECASE
)


def redact_abb_encrypt_keys(value: str) -> str:
    """Remove ABB SDP media keys while retaining useful SDP structure."""
    value = _ABB_ENCRYPT_KEY_RE.sub(r"\1" + REDACTED, value)
    return _SDP_CRYPTO_INLINE_RE.sub(r"\1" + REDACTED, value)


def redact_log_value(value: Any, key: str | None = None) -> Any:
    """Recursively redact secrets, network addresses, and device identifiers."""
    if key is not None and key.lower() in _SENSITIVE_KEYS:
        return REDACTED
    if isinstance(value, dict):
        return {str(k): redact_log_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_log_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_log_value(item) for item in value)
    if isinstance(value, BaseException):
        return redact_log_value(str(value))
    if isinstance(value, str):
        value = redact_abb_encrypt_keys(value)
        value = _PEM_RE.sub(REDACTED, value)
        value = _UUID_RE.sub(REDACTED, value)
        value = _IPV4_RE.sub(REDACTED, value)
        value = _IPV6_RE.sub(REDACTED, value)
        return _SIP_RE.sub("sip:<redacted>@<redacted>", value)
    return value


class ABBWelcomeRedactionFilter(logging.Filter):
    """Sanitize every record created by an ABB Welcome module logger."""

    def filter(self, record: logging.LogRecord) -> bool:
        sensitive_context = bool(
            _SENSITIVE_MESSAGE_WORDS.search(str(record.msg))
        )
        if isinstance(record.args, dict):
            record.args = {
                key: (
                    REDACTED
                    if sensitive_context and isinstance(value, str)
                    else redact_log_value(value, str(key))
                )
                for key, value in record.args.items()
            }
        elif isinstance(record.args, tuple):
            record.args = tuple(
                self._redact_argument(value, sensitive_context)
                for value in record.args
            )
        record.msg = redact_log_value(record.msg)
        # Preserve the traceback while sanitizing the exception message.
        if record.exc_info and record.exc_info[1] is not None:
            exc_type, exc, traceback = record.exc_info
            safe_message = (
                REDACTED if sensitive_context else redact_log_value(str(exc))
            )
            try:
                safe_exc = exc_type(safe_message)
            except Exception:  # noqa: BLE001
                safe_exc = RuntimeError(safe_message)
            record.exc_info = (type(safe_exc), safe_exc, traceback)
        record.exc_text = None
        return True

    @staticmethod
    def _redact_argument(value: Any, sensitive_context: bool) -> Any:
        """Redact identifiers while retaining fixed protocol/status labels."""
        if not sensitive_context:
            return redact_log_value(value)
        if isinstance(value, str) and value.lower() in _SAFE_STATUS_VALUES:
            return value
        if isinstance(value, (str, dict, list, tuple, BaseException)):
            return REDACTED
        return redact_log_value(value)


def get_redacting_logger(name: str) -> logging.Logger:
    """Return a module logger with one ABB redaction filter installed."""
    logger = logging.getLogger(name)
    if not any(isinstance(item, ABBWelcomeRedactionFilter) for item in logger.filters):
        logger.addFilter(ABBWelcomeRedactionFilter())
    return logger
