"""Sanitized inbound MESSAGE bodies for temporary protocol diagnostics."""

from __future__ import annotations

import json
import re

from .redaction import REDACTED

MAX_MESSAGE_BODY_BYTES = 4096
MAX_MESSAGE_DIAGNOSTICS_SECONDS = 600
DEFAULT_MESSAGE_DIAGNOSTICS_SECONDS = 300

_JSON_FIELDS = frozenset(
    {
        "id",
        "button",
        "buttons",
        "func",
        "function",
        "params",
        "addr",
        "address",
        "cmd",
        "channel",
        "type",
        "seq",
        "dst",
        "data",
        "name",
        "password",
        "username",
        "token",
        "authorization",
        "certificate",
        "key",
    }
)
_COMMANDS = frozenset({"unlock", "light", "actuator", "intercom", "guard"})
_TEXT_COMMANDS = frozenset({"1", "2", "a"})
_CAMERA_COMMAND = re.compile(r"[cd]:([0-9]{1,3})\Z")


def _json_body(value: object, key: str = "", depth: int = 0) -> object:
    if depth > 6:
        return REDACTED
    if (
        key
        and key not in ("params", "buttons", "data")
        and isinstance(value, (dict, list))
    ):
        return REDACTED
    if isinstance(value, dict):
        return {
            field if field in _JSON_FIELDS else f"redacted_field_{index}": _json_body(
                item, field, depth + 1
            )
            for index, (field, item) in enumerate(value.items(), start=1)
        }
    if isinstance(value, list):
        return [_json_body(item, key, depth + 1) for item in value]
    if key in ("cmd", "function") and isinstance(value, str) and value in _COMMANDS:
        return value
    limits = {
        "id": (1, 2),
        "button": (1, 2),
        "func": (1, 6),
        "channel": (0, 1),
        "type": (0, 6),
        "addr": (1, 199),
        "address": (1, 199),
    }
    if key in limits:
        lower, upper = limits[key]
        if type(value) is int and lower <= value <= upper:
            return value
        if (
            key in ("addr", "address")
            and isinstance(value, str)
            and re.fullmatch(r"[0-9]{1,3}", value)
            and lower <= int(value) <= upper
        ):
            return value
    return REDACTED


def redact_message_body(body: bytes) -> dict[str, object]:
    """Retain protocol commands and button parameters, never unknown values.

    MESSAGE bodies can contain credentials as well as device commands. Unknown
    plaintext has no confidentiality contract, so a deny-list cannot safely
    publish it. Keep only the known command/configuration fields; mask other
    values and unknown field names while retaining their surrounding structure.
    """
    if len(body) > MAX_MESSAGE_BODY_BYTES:
        return {"body": REDACTED, "body_format": "too_large", "body_redacted": True}
    try:
        original = body.decode("utf-8")
    except UnicodeDecodeError:
        return {"body": REDACTED, "body_format": "binary", "body_redacted": True}
    try:
        parsed = json.loads(original)
    except (json.JSONDecodeError, RecursionError):
        parsed = None
    if isinstance(parsed, (dict, list)):
        sanitized_data = _json_body(parsed)
        sanitized = json.dumps(sanitized_data, ensure_ascii=True)
        return {
            "body": sanitized,
            "body_format": "json",
            "body_redacted": sanitized_data != parsed,
        }

    command = original.strip()
    if command in _TEXT_COMMANDS or (
        (match := _CAMERA_COMMAND.fullmatch(command)) and int(match.group(1)) <= 255
    ):
        sanitized = original
    elif re.fullmatch(r"b:[0-9]+", command):
        sanitized = f"b:{REDACTED}"
    else:
        sanitized = REDACTED
    return {
        "body": sanitized,
        "body_format": "text",
        "body_redacted": sanitized != original,
    }
