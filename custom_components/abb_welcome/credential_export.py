"""Path checks and private file writing for the export_credentials service."""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_EXPORT_FILENAME = "abb_welcome_creds.json"

# ``<config>/www`` is served without authentication under ``/local/``.
_PUBLIC_SUBDIRS = ("www",)


class ExportPathError(ValueError):
    """Raised when a requested export path is not acceptable."""


def resolve_export_path(config_dir: str | os.PathLike[str], requested: str | None) -> Path:
    """Return the resolved export path, or raise ``ExportPathError``.

    The file must live inside the Home Assistant config directory and outside
    any directory that Home Assistant serves without authentication. Relative
    paths are taken relative to the config directory. Symlinks are resolved
    before the checks, so a link inside ``/config`` cannot point elsewhere.
    """
    base = Path(config_dir).resolve()
    raw = Path(requested) if requested else Path(DEFAULT_EXPORT_FILENAME)
    if not raw.is_absolute():
        raw = base / raw
    target = raw.resolve()

    if target == base or not target.is_relative_to(base):
        raise ExportPathError(
            f"Export path must be a file inside the config directory ({base})"
        )
    for name in _PUBLIC_SUBDIRS:
        public = (base / name).resolve()
        if target == public or target.is_relative_to(public):
            raise ExportPathError(
                f"Export path must not be inside {public}: files there are "
                "served without authentication under /local/"
            )
    if target.is_dir():
        raise ExportPathError(f"Export path {target} is a directory")
    return target


def write_private_file(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` readable and writable by the owner only."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        # O_CREAT's mode only applies to new files; tighten existing ones too.
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(text)
    finally:
        if fd != -1:
            os.close(fd)
