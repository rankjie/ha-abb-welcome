"""The credential export must stay private and out of public web paths."""

from __future__ import annotations

import importlib.util
import os
import stat
import sys
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"
_spec = importlib.util.spec_from_file_location(
    "abb_credential_export_test", _PKG_DIR / "credential_export.py"
)
assert _spec is not None and _spec.loader is not None
export = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = export
_spec.loader.exec_module(export)


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    (config / "www").mkdir(parents=True)
    (config / "private").mkdir()
    return config


def test_default_path_is_in_config_dir(config_dir: Path):
    assert export.resolve_export_path(config_dir, None) == (
        config_dir.resolve() / export.DEFAULT_EXPORT_FILENAME
    )


@pytest.mark.parametrize("requested", ["private/creds.json", "{config}/private/creds.json"])
def test_relative_and_absolute_paths_inside_config(config_dir: Path, requested: str):
    resolved = export.resolve_export_path(config_dir, requested.format(config=config_dir))
    assert resolved == config_dir.resolve() / "private" / "creds.json"


@pytest.mark.parametrize(
    "requested",
    [
        "www/creds.json",
        "{config}/www/creds.json",
        "{config}/www/sub/creds.json",
        "private/../www/creds.json",
        "{config}/www",
    ],
)
def test_public_www_is_rejected(config_dir: Path, requested: str):
    with pytest.raises(export.ExportPathError, match="www"):
        export.resolve_export_path(config_dir, requested.format(config=config_dir))


@pytest.mark.parametrize("requested", ["/tmp/creds.json", "../creds.json", "{config}"])
def test_outside_config_is_rejected(config_dir: Path, requested: str):
    with pytest.raises(export.ExportPathError, match="inside the config directory"):
        export.resolve_export_path(config_dir, requested.format(config=config_dir))


def test_symlink_into_www_is_rejected(config_dir: Path):
    (config_dir / "innocent").symlink_to(config_dir / "www")
    with pytest.raises(export.ExportPathError, match="www"):
        export.resolve_export_path(config_dir, "innocent/creds.json")


def test_directory_target_is_rejected(config_dir: Path):
    with pytest.raises(export.ExportPathError, match="directory"):
        export.resolve_export_path(config_dir, "private")


def test_written_file_is_owner_only(config_dir: Path):
    target = config_dir / "private" / "creds.json"
    export.write_private_file(target, '{"sip_password": "x"}')
    assert target.read_text() == '{"sip_password": "x"}'
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_existing_world_readable_file_is_tightened(config_dir: Path):
    target = config_dir / "private" / "creds.json"
    target.write_text("old")
    os.chmod(target, 0o644)
    export.write_private_file(target, "new")
    assert target.read_text() == "new"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_export_service_is_admin_only():
    """export_credentials must be registered through HA's admin wrapper."""
    source = (_PKG_DIR / "__init__.py").read_text(encoding="utf-8")
    start = source.index("async def _export_creds")
    registration = source[start:source.index("SERVICE_REFRESH_DOORS", start)]
    assert "async_register_admin_service(" in registration
    assert "hass.services.async_register(" not in registration
