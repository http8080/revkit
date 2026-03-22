"""Tests for migration script."""

import json
import os
from pathlib import Path

import pytest


def test_old_registry_format_convertible(tmp_path):
    """Old ida_servers.json format can be converted."""
    old_format = {
        "abc123": {
            "binary": "/path/to/test.exe",
            "pid": 12345,
            "port": 13000,
            "state": "ready",
        }
    }
    old_file = tmp_path / "ida_servers.json"
    old_file.write_text(json.dumps(old_format))

    data = json.loads(old_file.read_text())
    new_format = []
    for iid, info in data.items():
        entry = dict(info)
        entry["id"] = iid
        new_format.append(entry)

    assert len(new_format) == 1
    assert new_format[0]["id"] == "abc123"
    assert new_format[0]["binary"] == "/path/to/test.exe"


def test_config_path_migration(tmp_path):
    """Config can be loaded from new path."""
    new_dir = tmp_path / ".revkit"
    new_dir.mkdir()
    config = {"ida": {"install_dir": "/opt/ida"}, "jeb": {"install_dir": "/opt/jeb"}}
    (new_dir / "config.json").write_text(json.dumps(config))

    from revkit.tools.core.config import load_config
    cfg = load_config(new_dir / "config.json")
    assert "ida" in cfg
    assert "jeb" in cfg


def test_registry_new_format(tmp_path):
    """New registry.json format is a list."""
    from revkit.tools.core.registry import save_registry, load_registry

    reg_path = tmp_path / "registry.json"
    entries = [
        {"id": "test_001", "binary": "test.exe", "pid": 1234, "state": "ready"},
    ]
    save_registry(reg_path, entries)
    loaded = load_registry(reg_path)
    assert isinstance(loaded, list)
    assert loaded[0]["id"] == "test_001"


def test_data_dir_structure(tmp_path):
    """New data directory structure: ~/.revkit/{engine}/"""
    for engine in ("ida", "jeb"):
        engine_dir = tmp_path / ".revkit" / engine
        engine_dir.mkdir(parents=True)
        assert engine_dir.is_dir()


def test_exit_code_convention():
    """Exit codes follow convention: 0=success, 1=error, 2=arg error."""
    from revkit.tools.cli.main import main
    result = main([])
    assert result == 2
