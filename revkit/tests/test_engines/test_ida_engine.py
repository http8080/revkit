"""Tests for engines/ida/engine.py — IDAEngine."""

import pytest

from revkit.tools.engines.ida.engine import IDAEngine


@pytest.fixture
def ida():
    return IDAEngine()


def test_engine_name(ida):
    assert ida.engine_name == "ida"


def test_db_extension(ida):
    assert ida.db_extension == ".i64"


def test_make_instance_id(ida):
    iid = ida.make_instance_id("/path/to/test.exe")
    assert len(iid) == 4
    assert all(c in "0123456789abcdefghijklmnopqrstuvwxyz" for c in iid)


def test_batch_methods(ida):
    methods = ida.get_batch_methods()
    assert "decompile_batch" in methods
    assert "exec" in methods


def test_build_registry_entry(ida):
    entry = ida.build_initial_registry_entry(
        "ab12", "/path/test.exe",
        arch="x86", bits=64, file_format="PE",
    )
    assert entry["id"] == "ab12"
    assert entry["engine"] == "ida"
    assert entry["state"] == "initializing"
    assert entry["arch"] == "x86"


def test_build_spawn_config(ida, tmp_path):
    config = {"ida": {"install_dir": str(tmp_path)}}
    sc = ida.build_spawn_config(
        config, str(tmp_path / "test.exe"), "ab12",
        config_path="/tmp/cfg.json",
        idb_path="/tmp/test.i64",
        log_path="/tmp/test.log",
    )
    assert len(sc.cmd) > 0
    assert "IDADIR" in sc.env


def test_detect_binary_pe(ida, sample_binaries):
    assert ida.detect_binary(str(sample_binaries["pe"])) is True


def test_detect_binary_elf(ida, sample_binaries):
    assert ida.detect_binary(str(sample_binaries["elf"])) is True


def test_detect_binary_apk(ida, sample_binaries):
    assert ida.detect_binary(str(sample_binaries["apk"])) is False


def test_detect_binary_txt(ida, sample_binaries):
    assert ida.detect_binary(str(sample_binaries["txt"])) is False


def test_validate_installation_no_idadir(ida, monkeypatch):
    monkeypatch.delenv("IDADIR", raising=False)
    assert ida.validate_installation() is False
