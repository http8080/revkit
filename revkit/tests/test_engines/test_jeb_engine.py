"""Tests for engines/jeb/engine.py — JEBEngine."""

import pytest

from revkit.tools.engines.jeb.engine import JEBEngine, _parse_mem_gb


@pytest.fixture
def jeb():
    return JEBEngine()


def test_engine_name(jeb):
    assert jeb.engine_name == "jeb"


def test_db_extension(jeb):
    assert jeb.db_extension == ".jdb2"


def test_make_instance_id(jeb):
    iid = jeb.make_instance_id("/path/to/sample.apk")
    assert "sample" in iid
    assert "_" in iid


def test_make_instance_id_long_name(jeb):
    iid = jeb.make_instance_id("/path/to/very-long-application-name-here.apk")
    name_part = iid.rsplit("_", 1)[0]
    assert len(name_part) <= 20


def test_batch_methods(jeb):
    methods = jeb.get_batch_methods()
    assert "decompile_all" in methods
    assert "security_scan" in methods


def test_build_registry_entry(jeb):
    entry = jeb.build_initial_registry_entry(
        "sample_ab12", "/path/sample.apk",
        project_path="/tmp/sample.jdb2",
    )
    assert entry["id"] == "sample_ab12"
    assert entry["engine"] == "jeb"
    assert entry["project_path"] == "/tmp/sample.jdb2"


def test_build_spawn_config_wrapper(jeb, tmp_path):
    config = {
        "jeb": {
            "install_dir": str(tmp_path),
            "spawn_method": "wrapper",
            "java_home": str(tmp_path / "java"),
            "jvm_opts": ["-Xms512M"],
            "heap": {"auto": False, "default": "4G"},
        }
    }
    sc = jeb.build_spawn_config(
        config, str(tmp_path / "test.apk"), "test_ab12",
        config_path="/tmp/cfg.json",
        project_path="/tmp/test.jdb2",
        log_path="/tmp/test.log",
    )
    assert len(sc.cmd) > 0
    assert sc.cwd == str(tmp_path)


def test_detect_binary_apk(jeb, sample_binaries):
    assert jeb.detect_binary(str(sample_binaries["apk"])) is True


def test_detect_binary_dex(jeb, sample_binaries):
    assert jeb.detect_binary(str(sample_binaries["dex"])) is True


def test_detect_binary_pe(jeb, sample_binaries):
    assert jeb.detect_binary(str(sample_binaries["pe"])) is False


def test_parse_mem_gb():
    assert _parse_mem_gb("4G") == 4
    assert _parse_mem_gb("512M") == 0 or _parse_mem_gb("512M") >= 0
    assert _parse_mem_gb("16G") == 16


def test_compute_resource_opts(jeb, tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_bytes(b"\x00" * 1024)
    config = {"jeb": {"heap": {"auto": False, "default": "4G"}}}
    opts = jeb.compute_resource_opts(str(apk), config)
    assert "xmx" in opts


def test_get_system_ram_gb(jeb):
    ram = JEBEngine._get_system_ram_gb()
    assert ram > 0
