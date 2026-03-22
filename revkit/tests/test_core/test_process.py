"""Tests for core/process.py."""

import sys

import pytest

from revkit.tools.core.process import SpawnConfig, detach_spawn, force_kill


def test_spawn_config_defaults():
    sc = SpawnConfig(cmd=["echo", "test"])
    assert sc.cwd is None
    assert sc.env is None
    assert sc.log_path is None


def test_spawn_config_with_all_fields(tmp_path):
    sc = SpawnConfig(
        cmd=["python", "-c", "pass"],
        cwd=str(tmp_path),
        env={"FOO": "bar"},
        log_path=str(tmp_path / "test.log"),
    )
    assert sc.env["FOO"] == "bar"


def test_detach_spawn():
    sc = SpawnConfig(cmd=[sys.executable, "-c", "import time; time.sleep(0.1)"])
    pid = detach_spawn(sc)
    assert isinstance(pid, int)
    assert pid > 0


def test_force_kill_dead():
    result = force_kill(999999)
    # May or may not succeed depending on OS, but should not raise
    assert isinstance(result, bool)


def test_force_kill_zero():
    assert force_kill(0) is False
