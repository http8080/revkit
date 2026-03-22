"""Tests for core/instance.py."""

import os
import time

import pytest

from revkit.tools.core.instance import (
    is_process_alive,
    make_instance_id,
    resolve_instance,
    wait_for_start,
)
from revkit.tools.core.registry import save_registry


def test_make_instance_id():
    iid = make_instance_id("/path/to/sample.apk")
    assert "_" in iid
    assert "sample" in iid


def test_make_instance_id_uniqueness():
    ids = {make_instance_id(f"/path/to/file_{i}.exe") for i in range(10)}
    assert len(ids) == 10


def test_make_instance_id_unicode():
    iid = make_instance_id("/path/to/테스트앱.apk")
    assert len(iid) > 0


def test_is_process_alive_self():
    assert is_process_alive(os.getpid()) is True


def test_is_process_alive_dead():
    assert is_process_alive(999999) is False


def test_is_process_alive_zero():
    assert is_process_alive(0) is False


class MockArgs:
    def __init__(self, **kwargs):
        self.instance = kwargs.get("instance")
        self.binary_hint = kwargs.get("binary_hint")


def test_resolve_by_id(tmp_registry):
    entries = [{"id": "abc1", "state": "ready", "binary": "test.exe", "pid": os.getpid(),
                "last_heartbeat": time.time()}]
    save_registry(tmp_registry, entries)
    args = MockArgs(instance="abc1")
    iid, info = resolve_instance(args, tmp_registry)
    assert iid == "abc1"


def test_resolve_by_hint(tmp_registry):
    entries = [{"id": "abc1", "state": "ready", "binary": "sample.exe", "pid": os.getpid(),
                "last_heartbeat": time.time()}]
    save_registry(tmp_registry, entries)
    args = MockArgs(binary_hint="sample")
    iid, info = resolve_instance(args, tmp_registry)
    assert iid == "abc1"


def test_resolve_single_active(tmp_registry):
    entries = [{"id": "only1", "state": "ready", "binary": "test.exe", "pid": os.getpid(),
                "last_heartbeat": time.time()}]
    save_registry(tmp_registry, entries)
    args = MockArgs()
    iid, info = resolve_instance(args, tmp_registry)
    assert iid == "only1"


def test_resolve_no_active(tmp_registry):
    save_registry(tmp_registry, [])
    args = MockArgs()
    iid, info = resolve_instance(args, tmp_registry)
    assert iid is None


def test_wait_for_start_immediate(tmp_registry):
    entries = [{"id": "w1", "state": "ready"}]
    save_registry(tmp_registry, entries)
    assert wait_for_start(tmp_registry, "w1", timeout=1.0) is True


def test_wait_for_start_timeout(tmp_registry):
    entries = [{"id": "w2", "state": "initializing"}]
    save_registry(tmp_registry, entries)
    assert wait_for_start(tmp_registry, "w2", timeout=0.5, poll_interval=0.1) is False
