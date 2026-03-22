"""Tests for core/registry.py."""

import json
import os
import threading
import time

import pytest

from revkit.tools.core.registry import (
    acquire_lock,
    cleanup_stale,
    get_registry_path,
    load_registry,
    register_instance,
    registry_locked,
    release_lock,
    save_registry,
    unregister_instance,
)


def test_get_registry_path():
    p = get_registry_path("ida")
    assert "ida" in str(p)
    assert p.name == "registry.json"


def test_load_empty(tmp_registry):
    assert load_registry(tmp_registry) == []


def test_save_load_roundtrip(tmp_registry):
    entries = [{"id": "abc1", "state": "ready"}]
    save_registry(tmp_registry, entries)
    loaded = load_registry(tmp_registry)
    assert loaded == entries


def test_load_corrupt_json(tmp_registry):
    tmp_registry.write_text("{bad json", encoding="utf-8")
    assert load_registry(tmp_registry) == []


def test_load_dict_format(tmp_registry):
    """Legacy dict format → converted to list."""
    data = {"abc1": {"id": "abc1", "state": "ready"}}
    tmp_registry.write_text(json.dumps(data), encoding="utf-8")
    result = load_registry(tmp_registry)
    assert isinstance(result, list)
    assert result[0]["id"] == "abc1"


def test_register_instance(tmp_registry):
    entry = {"id": "test1", "path": "/bin/test", "state": "initializing"}
    register_instance(tmp_registry, entry)
    entries = load_registry(tmp_registry)
    assert len(entries) == 1
    assert entries[0]["id"] == "test1"


def test_register_max_instances(tmp_registry):
    for i in range(3):
        entry = {"id": f"t{i}", "path": f"/bin/t{i}", "state": "ready", "pid": None}
        save_registry(tmp_registry, load_registry(tmp_registry) + [entry])

    with pytest.raises(RuntimeError, match="Max instances"):
        register_instance(
            tmp_registry,
            {"id": "t3", "path": "/bin/t3", "state": "initializing"},
            max_instances=3,
        )


def test_unregister_instance(tmp_registry):
    entries = [{"id": "a1"}, {"id": "b2"}]
    save_registry(tmp_registry, entries)
    assert unregister_instance(tmp_registry, "a1") is True
    remaining = load_registry(tmp_registry)
    assert len(remaining) == 1
    assert remaining[0]["id"] == "b2"


def test_unregister_not_found(tmp_registry):
    save_registry(tmp_registry, [{"id": "a1"}])
    assert unregister_instance(tmp_registry, "zzz") is False


def test_acquire_release_lock(tmp_path):
    lock = tmp_path / "test.lock"
    assert acquire_lock(lock, timeout=1.0) is True
    assert lock.exists()
    release_lock(lock)
    assert not lock.exists()


def test_lock_timeout(tmp_path):
    lock = tmp_path / "test.lock"
    acquire_lock(lock)
    assert acquire_lock(lock, timeout=0.3) is False
    release_lock(lock)


def test_registry_locked_context(tmp_registry):
    save_registry(tmp_registry, [])
    with registry_locked(tmp_registry):
        entries = load_registry(tmp_registry)
        assert isinstance(entries, list)


def test_cleanup_stale_removes_dead(tmp_registry):
    entries = [
        {"id": "dead1", "pid": 999999, "state": "ready", "last_heartbeat": 0},
    ]
    save_registry(tmp_registry, entries)
    result = cleanup_stale(tmp_registry, stale_threshold=1.0)
    assert len(result) == 0


def test_cleanup_stale_keeps_alive(tmp_registry):
    entries = [
        {"id": "alive1", "pid": os.getpid(), "state": "ready",
         "last_heartbeat": time.time()},
    ]
    save_registry(tmp_registry, entries)
    result = cleanup_stale(tmp_registry, stale_threshold=9999)
    assert len(result) == 1


def test_concurrent_lock(tmp_path):
    """Two threads contending for the same lock."""
    lock = tmp_path / "race.lock"
    results = []

    def worker(wid):
        ok = acquire_lock(lock, timeout=2.0)
        results.append((wid, ok))
        if ok:
            time.sleep(0.2)
            release_lock(lock)

    t1 = threading.Thread(target=worker, args=(1,))
    t2 = threading.Thread(target=worker, args=(2,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    assert all(ok for _, ok in results)
