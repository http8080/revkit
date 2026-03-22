"""Tests for core/config.py."""

import json
import os

import pytest

from revkit.tools.core.config import (
    _deep_merge,
    _expand_env,
    get_engine_config,
    load_config,
    merge_project_config,
)


def test_load_config(sample_config):
    cfg = load_config(sample_config)
    assert "ida" in cfg
    assert "jeb" in cfg


def test_load_config_missing():
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/config.json")


def test_load_config_invalid_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{invalid", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        load_config(bad)


def test_expand_env_home():
    result = _expand_env("~/test")
    assert "~" not in result


def test_expand_env_var(monkeypatch):
    monkeypatch.setenv("REVKIT_TEST_VAR", "/custom/path")
    result = _expand_env("$REVKIT_TEST_VAR/data")
    assert "custom" in result and "path" in result


def test_deep_merge_basic():
    base = {"a": 1, "b": {"x": 10, "y": 20}}
    over = {"b": {"y": 99, "z": 30}, "c": 3}
    merged = _deep_merge(base, over)
    assert merged == {"a": 1, "b": {"x": 10, "y": 99, "z": 30}, "c": 3}


def test_deep_merge_recursive():
    base = {"a": {"b": {"c": 1, "d": 2}}}
    over = {"a": {"b": {"d": 99, "e": 3}}}
    merged = _deep_merge(base, over)
    assert merged["a"]["b"] == {"c": 1, "d": 99, "e": 3}


def test_deep_merge_no_mutation():
    base = {"a": {"x": 1}}
    over = {"a": {"y": 2}}
    _deep_merge(base, over)
    assert base == {"a": {"x": 1}}


def test_get_engine_config():
    cfg = {"ida": {"install_dir": "/opt/ida"}, "jeb": {"install_dir": "/opt/jeb"}}
    assert get_engine_config(cfg, "ida") == {"install_dir": "/opt/ida"}
    assert get_engine_config(cfg, "ghidra") == {}


def test_merge_project_config(tmp_path):
    base = {"a": 1, "b": {"x": 10}}
    local = {"b": {"y": 20}, "c": 3}
    (tmp_path / "config.local.json").write_text(json.dumps(local))
    merged = merge_project_config(base, tmp_path)
    assert merged["a"] == 1
    assert merged["b"] == {"x": 10, "y": 20}
    assert merged["c"] == 3


def test_merge_project_config_no_local(tmp_path):
    base = {"a": 1}
    result = merge_project_config(base, tmp_path)
    assert result is base


def test_data_dir_auto_create(tmp_path):
    cfg = {"data_dir": str(tmp_path / "auto_created")}
    config_path = tmp_path / "cfg.json"
    config_path.write_text(json.dumps(cfg))
    load_config(config_path)
    assert (tmp_path / "auto_created").is_dir()
