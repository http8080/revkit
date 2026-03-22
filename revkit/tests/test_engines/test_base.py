"""Tests for engines/base.py — EngineBase ABC."""

import argparse

import pytest

from revkit.tools.core.process import SpawnConfig
from revkit.tools.engines.base import CmdContext, EngineBase


def test_abc_cannot_instantiate():
    with pytest.raises(TypeError):
        EngineBase()


class StubEngine(EngineBase):
    @property
    def engine_name(self): return "stub"
    @property
    def db_extension(self): return ".stub"
    def make_instance_id(self, bp): return "s001"
    def build_spawn_config(self, *a, **kw): return SpawnConfig(cmd=["echo"])
    def pre_spawn(self, *a, **kw): pass
    def get_batch_methods(self): return frozenset()
    def build_initial_registry_entry(self, iid, bp, **kw): return {"id": iid}
    def register_commands(self, sub): pass
    def validate_installation(self): return True


def test_stub_engine():
    e = StubEngine()
    assert e.engine_name == "stub"
    assert e.db_extension == ".stub"
    assert e.make_instance_id("x") == "s001"
    assert e.validate_installation() is True


def test_concrete_defaults():
    e = StubEngine()
    assert e.compute_resource_opts("x", {}) == {}
    assert e.detect_binary("x") is False
    assert "ready" in e.active_states


def test_cmd_context_fields():
    args = argparse.Namespace(instance="abc1")
    ctx = CmdContext(args=args, config={"key": "val"})
    assert ctx.args.instance == "abc1"
    assert ctx.config["key"] == "val"
    assert ctx.config_path is None
    assert ctx.engine is None


def test_inject_common_options():
    parser = argparse.ArgumentParser()
    EngineBase._inject_common_options(parser)
    args = parser.parse_args(["-i", "test123", "--json"])
    assert args.instance == "test123"
    assert args.json is True
