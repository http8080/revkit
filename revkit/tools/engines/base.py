"""revkit engines — EngineBase ABC + CmdContext.

All reverse-engineering engine implementations (IDA, JEB, …) inherit
from :class:`EngineBase` and use :class:`CmdContext` as the single
argument to every ``cmd_*`` handler (D11).
"""

from __future__ import annotations

import argparse
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..core.process import SpawnConfig  # re-export for convenience

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["EngineBase", "CmdContext", "SpawnConfig"]


# ── CmdContext (D11: unified cmd_* signature) ─────────────

@dataclass
class CmdContext:
    """Single argument passed to every ``cmd_*`` handler.

    Unifies the four legacy patterns: ``(args)``, ``(args, config)``,
    ``(args, config, config_path)``, ``(args, engine)`` into one.
    """
    args: argparse.Namespace
    config: dict
    config_path: str | None = None
    engine: EngineBase | None = None
    trace_id: str | None = None


# ── Common options auto-injected by register_commands (D8) ─

_COMMON_OPTIONS = [
    (("-i", "--instance"), {"help": "Target instance ID"}),
    (("-b", "--binary-hint"), {"help": "Binary name substring for instance lookup"}),
    (("--json",), {"action": "store_true", "help": "Output as JSON"}),
    (("--config",), {"metavar": "PATH", "help": "Override config file path"}),
]


# ── EngineBase ABC ────────────────────────────────────────

class EngineBase(ABC):
    """Abstract base class for all analysis engines."""

    # ── abstract properties ──

    @property
    @abstractmethod
    def engine_name(self) -> str:
        """Short engine identifier (e.g. ``'ida'``, ``'jeb'``)."""
        ...

    @property
    @abstractmethod
    def db_extension(self) -> str:
        """Engine database file extension (e.g. ``'.i64'``, ``'.jdb2'``)."""
        ...

    # ── abstract methods ──

    @abstractmethod
    def make_instance_id(self, binary_path: str) -> str:
        """Generate a unique instance ID for *binary_path*."""
        ...

    @abstractmethod
    def build_spawn_config(
        self, config: dict, binary_path: str, instance_id: str, **kwargs: Any
    ) -> SpawnConfig:
        """Build a :class:`SpawnConfig` for spawning the engine server."""
        ...

    @abstractmethod
    def pre_spawn(
        self, config: dict, spawn_config: SpawnConfig, **kwargs: Any
    ) -> None:
        """Hook called before :func:`detach_spawn` (e.g. write JVM opts)."""
        ...

    @abstractmethod
    def get_batch_methods(self) -> frozenset[str]:
        """Return method names that use the longer batch timeout."""
        ...

    @abstractmethod
    def build_initial_registry_entry(
        self, instance_id: str, binary_path: str, **kwargs: Any
    ) -> dict:
        """Build the initial registry dict for a new instance."""
        ...

    @abstractmethod
    def register_commands(self, subparsers: Any) -> None:
        """Register engine-specific CLI sub-commands.

        Common options (``-i``, ``--json``, ``-b``, ``--config``)
        are auto-injected by :meth:`_inject_common_options` (D8).
        """
        ...

    @abstractmethod
    def validate_installation(self) -> bool:
        """Check that the engine binary is installed and reachable."""
        ...

    # ── concrete methods (overridable) ──

    def compute_resource_opts(
        self,
        binary_path: str,
        config: dict,
        override: dict | None = None,
    ) -> dict:
        """Return resource options (memory, threads). Default: empty."""
        return {}

    def detect_binary(self, path: str) -> bool:
        """Return True if this engine can handle the file at *path*."""
        return False

    @property
    def active_states(self) -> frozenset[str]:
        """States considered 'active' for instance resolution."""
        return frozenset({"ready", "analyzing"})

    # ── D8: common option auto-injection ──

    @staticmethod
    def _inject_common_options(parser: argparse.ArgumentParser) -> None:
        """Add ``-i``, ``--json``, ``-b``, ``--config`` to a sub-parser."""
        for flags, kwargs in _COMMON_OPTIONS:
            parser.add_argument(*flags, **kwargs)
