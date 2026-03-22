"""revkit core — configuration loader.

Loads JSON config, expands environment variables, supports deep merge
for project-local overrides.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)


def _expand_env(value: str) -> str:
    """Expand ~ and environment variables ($HOME, %USERPROFILE%) in a string."""
    # Skip URL values — normpath would mangle http:// to http:/
    if value.startswith(("http://", "https://")):
        return value
    result = os.path.expanduser(value)
    result = os.path.expandvars(result)
    # Cross-platform fallback: %USERPROFILE% on Unix → $HOME
    if "%USERPROFILE%" in result:
        result = result.replace("%USERPROFILE%", os.environ.get("HOME", ""))
    return os.path.normpath(result)


def _expand_config(obj):
    """Recursively expand environment variables in all string values."""
    if isinstance(obj, str):
        return _expand_env(obj)
    if isinstance(obj, dict):
        return {k: _expand_config(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_config(v) for v in obj]
    return obj


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base* (non-destructive)."""
    merged = dict(base)
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = _deep_merge(merged[key], val)
        else:
            merged[key] = val
    return merged


_DEFAULT_CONFIG_PATH = Path.home() / ".revkit" / "config.json"


def load_config(config_path: str | Path | None = None) -> dict:
    """Load a JSON config file and expand environment variables.

    If *config_path* is ``None``, falls back to ``~/.revkit/config.json``.

    Raises:
        FileNotFoundError: *config_path* does not exist.
        json.JSONDecodeError: file is not valid JSON.
    """
    if config_path is None:
        config_path = _DEFAULT_CONFIG_PATH
        log.debug("No config path specified, using default: %s", config_path)
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    log.debug("Loading config from %s", config_path)
    with open(config_path, encoding="utf-8") as f:
        raw = json.load(f)

    config = _expand_config(raw)

    # Auto-create data directory if specified (JEB pattern)
    data_dir = config.get("data_dir")
    if data_dir:
        os.makedirs(data_dir, exist_ok=True)

    return config


def merge_project_config(
    config: dict, project_dir: str | Path | None = None
) -> dict:
    """Merge project-local ``config.local.json`` if present."""
    if project_dir is None:
        project_dir = Path.cwd()
    local_path = Path(project_dir) / "config.local.json"
    if not local_path.is_file():
        log.debug("No project-local config at %s", local_path)
        return config
    try:
        log.debug("Merging project-local config from %s", local_path)
        with open(local_path, encoding="utf-8") as f:
            local = json.load(f)
        return _deep_merge(config, _expand_config(local))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Failed to load project-local config %s: %s", local_path, exc)
        return config


def get_engine_config(config: dict, engine_name: str) -> dict:
    """Return engine-specific config section (empty dict if absent)."""
    return config.get(engine_name, {})
