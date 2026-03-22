"""Config commands -- show/set configuration."""

import json
import logging
import os

from ..core import _log_ok, _opt
from ...base import CmdContext

log = logging.getLogger(__name__)


def cmd_config_show(ctx: CmdContext):
    """#7: Display current config (after env expansion)."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_config_show: json=%s", _opt(args, 'json_output', False))
    if _opt(args, 'json_output', False):
        print(json.dumps(config, indent=2, default=str))
        return

    def _print_section(d, prefix=""):
        for k, v in sorted(d.items()):
            key_str = f"{prefix}{k}" if prefix else k
            if isinstance(v, dict):
                print(f"  {key_str}:")
                _print_section(v, prefix=f"  {key_str}.")
            else:
                print(f"  {key_str}: {v}")
    _print_section(config)


def cmd_config_set(ctx: CmdContext):
    """#8: Set a config value (dot-separated key path)."""
    args, config, config_path = ctx.args, ctx.config, ctx.config_path
    key = args.key
    value = args.value
    log.debug("cmd_config_set: key=%s value=%s config_path=%s", key, value, config_path)

    # Auto-detect type
    if value.lower() in ("true", "false"):
        value = value.lower() == "true"
    else:
        try:
            value = int(value)
        except ValueError:
            try:
                value = float(value)
            except ValueError:
                pass

    # Load raw config file
    with open(config_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # Navigate dot-separated key path
    parts = key.split(".")
    target = raw
    for p in parts[:-1]:
        if p not in target or not isinstance(target[p], dict):
            target[p] = {}
        target = target[p]
    old = target.get(parts[-1], "<unset>")
    target[parts[-1]] = value

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(raw, f, indent=4, ensure_ascii=False)

    _log_ok(f"{key}: {old} → {value}")
