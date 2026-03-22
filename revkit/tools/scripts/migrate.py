"""revkit migration script — migrate from legacy directories.

Migrates:
    ~/.ida-headless/ → ~/.revkit/ida/
    ~/.jeb-headless/ → ~/.revkit/jeb/

Usage:
    python -m revkit.tools.scripts.migrate [--dry-run]
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path


LEGACY_DIRS = {
    "ida": ".ida-headless",
    "jeb": ".jeb-headless",
}

REGISTRY_MAPPING = {
    "ida": "ida_servers.json",
    "jeb": "jeb_servers.json",
}

NEW_BASE = Path.home() / ".revkit"


def migrate(dry_run: bool = False) -> list[str]:
    """Run migration. Returns list of actions taken."""
    actions = []

    for engine, legacy_name in LEGACY_DIRS.items():
        legacy_dir = Path.home() / legacy_name
        if not legacy_dir.exists():
            actions.append(f"SKIP: {legacy_dir} does not exist")
            continue

        new_dir = NEW_BASE / engine
        if new_dir.exists():
            actions.append(f"SKIP: {new_dir} already exists")
            continue

        if dry_run:
            actions.append(f"DRY-RUN: would copy {legacy_dir} → {new_dir}")
            continue

        new_dir.mkdir(parents=True, exist_ok=True)

        # Copy config files
        for f in legacy_dir.iterdir():
            if f.is_file() and f.suffix == ".json":
                dest = new_dir / f.name
                shutil.copy2(str(f), str(dest))
                actions.append(f"COPY: {f} → {dest}")

        # Convert registry format
        old_reg_name = REGISTRY_MAPPING.get(engine)
        if old_reg_name:
            old_reg = legacy_dir / old_reg_name
            if old_reg.exists():
                new_reg = new_dir / "registry.json"
                _convert_registry(old_reg, new_reg)
                actions.append(f"CONVERT: {old_reg} → {new_reg}")

        # Create symlink/junction for backward compatibility
        if sys.platform == "win32":
            _create_junction(legacy_dir, new_dir, actions)
        else:
            _create_symlink(legacy_dir, new_dir, actions)

        actions.append(f"DONE: {engine} migration complete")

    # Migrate config.json
    _migrate_config(dry_run, actions)

    return actions


def _convert_registry(old_path: Path, new_path: Path) -> None:
    """Convert dict-keyed registry to list format."""
    try:
        data = json.loads(old_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            entries = []
            for iid, info in data.items():
                entry = dict(info)
                entry["id"] = iid
                entries.append(entry)
        elif isinstance(data, list):
            entries = data
        else:
            entries = []
        new_path.write_text(
            json.dumps(entries, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: failed to convert {old_path}: {e}", file=sys.stderr)


def _create_junction(legacy_dir: Path, new_dir: Path, actions: list[str]) -> None:
    """Create Windows junction for backward compatibility."""
    junction_target = legacy_dir
    if junction_target.exists():
        return
    try:
        import subprocess
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction_target), str(new_dir)],
            check=False, capture_output=True,
        )
        actions.append(f"JUNCTION: {junction_target} → {new_dir}")
    except OSError as e:
        actions.append(f"WARN: junction failed: {e}")


def _create_symlink(legacy_dir: Path, new_dir: Path, actions: list[str]) -> None:
    """Create Unix symlink for backward compatibility."""
    if legacy_dir.exists():
        return
    try:
        legacy_dir.symlink_to(new_dir)
        actions.append(f"SYMLINK: {legacy_dir} → {new_dir}")
    except OSError as e:
        actions.append(f"WARN: symlink failed: {e}")


def _migrate_config(dry_run: bool, actions: list[str]) -> None:
    """Migrate or merge config files."""
    new_config = NEW_BASE / "config.json"
    if new_config.exists():
        actions.append(f"SKIP: {new_config} already exists")
        return

    for engine, legacy_name in LEGACY_DIRS.items():
        legacy_config = Path.home() / legacy_name / "config.json"
        if legacy_config.exists():
            if dry_run:
                actions.append(f"DRY-RUN: would use {legacy_config} as base config")
            else:
                NEW_BASE.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(legacy_config), str(new_config))
                actions.append(f"COPY: {legacy_config} → {new_config}")
            return


def verify_migration() -> list[str]:
    """Verify migration results. Returns list of check results."""
    results = []

    # Check new directory structure
    for engine in ("ida", "jeb"):
        engine_dir = NEW_BASE / engine
        if engine_dir.is_dir():
            results.append(f"OK: {engine_dir} exists")
        else:
            results.append(f"MISSING: {engine_dir}")

    # Check config
    config_path = NEW_BASE / "config.json"
    if config_path.exists():
        try:
            json.loads(config_path.read_text(encoding="utf-8"))
            results.append(f"OK: {config_path} valid JSON")
        except json.JSONDecodeError:
            results.append(f"ERROR: {config_path} invalid JSON")
    else:
        results.append(f"MISSING: {config_path}")

    # Check registries
    for engine in ("ida", "jeb"):
        reg = NEW_BASE / engine / "registry.json"
        if reg.exists():
            try:
                data = json.loads(reg.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    results.append(f"OK: {reg} list format ({len(data)} entries)")
                else:
                    results.append(f"WARN: {reg} not list format")
            except json.JSONDecodeError:
                results.append(f"ERROR: {reg} invalid JSON")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Migrate legacy revkit data")
    parser.add_argument("--dry-run", action="store_true", help="Show actions without executing")
    parser.add_argument("--verify", action="store_true", help="Verify migration")
    args = parser.parse_args()

    if args.verify:
        for line in verify_migration():
            print(line)
    else:
        for line in migrate(dry_run=args.dry_run):
            print(line)
