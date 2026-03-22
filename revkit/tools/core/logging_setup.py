"""revkit core — structured JSON logging setup.

All log files use JSONL (one JSON object per line) for easy parsing.

Directory layout:
    ~/.revkit/logs/
    ├── revkit.jsonl             # all-in-one (global)
    ├── commands.jsonl            # every CLI command invocation
    ├── ida/
    │   ├── engine.jsonl         # IDA engine operations
    │   └── instances/
    │       ├── {iid}.jsonl      # per-instance server log
    │       └── {iid}.stderr     # per-instance stderr capture (raw)
    ├── jeb/
    │   ├── engine.jsonl
    │   └── instances/
    │       └── ...
    └── gateway/
        └── gateway.jsonl
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

_REVKIT_DIR = Path.home() / ".revkit"
_LOGS_DIR = _REVKIT_DIR / "logs"

_MAX_BYTES = 10 * 1024 * 1024  # 10 MB per log file
_BACKUP_COUNT = 3

_initialized = False


class JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra_data"):
            entry["data"] = record.extra_data
        return json.dumps(entry, ensure_ascii=False)


_json_fmt = JsonFormatter()


def _ensure_dirs() -> None:
    """Create the full log directory tree."""
    for sub in (
        _LOGS_DIR,
        _LOGS_DIR / "ida" / "instances",
        _LOGS_DIR / "jeb" / "instances",
        _LOGS_DIR / "gateway",
    ):
        sub.mkdir(parents=True, exist_ok=True)


def _rotating_handler(path: Path, level: int = logging.DEBUG) -> RotatingFileHandler:
    h = RotatingFileHandler(
        str(path), maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT, encoding="utf-8",
    )
    h.setLevel(level)
    h.setFormatter(_json_fmt)
    return h


def init_logging(*, verbose: bool = False) -> None:
    """One-time setup: attach file handlers to the root 'revkit' logger."""
    global _initialized
    if _initialized:
        return
    _initialized = True

    _ensure_dirs()

    root = logging.getLogger("revkit")
    root.setLevel(logging.DEBUG)

    # Global JSON log — everything
    root.addHandler(_rotating_handler(_LOGS_DIR / "revkit.jsonl"))

    # Console handler (only warnings+ unless verbose), also JSON
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.DEBUG if verbose else logging.WARNING)
    ch.setFormatter(_json_fmt)
    root.addHandler(ch)


def get_engine_logger(engine_name: str) -> logging.Logger:
    """Return a logger that also writes to ~/.revkit/logs/{engine}/engine.jsonl."""
    _ensure_dirs()
    name = f"revkit.{engine_name}"
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.addHandler(
            _rotating_handler(_LOGS_DIR / engine_name / "engine.jsonl"),
        )
    return logger


def get_instance_log_path(engine_name: str, instance_id: str) -> Path:
    """Return path for per-instance server log (JSONL)."""
    _ensure_dirs()
    return _LOGS_DIR / engine_name / "instances" / f"{instance_id}.jsonl"


def get_instance_stderr_path(engine_name: str, instance_id: str) -> Path:
    """Return path for per-instance stderr capture (raw text)."""
    _ensure_dirs()
    return _LOGS_DIR / engine_name / "instances" / f"{instance_id}.stderr"


def get_gateway_logger() -> logging.Logger:
    """Return a logger that writes to ~/.revkit/logs/gateway/gateway.jsonl."""
    _ensure_dirs()
    logger = logging.getLogger("revkit.gateway")
    if not logger.handlers:
        logger.addHandler(
            _rotating_handler(_LOGS_DIR / "gateway" / "gateway.jsonl"),
        )
    return logger


# ── Command execution log (JSONL) ────────────────────────

_CMD_LOG_PATH = _LOGS_DIR / "commands.jsonl"


def log_command(
    engine: str,
    command: str,
    *,
    args: dict[str, Any] | None = None,
    result_ok: bool = True,
    elapsed_ms: float = 0.0,
    error: str | None = None,
    instance_id: str | None = None,
) -> None:
    """Append a CLI command invocation record to commands.jsonl."""
    _ensure_dirs()
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "engine": engine,
        "cmd": command,
        "ok": result_ok,
        "ms": round(elapsed_ms, 2),
    }
    if instance_id:
        record["iid"] = instance_id
    if args:
        record["args"] = _safe_args(args)
    if error:
        record["error"] = error[:500]

    try:
        with open(_CMD_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _safe_args(raw: dict[str, Any]) -> dict[str, Any]:
    """Strip internal/sensitive keys from args before logging."""
    skip = {"func", "json_mode", "quiet", "verbose", "config", "_trace_id"}
    out = {}
    for k, v in raw.items():
        if k in skip or v is None:
            continue
        if k in ("code", "script", "exec_code"):
            out[k] = "[REDACTED]"
        else:
            out[k] = str(v) if not isinstance(v, (str, int, float, bool)) else v
    return out


# ── Trace ID (P4: CLI ↔ server correlation) ──────────────

def generate_trace_id() -> str:
    """Generate a short trace ID for correlating CLI commands with server RPC calls."""
    return uuid.uuid4().hex[:12]


# ── Structured logging helpers (P8: extra_data) ──────────

def log_with_data(
    logger: logging.Logger,
    level: int,
    msg: str,
    data: dict[str, Any] | None = None,
) -> None:
    """Log a message with structured extra_data attached (appears as 'data' in JSONL)."""
    record = logger.makeRecord(
        logger.name, level, "(revkit)", 0, msg, (), None,
    )
    if data:
        record.extra_data = data  # type: ignore[attr-defined]
    logger.handle(record)


# ── Lifecycle event logging (P3: instance start/ready/error/stop) ──

def log_lifecycle(
    engine_name: str,
    event: str,
    instance_id: str,
    **extra: Any,
) -> None:
    """Log an instance lifecycle event to the engine logger.

    Events: instance.start, instance.ready, instance.error, instance.stop
    """
    logger = get_engine_logger(engine_name)
    data: dict[str, Any] = {"iid": instance_id, "event": event, **extra}
    log_with_data(logger, logging.INFO, f"lifecycle: {event} iid={instance_id}", data)
