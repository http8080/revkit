"""revkit core — audit logger (JSONL).

Thread-safe, append-only audit log. I/O failures are silently
swallowed so they never disrupt engine operations.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def get_audit_path(engine_name: str) -> Path:
    """Return ``~/.revkit/{engine}/audit.jsonl``."""
    return Path.home() / ".revkit" / engine_name / "audit.jsonl"


class AuditLogger:
    """Append-only JSONL audit logger (thread-safe)."""

    def __init__(self, audit_path: str | Path):
        self._path = Path(audit_path)
        self._lock = threading.Lock()

    def log_event(
        self,
        engine: str,
        command: str,
        instance_id: str | None = None,
        params: dict | None = None,
        result_ok: bool = True,
        elapsed_ms: float = 0.0,
        source_ip: str | None = None,
    ) -> None:
        """Write a single audit event. Never raises."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "engine": engine,
            "cmd": command,
            "iid": instance_id,
            "ok": result_ok,
            "ms": round(elapsed_ms, 2),
        }
        if source_ip:
            record["source_ip"] = source_ip
        if params:
            record["params"] = _redact(params)

        try:
            with self._lock:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass


def _redact(params: dict) -> dict:
    """Redact sensitive fields (exec code) from audit params."""
    redacted = dict(params)
    for key in ("code", "script", "exec_code"):
        if key in redacted:
            redacted[key] = "[REDACTED]"
    return redacted
