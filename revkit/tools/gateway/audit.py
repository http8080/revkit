"""revkit gateway — audit logger (JSONL).

Gateway-specific audit extending core AuditLogger.
Adds source_ip, elapsed_ms, and redaction for sensitive params.
Thread-safe with archive rotation on size limit.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_AUDIT_MAX_SIZE_MB = 100


class GatewayAuditLogger:
    """Gateway HTTP request-level audit logger (JSONL, thread-safe)."""

    def __init__(
        self,
        audit_path: str | Path | None = None,
        max_size_mb: float = DEFAULT_AUDIT_MAX_SIZE_MB,
        log_rpc_params: bool = False,
    ):
        if audit_path is None:
            audit_path = Path.home() / ".revkit" / "gateway" / "audit.jsonl"
        self._path = Path(audit_path)
        self._max_size = int(max_size_mb * 1024 * 1024)
        self._log_rpc_params = log_rpc_params
        self._lock = threading.Lock()

    def log_request(
        self,
        method: str,
        path: str,
        status: int,
        source_ip: str,
        elapsed_ms: float,
        api_key_id: str | None = None,
        instance_id: str | None = None,
        rpc_method: str | None = None,
        params: dict | None = None,
    ) -> None:
        """Write a single audit record. Never raises."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "path": path,
            "status": status,
            "source_ip": source_ip,
            "elapsed_ms": round(elapsed_ms, 2),
        }
        if api_key_id:
            record["api_key_id"] = api_key_id
        if instance_id:
            record["instance_id"] = instance_id
        if rpc_method:
            record["rpc_method"] = rpc_method
        if params and self._log_rpc_params:
            record["params"] = _redact_params(params)

        try:
            with self._lock:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._maybe_archive()
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def _maybe_archive(self) -> None:
        """Archive current log if it exceeds max size."""
        try:
            if not self._path.exists():
                return
            if self._path.stat().st_size < self._max_size:
                return
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            archive = self._path.with_name(f"audit_{ts}.jsonl")
            shutil.move(str(self._path), str(archive))
        except OSError:
            pass


def _redact_params(params: dict) -> dict:
    """Redact sensitive fields from RPC params."""
    redacted = dict(params)
    for key in ("code", "script", "exec_code", "exec"):
        if key in redacted:
            redacted[key] = "[REDACTED]"
    return redacted
