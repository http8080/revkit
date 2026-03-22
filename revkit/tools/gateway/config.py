"""revkit gateway — configuration loader.

Loads gateway-specific settings from the 'gateway' section of config.json.
Reuses core/config.py's load_config().
"""

from __future__ import annotations

from typing import Any

GATEWAY_DEFAULTS: dict[str, Any] = {
    "host": "0.0.0.0",
    "port": 8080,
    "max_upload_size_mb": 500,
    "upload_dir": None,
    "api_key": None,
    "allowed_ips": [],
    "trusted_proxies": [],
    "request_timeout": 60,
    "batch_timeout": 300,
    "log_rpc_params": False,
    "audit_path": None,
    "audit_max_size_mb": 100,
    "exec_enabled": False,
}


def load_gateway_config(config: dict) -> dict:
    """Extract gateway section from full config, applying defaults.

    Args:
        config: Full parsed config dict (from core load_config).

    Returns:
        Gateway-specific config with defaults applied.
    """
    gw = dict(GATEWAY_DEFAULTS)
    raw = config.get("gateway", {})
    gw.update({k: v for k, v in raw.items() if k in GATEWAY_DEFAULTS})
    return gw


def validate_gateway_config(gw_config: dict) -> list[str]:
    """Validate gateway config values. Returns list of error messages (empty = OK)."""
    errors: list[str] = []

    port = gw_config.get("port", 8080)
    if not isinstance(port, int) or not (1 <= port <= 65535):
        errors.append(f"Invalid port: {port} (must be 1-65535)")

    max_upload = gw_config.get("max_upload_size_mb", 500)
    if max_upload is not None and (not isinstance(max_upload, (int, float)) or max_upload < 0):
        errors.append(f"Invalid max_upload_size_mb: {max_upload} (0 = unlimited, null = upload disabled)")

    allowed_ips = gw_config.get("allowed_ips", [])
    if not isinstance(allowed_ips, list):
        errors.append("allowed_ips must be a list")

    trusted_proxies = gw_config.get("trusted_proxies", [])
    if not isinstance(trusted_proxies, list):
        errors.append("trusted_proxies must be a list")

    return errors
