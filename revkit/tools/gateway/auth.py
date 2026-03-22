"""revkit gateway — API key + IP whitelist authentication.

- API key: timing-safe comparison via hmac.compare_digest
- IP whitelist: CIDR support via ipaddress module
- Reverse proxy: X-Forwarded-For trusted only from configured proxies
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
from http.server import BaseHTTPRequestHandler

log = logging.getLogger(__name__)


def validate_api_key(request_key: str | None, stored_key: str | None) -> bool:
    """Timing-safe API key comparison.

    Returns True if stored_key is None (auth disabled) or keys match.
    """
    if not stored_key:
        return True
    if not request_key:
        return False
    return hmac.compare_digest(request_key.encode(), stored_key.encode())


def extract_bearer_token(handler: BaseHTTPRequestHandler) -> str | None:
    """Extract Bearer token from Authorization header."""
    auth = handler.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def extract_client_ip(
    handler: BaseHTTPRequestHandler,
    trusted_proxies: list[str] | None = None,
) -> str:
    """Extract real client IP, respecting X-Forwarded-For from trusted proxies.

    If the direct connection IP is a trusted proxy and X-Forwarded-For is set,
    use the rightmost non-proxy IP. Otherwise, use direct connection IP.
    """
    client_ip = handler.client_address[0]
    if not trusted_proxies:
        return client_ip

    if not _ip_in_list(client_ip, trusted_proxies):
        return client_ip

    xff = handler.headers.get("X-Forwarded-For")
    if not xff:
        return client_ip

    parts = [ip.strip() for ip in xff.split(",")]
    for ip_str in reversed(parts):
        if not _ip_in_list(ip_str, trusted_proxies):
            return ip_str
    return client_ip


def check_ip_whitelist(client_ip: str, allowed_ips: list[str]) -> bool:
    """Check client IP against allowed list with CIDR support.

    Returns True if allowed_ips is empty (whitelist disabled) or IP matches.
    """
    if not allowed_ips:
        return True
    return _ip_in_list(client_ip, allowed_ips)


def _ip_in_list(ip_str: str, ip_list: list[str]) -> bool:
    """Check if ip_str matches any entry in ip_list (exact or CIDR)."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for entry in ip_list:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


def authenticate(handler: BaseHTTPRequestHandler, gw_config: dict) -> bool:
    """Full authentication: API key + IP whitelist.

    Returns True if authenticated, False otherwise.
    """
    trusted_proxies = gw_config.get("trusted_proxies", [])
    client_ip = extract_client_ip(handler, trusted_proxies)
    log.debug("authenticate: client_ip=%s path=%s", client_ip, handler.path)

    allowed_ips = gw_config.get("allowed_ips", [])
    if not check_ip_whitelist(client_ip, allowed_ips):
        log.warning("IP rejected: %s (allowed: %s)", client_ip, allowed_ips)
        return False

    stored_key = gw_config.get("api_key")
    request_key = extract_bearer_token(handler)
    if not validate_api_key(request_key, stored_key):
        log.warning("API key rejected from %s", client_ip)
        return False

    log.debug("authenticate: OK for %s", client_ip)
    return True
