"""Tests for gateway/auth.py."""

import pytest
from unittest.mock import MagicMock

from revkit.tools.gateway.auth import (
    validate_api_key,
    extract_bearer_token,
    extract_client_ip,
    check_ip_whitelist,
    _ip_in_list,
    authenticate,
)


def test_valid_api_key():
    assert validate_api_key("secret123", "secret123") is True


def test_invalid_api_key():
    assert validate_api_key("wrong", "secret123") is False


def test_missing_request_key():
    assert validate_api_key(None, "secret123") is False


def test_no_stored_key_disables_auth():
    assert validate_api_key(None, None) is True
    assert validate_api_key("anything", None) is True
    assert validate_api_key("anything", "") is True


def test_extract_bearer_token():
    handler = MagicMock()
    handler.headers = {"Authorization": "Bearer my-token-123"}
    assert extract_bearer_token(handler) == "my-token-123"


def test_extract_bearer_token_missing():
    handler = MagicMock()
    handler.headers = {}
    assert extract_bearer_token(handler) is None


def test_extract_bearer_token_wrong_scheme():
    handler = MagicMock()
    handler.headers = {"Authorization": "Basic dXNlcjpwYXNz"}
    assert extract_bearer_token(handler) is None


def test_ip_whitelist_allow():
    assert check_ip_whitelist("192.168.1.10", ["192.168.1.10"]) is True


def test_ip_whitelist_block():
    assert check_ip_whitelist("10.0.0.1", ["192.168.1.10"]) is False


def test_ip_whitelist_empty_allows_all():
    assert check_ip_whitelist("10.0.0.1", []) is True


def test_cidr_matching():
    assert _ip_in_list("192.168.1.50", ["192.168.1.0/24"]) is True
    assert _ip_in_list("192.168.2.1", ["192.168.1.0/24"]) is False


def test_cidr_ipv6():
    assert _ip_in_list("::1", ["::1"]) is True
    assert _ip_in_list("::1", ["::1/128"]) is True


def test_invalid_ip():
    assert _ip_in_list("not-an-ip", ["192.168.1.0/24"]) is False


def test_extract_client_ip_direct():
    handler = MagicMock()
    handler.client_address = ("10.0.0.5", 12345)
    handler.headers = {}
    assert extract_client_ip(handler) == "10.0.0.5"


def test_extract_client_ip_xff_trusted():
    handler = MagicMock()
    handler.client_address = ("10.0.0.1", 12345)
    handler.headers = {"X-Forwarded-For": "203.0.113.50, 10.0.0.1"}
    result = extract_client_ip(handler, trusted_proxies=["10.0.0.1"])
    assert result == "203.0.113.50"


def test_extract_client_ip_xff_untrusted():
    handler = MagicMock()
    handler.client_address = ("10.0.0.5", 12345)
    handler.headers = {"X-Forwarded-For": "203.0.113.50"}
    result = extract_client_ip(handler, trusted_proxies=["10.0.0.1"])
    assert result == "10.0.0.5"


def test_authenticate_full():
    handler = MagicMock()
    handler.client_address = ("127.0.0.1", 12345)
    handler.headers = {"Authorization": "Bearer secret-key"}
    gw_config = {
        "api_key": "secret-key",
        "allowed_ips": ["127.0.0.1"],
        "trusted_proxies": [],
    }
    assert authenticate(handler, gw_config) is True


def test_authenticate_ip_rejected():
    handler = MagicMock()
    handler.client_address = ("10.0.0.99", 12345)
    handler.headers = {"Authorization": "Bearer secret-key"}
    gw_config = {
        "api_key": "secret-key",
        "allowed_ips": ["127.0.0.1"],
        "trusted_proxies": [],
    }
    assert authenticate(handler, gw_config) is False


def test_authenticate_key_rejected():
    handler = MagicMock()
    handler.client_address = ("127.0.0.1", 12345)
    handler.headers = {"Authorization": "Bearer wrong-key"}
    gw_config = {
        "api_key": "secret-key",
        "allowed_ips": [],
        "trusted_proxies": [],
    }
    assert authenticate(handler, gw_config) is False
