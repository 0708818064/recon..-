"""
Tests for Scope Manager & RoE Enforcement
"""

import pytest
from app import create_app
from database.db import db
from core.scope_manager import ScopeManager


@pytest.fixture
def app_ctx():
    app = create_app('testing')
    with app.app_context():
        yield app


def test_sanitize_target_input():
    assert ScopeManager.sanitize_input("https://scanme.nmap.org/test") == "scanme.nmap.org"
    assert ScopeManager.sanitize_input("http://example.com:8080/admin") == "example.com"
    assert ScopeManager.sanitize_input("  target.local  ") == "target.local"


def test_validate_domain():
    valid, res = ScopeManager.validate_domain("sub.example.com")
    assert valid is True
    assert res == "sub.example.com"

    invalid, msg = ScopeManager.validate_domain("invalid_domain..com")
    assert invalid is False


def test_validate_ip():
    v4_ok, ip = ScopeManager.validate_ip("192.168.1.50")
    assert v4_ok is True
    assert ip == "192.168.1.50"

    v6_ok, ip6 = ScopeManager.validate_ip("2001:db8::1")
    assert v6_ok is True

    bad_ip, _ = ScopeManager.validate_ip("999.999.999.999")
    assert bad_ip is False


def test_validate_cidr():
    ok, net = ScopeManager.validate_cidr("10.0.0.0/24")
    assert ok is True
    assert net == "10.0.0.0/24"

    bad, _ = ScopeManager.validate_cidr("10.0.0.0/99")
    assert bad is False


def test_scope_hierarchy(app_ctx):
    # Add parent domain to scope
    ok, msg, t = ScopeManager.add_target("domain", "test-scope.org", "Authorized Lab")
    assert ok is True

    # Exact match
    in_scope, _ = ScopeManager.is_in_scope("test-scope.org")
    assert in_scope is True

    # Subdomain should be in scope
    sub_in_scope, _ = ScopeManager.is_in_scope("api.test-scope.org")
    assert sub_in_scope is True

    # Unrelated domain must NOT be in scope
    other_in_scope, _ = ScopeManager.is_in_scope("evilcorp.com")
    assert other_in_scope is False
