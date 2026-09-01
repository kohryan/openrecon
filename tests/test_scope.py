from __future__ import annotations

import pytest

from openrecon.scope import Scope, ScopeViolation


def test_wildcard_include_matches_subdomains():
    s = Scope(include=["example.com", "*.example.com"])
    assert s.allows_host("example.com")
    assert s.allows_host("api.example.com")
    assert not s.allows_host("example.com.evil.net")
    assert not s.allows_host("notexample.com")


def test_exclude_beats_include():
    s = Scope(include=["*.example.com"], exclude=["status.example.com"])
    assert s.allows_host("api.example.com")
    assert not s.allows_host("status.example.com")


def test_ip_requires_explicit_network_or_derivation():
    s = Scope(include=["*.example.com"], networks=["93.184.216.0/24"])
    assert s.allows_ip("93.184.216.34")
    assert not s.allows_ip("198.51.100.1")


def test_resolved_ip_of_in_scope_host_becomes_authorized():
    s = Scope(include=["*.example.com"])
    assert not s.allows_ip("93.184.216.34")
    s.authorize_ip("93.184.216.34")
    assert s.allows_ip("93.184.216.34")


def test_private_addresses_are_never_in_scope():
    s = Scope(include=["*"], networks=["10.0.0.0/8", "127.0.0.0/8"])
    assert not s.allows_ip("10.1.2.3")
    assert not s.allows_ip("127.0.0.1")


def test_require_raises_with_an_actionable_message():
    s = Scope(include=["example.com"], authorized_by="alice")
    with pytest.raises(ScopeViolation) as exc:
        s.require("evil.net")
    assert "authorization scope" in str(exc.value)


def test_filter_splits_allowed_and_refused():
    s = Scope(include=["*.example.com"])
    allowed, refused = s.filter(["api.example.com", "other.net"])
    assert allowed == ["api.example.com"]
    assert refused == ["other.net"]


def test_scope_file_without_include_is_rejected(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text("authorized_by: alice\ninclude: []\n")
    with pytest.raises(ValueError):
        Scope.load(p)


def test_template_roundtrips(tmp_path):
    path = Scope.write_template(tmp_path / "scope.yaml", "example.com")
    scope = Scope.load(path)
    assert scope.allows_host("api.example.com")
    assert not scope.allows_host("status.example.com")


def test_private_space_is_opt_in_for_internal_asm():
    default = Scope(include=["*"], networks=["10.0.0.0/8"])
    internal = Scope(include=["*"], networks=["10.0.0.0/8"], allow_private=True)
    assert not default.allows_ip("10.1.2.3")
    assert internal.allows_ip("10.1.2.3")
    assert not internal.allows_ip("127.0.0.1"), "loopback stays blocked either way"
