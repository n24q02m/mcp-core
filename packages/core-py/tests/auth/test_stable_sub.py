"""Unit tests for the username -> stable subject derivation helper."""

import pytest

from mcp_core.auth.stable_sub import derive_stable_sub


def test_same_input_same_sub():
    a = derive_stable_sub("alice", "wet-mcp", "secret-key")
    b = derive_stable_sub("alice", "wet-mcp", "secret-key")
    assert a == b


def test_normalizes_case_and_whitespace():
    assert derive_stable_sub("Alice", "wet-mcp", "k") == derive_stable_sub("  alice ", "wet-mcp", "k")


def test_distinct_username_distinct_sub():
    assert derive_stable_sub("alice", "wet-mcp", "k") != derive_stable_sub("bob", "wet-mcp", "k")


def test_scoped_per_server():
    assert derive_stable_sub("alice", "wet-mcp", "k") != derive_stable_sub("alice", "mnemo-mcp", "k")


def test_keyed_by_secret():
    assert derive_stable_sub("alice", "wet-mcp", "k1") != derive_stable_sub("alice", "wet-mcp", "k2")


def test_shape_matches_random_sub():
    sub = derive_stable_sub("alice", "wet-mcp", "k")
    assert 20 <= len(sub) <= 24
    assert "=" not in sub and "/" not in sub and "+" not in sub


def test_dev_fallback_when_secret_unset():
    # Stable even without a secret (single-user/dev): same input -> same sub.
    assert derive_stable_sub("alice", "wet-mcp", None) == derive_stable_sub("alice", "wet-mcp", None)


def test_empty_username_rejected():
    with pytest.raises(ValueError):
        derive_stable_sub("   ", "wet-mcp", "k")
