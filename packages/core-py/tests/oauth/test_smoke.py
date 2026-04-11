"""Smoke test for oauth public API.

Verifies every symbol exported by ``mcp_core.oauth.__init__`` is importable.
Behavior tests for JWTIssuer / OAuthProvider / SqliteUserStore live in the
downstream server test suites that exercise the full OAuth 2.1 flow.
"""

from __future__ import annotations


def test_oauth_public_symbols_importable() -> None:
    from mcp_core.oauth import (
        InMemoryAuthCache,
        IOAuthSessionCache,
        IUserCredentialStore,
        JWTIssuer,
        OAuthProvider,
        PreAuthSession,
        SqliteUserStore,
    )

    assert JWTIssuer is not None
    assert OAuthProvider is not None
    assert SqliteUserStore is not None
    assert InMemoryAuthCache is not None
    assert IOAuthSessionCache is not None
    assert IUserCredentialStore is not None
    assert PreAuthSession is not None
