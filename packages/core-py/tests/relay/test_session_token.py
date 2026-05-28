import pytest
from datetime import timedelta
from mcp_core.relay.session import (
    claim_session,
    release_session,
    is_session_active,
    validate_session_token,
    get_active_session,
)


@pytest.fixture(autouse=True)
def reset_state():
    release_session()
    yield
    release_session()


def test_claim_returns_token():
    info = claim_session(client_id="bridge-1")
    assert info.token
    assert info.client_id == "bridge-1"
    assert info.expires_at > info.started_at


def test_second_claim_returns_existing():
    first = claim_session(client_id="bridge-1")
    second = claim_session(client_id="bridge-2")
    assert second.token == first.token
    assert second.client_id == "bridge-1"  # original holder


def test_is_session_active_after_claim():
    claim_session(client_id="bridge-1")
    assert is_session_active() is True


def test_release_clears_session():
    claim_session(client_id="bridge-1")
    release_session()
    assert is_session_active() is False


def test_session_expires_after_ttl(monkeypatch):
    info = claim_session(client_id="bridge-1")
    monkeypatch.setattr(
        "mcp_core.relay.session._now",
        lambda: info.expires_at + timedelta(seconds=1),
    )
    assert is_session_active() is False


def test_validate_token_match():
    info = claim_session(client_id="bridge-1")
    assert validate_session_token(info.token) is True


def test_validate_token_mismatch():
    claim_session(client_id="bridge-1")
    assert validate_session_token("wrong-token") is False


def test_validate_token_no_session():
    assert validate_session_token("any") is False


def test_claim_after_expiry(monkeypatch):
    first = claim_session(client_id="bridge-1")
    monkeypatch.setattr(
        "mcp_core.relay.session._now",
        lambda: first.expires_at + timedelta(seconds=1),
    )
    second = claim_session(client_id="bridge-2")
    assert second.token != first.token
    assert second.client_id == "bridge-2"


def test_validate_token_expired(monkeypatch):
    info = claim_session(client_id="bridge-1")
    monkeypatch.setattr(
        "mcp_core.relay.session._now",
        lambda: info.expires_at + timedelta(seconds=1),
    )
    assert validate_session_token(info.token) is False
    assert is_session_active() is False


def test_get_active_session_none():
    assert get_active_session() is None


def test_get_active_session_active():
    info = claim_session(client_id="bridge-1")
    active = get_active_session()
    assert active is not None
    assert active.token == info.token


def test_get_active_session_expired(monkeypatch):
    info = claim_session(client_id="bridge-1")
    monkeypatch.setattr(
        "mcp_core.relay.session._now",
        lambda: info.expires_at + timedelta(seconds=1),
    )
    assert get_active_session() is None
    assert is_session_active() is False
