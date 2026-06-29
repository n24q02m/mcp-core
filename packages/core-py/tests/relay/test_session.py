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
    assert active == info


def test_get_active_session_expired(monkeypatch):
    info = claim_session(client_id="bridge-1")
    monkeypatch.setattr(
        "mcp_core.relay.session._now",
        lambda: info.expires_at + timedelta(seconds=1),
    )
    assert get_active_session() is None


def test_session_expires_exactly_at_limit(monkeypatch):
    info = claim_session(client_id="bridge-1")
    monkeypatch.setattr(
        "mcp_core.relay.session._now",
        lambda: info.expires_at,
    )
    assert is_session_active() is False
    assert validate_session_token(info.token) is False


def test_release_session_no_active():
    # Ensure no session is active
    release_session()
    assert is_session_active() is False

    # Call release_session again
    release_session()
    assert is_session_active() is False

    # Call it multiple times
    release_session()
    release_session()
    assert is_session_active() is False


def test_claim_session_thread_safety():
    import threading
    from queue import Queue

    num_threads = 20
    results = Queue()

    def worker(client_id):
        try:
            # Add a tiny delay to increase chance of contention if lock was missing
            # (though it's already there)
            session = claim_session(client_id)
            results.put(session)
        except Exception as e:
            results.put(e)

    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(f"bridge-{i}",))
        threads.append(t)

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    sessions = []
    while not results.empty():
        res = results.get()
        if isinstance(res, Exception):
            raise res
        sessions.append(res)

    assert len(sessions) == num_threads
    first_session = sessions[0]
    for s in sessions[1:]:
        # All should have the same token and same client_id (the winner's)
        assert s.token == first_session.token
        assert s.client_id == first_session.client_id
