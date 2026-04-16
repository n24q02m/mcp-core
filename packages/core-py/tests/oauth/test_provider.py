import base64
import hashlib
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_core.oauth.provider import InMemoryAuthCache, OAuthProvider, PreAuthSession
from mcp_core.relay.client import RelaySession


def test_in_memory_auth_cache_save_and_get():
    cache = InMemoryAuthCache()
    session = PreAuthSession(
        session_id="sess_1",
        client_id="client_1",
        redirect_uri="https://app.example/callback",
        state="state_123",
        code_challenge="challenge_123",
        code_challenge_method="S256",
        private_key_b64="pk_b64",
        passphrase="pass",
        expires_at=int(time.time()) + 60,
    )

    cache.save(session)

    # Retrieve
    retrieved = cache.get_and_delete("sess_1")
    assert retrieved == session

    # Verify it's deleted after retrieval
    assert cache.get_and_delete("sess_1") is None


def test_in_memory_auth_cache_expiration():
    cache = InMemoryAuthCache()
    now = int(time.time())

    expired_session = PreAuthSession(
        session_id="expired",
        client_id="client_1",
        redirect_uri="https://app.example/callback",
        state="state_123",
        code_challenge="challenge_123",
        code_challenge_method="S256",
        private_key_b64="pk_b64",
        passphrase="pass",
        expires_at=now - 10,
    )

    cache.save(expired_session)

    # Should return None because it's expired
    assert cache.get_and_delete("expired") is None


def test_in_memory_auth_cache_cleanup_on_save():
    cache = InMemoryAuthCache()
    now = int(time.time())

    # Add an expired session
    expired_session = PreAuthSession(
        session_id="expired",
        client_id="client_1",
        redirect_uri="...",
        state="...",
        code_challenge="...",
        code_challenge_method="S256",
        private_key_b64="...",
        passphrase="...",
        expires_at=now - 10,
    )
    # We have to bypass save() to put it in without triggering cleanup immediately
    # or just trust that save() cleans up *other* expired sessions.
    # save() cleans up AFTER adding the new one.

    cache._cache["expired"] = expired_session
    assert "expired" in cache._cache

    # Add a valid session via save()
    valid_session = PreAuthSession(
        session_id="valid",
        client_id="client_2",
        redirect_uri="...",
        state="...",
        code_challenge="...",
        code_challenge_method="S256",
        private_key_b64="...",
        passphrase="...",
        expires_at=now + 60,
    )
    cache.save(valid_session)

    # expired should be gone now
    assert "expired" not in cache._cache
    assert "valid" in cache._cache


@pytest.mark.asyncio
async def test_create_authorize_redirect():
    # Setup mocks
    mock_jwt_issuer = MagicMock()
    mock_relay_session = RelaySession(
        session_id="relay_sess_1",
        private_key=MagicMock(),  # Normally an ec key, but we just need it for export_private_key mock
        public_key=MagicMock(),
        passphrase="mock_passphrase",
        relay_url="https://relay.example/setup/123",
    )

    with (
        patch("mcp_core.oauth.provider.create_session", new_callable=AsyncMock) as mock_create_session,
        patch("mcp_core.oauth.provider.export_private_key") as mock_export_pk,
    ):
        mock_create_session.return_value = mock_relay_session
        mock_export_pk.return_value = "mock_pk_b64"

        provider = OAuthProvider(
            server_name="test_server",
            relay_base_url="https://relay.example",
            relay_schema={},
            jwt_issuer=mock_jwt_issuer,
        )

        url = await provider.create_authorize_redirect(
            client_id="client_1",
            redirect_uri="https://app.example/callback",
            state="state_123",
            code_challenge="challenge_123",
            code_challenge_method="S256",
        )

        # Verify return value
        assert url == "https://relay.example/setup/123"

        # Verify create_session call
        mock_create_session.assert_called_once_with(
            "https://relay.example",
            "test_server",
            {},
            oauth_state={
                "clientId": "client_1",
                "redirectUri": "https://app.example/callback",
                "state": "state_123",
                "codeChallenge": "challenge_123",
                "codeChallengeMethod": "S256",
            },
        )

        # Verify cache
        stored = provider.cache.get_and_delete("relay_sess_1")
        assert stored is not None
        assert stored.client_id == "client_1"
        assert stored.code_challenge == "challenge_123"
        assert stored.private_key_b64 == "mock_pk_b64"


@pytest.mark.asyncio
async def test_exchange_code_s256_success():
    mock_jwt_issuer = MagicMock()
    mock_jwt_issuer.issue_access_token.return_value = "mock_jwt_token"

    provider = OAuthProvider(
        server_name="test_server",
        relay_base_url="https://relay.example",
        relay_schema={},
        jwt_issuer=mock_jwt_issuer,
    )

    # Setup cache
    code_verifier = "thishastobelongenoughtobesecure_12345678901234567890"
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    session = PreAuthSession(
        session_id="code_123",
        client_id="client_1",
        redirect_uri="...",
        state="...",
        code_challenge=code_challenge,
        code_challenge_method="S256",
        private_key_b64="mock_pk_b64",
        passphrase="mock_passphrase",
        expires_at=int(time.time()) + 60,
    )
    provider.cache.save(session)

    mock_credentials = {"apiKey": "secret_api_key"}

    with (
        patch("mcp_core.oauth.provider.import_private_key"),
        patch("mcp_core.oauth.provider.poll_for_result", new_callable=AsyncMock) as mock_poll,
    ):
        mock_poll.return_value = mock_credentials

        token, creds = await provider.exchange_code(
            code="code_123",
            code_verifier=code_verifier,
            user_id_extractor=lambda c: "user_456",
        )

        assert token == "mock_jwt_token"
        assert creds == mock_credentials
        mock_jwt_issuer.issue_access_token.assert_called_once_with(sub="user_456")


@pytest.mark.asyncio
async def test_exchange_code_plain_success():
    mock_jwt_issuer = MagicMock()
    mock_jwt_issuer.issue_access_token.return_value = "mock_jwt_token"

    provider = OAuthProvider(
        server_name="test_server",
        relay_base_url="https://relay.example",
        relay_schema={},
        jwt_issuer=mock_jwt_issuer,
    )

    code_verifier = "plain_verifier"
    session = PreAuthSession(
        session_id="code_plain",
        client_id="client_1",
        redirect_uri="...",
        state="...",
        code_challenge=code_verifier,
        code_challenge_method="plain",
        private_key_b64="...",
        passphrase="...",
        expires_at=int(time.time()) + 60,
    )
    provider.cache.save(session)

    with (
        patch("mcp_core.oauth.provider.import_private_key"),
        patch("mcp_core.oauth.provider.poll_for_result", new_callable=AsyncMock) as mock_poll,
    ):
        mock_poll.return_value = {"id": "1"}

        token, _ = await provider.exchange_code(
            code="code_plain",
            code_verifier=code_verifier,
            user_id_extractor=lambda c: "user_789",
        )
        assert token == "mock_jwt_token"


@pytest.mark.asyncio
async def test_exchange_code_invalid_code():
    provider = OAuthProvider(MagicMock(), "", {}, MagicMock())
    with pytest.raises(ValueError, match="invalid_grant: Expired or invalid code"):
        await provider.exchange_code("nonexistent", "verifier", lambda c: "id")


@pytest.mark.asyncio
async def test_exchange_code_pkce_failure():
    provider = OAuthProvider(MagicMock(), "", {}, MagicMock())
    session = PreAuthSession(
        session_id="code_fail",
        client_id="client_1",
        redirect_uri="...",
        state="...",
        code_challenge="correct_challenge",
        code_challenge_method="plain",
        private_key_b64="...",
        passphrase="...",
        expires_at=int(time.time()) + 60,
    )
    provider.cache.save(session)

    with pytest.raises(ValueError, match="invalid_grant: PKCE plain verification failed"):
        await provider.exchange_code("code_fail", "wrong_verifier", lambda c: "id")


@pytest.mark.asyncio
async def test_exchange_code_unsupported_method():
    provider = OAuthProvider(MagicMock(), "", {}, MagicMock())
    session = PreAuthSession(
        session_id="code_unsupported",
        client_id="client_1",
        redirect_uri="...",
        state="...",
        code_challenge="...",
        code_challenge_method="unknown",
        private_key_b64="...",
        passphrase="...",
        expires_at=int(time.time()) + 60,
    )
    provider.cache.save(session)

    with pytest.raises(ValueError, match="unsupported_challenge_method"):
        await provider.exchange_code("code_unsupported", "verifier", lambda c: "id")


@pytest.mark.asyncio
async def test_exchange_code_user_id_extraction_failure():
    mock_jwt_issuer = MagicMock()
    provider = OAuthProvider(
        server_name="test_server",
        relay_base_url="https://relay.example",
        relay_schema={},
        jwt_issuer=mock_jwt_issuer,
    )

    session = PreAuthSession(
        session_id="code_extract_fail",
        client_id="client_1",
        redirect_uri="...",
        state="...",
        code_challenge="verifier",
        code_challenge_method="plain",
        private_key_b64="...",
        passphrase="...",
        expires_at=int(time.time()) + 60,
    )
    provider.cache.save(session)

    with (
        patch("mcp_core.oauth.provider.import_private_key"),
        patch("mcp_core.oauth.provider.poll_for_result", new_callable=AsyncMock) as mock_poll,
    ):
        mock_poll.return_value = {"something": "else"}

        with pytest.raises(ValueError, match="server_error: Unable to extract user_id from credentials"):
            await provider.exchange_code(
                code="code_extract_fail",
                code_verifier="verifier",
                user_id_extractor=lambda c: None,  # Fail extraction
            )


@pytest.mark.asyncio
async def test_exchange_code_s256_pkce_failure():
    mock_jwt_issuer = MagicMock()
    provider = OAuthProvider(MagicMock(), "", {}, mock_jwt_issuer)

    session = PreAuthSession(
        session_id="code_s256_fail",
        client_id="client_1",
        redirect_uri="...",
        state="...",
        code_challenge="wrong_challenge",
        code_challenge_method="S256",
        private_key_b64="...",
        passphrase="...",
        expires_at=int(time.time()) + 60,
    )
    provider.cache.save(session)

    with pytest.raises(ValueError, match="invalid_grant: PKCE verification failed"):
        await provider.exchange_code("code_s256_fail", "some_verifier", lambda c: "id")
