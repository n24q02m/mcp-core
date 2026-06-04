import base64
import hashlib
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp_core.oauth.provider import InMemoryAuthCache, OAuthProvider, PreAuthSession
from mcp_core.schema.types import RelayConfigSchema


class TestInMemoryAuthCache:
    def test_save_and_get(self):
        cache = InMemoryAuthCache()
        session = PreAuthSession(
            session_id="sess_1",
            client_id="client_1",
            redirect_uri="https://example.com/callback",
            state="state_1",
            code_challenge="challenge_1",
            code_challenge_method="S256",
            private_key_b64="priv_1",
            passphrase="pass_1",
            expires_at=int(time.time()) + 100,
        )
        cache.save(session)

        retrieved = cache.get_and_delete("sess_1")
        assert retrieved == session
        assert cache.get_and_delete("sess_1") is None

    def test_cleanup_expired_on_save(self):
        cache = InMemoryAuthCache()
        expired_session = PreAuthSession(
            session_id="expired",
            client_id="client_1",
            redirect_uri="https://example.com/callback",
            state="state_1",
            code_challenge="challenge_1",
            code_challenge_method="S256",
            private_key_b64="priv_1",
            passphrase="pass_1",
            expires_at=int(time.time()) - 100,
        )
        # Manually inject into internal cache to bypass cleanup in save() if we want to test save() cleans up
        cache._cache["expired"] = expired_session

        new_session = PreAuthSession(
            session_id="new",
            client_id="client_1",
            redirect_uri="https://example.com/callback",
            state="state_1",
            code_challenge="challenge_1",
            code_challenge_method="S256",
            private_key_b64="priv_1",
            passphrase="pass_1",
            expires_at=int(time.time()) + 100,
        )
        cache.save(new_session)

        assert "expired" not in cache._cache
        assert "new" in cache._cache

    def test_get_expired_returns_none(self):
        cache = InMemoryAuthCache()
        expired_session = PreAuthSession(
            session_id="expired",
            client_id="client_1",
            redirect_uri="https://example.com/callback",
            state="state_1",
            code_challenge="challenge_1",
            code_challenge_method="S256",
            private_key_b64="priv_1",
            passphrase="pass_1",
            expires_at=int(time.time()) - 100,
        )
        cache._cache["expired"] = expired_session

        assert cache.get_and_delete("expired") is None
        assert "expired" not in cache._cache


@pytest.fixture
def mock_jwt_issuer():
    issuer = MagicMock()
    issuer.issue_access_token.return_value = "mock_jwt"
    return issuer


@pytest.fixture
def relay_schema():
    return RelayConfigSchema(
        displayName="Test Server",
        description="A test server",
    )


@pytest.fixture
def provider(mock_jwt_issuer, relay_schema):
    return OAuthProvider(
        server_name="test-server",
        relay_base_url="https://relay.io",
        relay_schema=relay_schema,
        jwt_issuer=mock_jwt_issuer,
    )


class TestOAuthProvider:
    @pytest.mark.asyncio
    @patch("mcp_core.oauth.provider.create_session", new_callable=AsyncMock)
    @patch("mcp_core.oauth.provider.export_private_key")
    async def test_create_authorize_redirect(self, mock_export, mock_create, provider):
        mock_session = MagicMock()
        mock_session.session_id = "sess_123"
        mock_session.relay_url = "https://relay.io/auth/sess_123"
        mock_session.private_key = MagicMock()
        mock_session.passphrase = "secret"
        mock_create.return_value = mock_session
        mock_export.return_value = "exported_priv_key"

        url = await provider.create_authorize_redirect(
            client_id="client_1",
            redirect_uri="https://example.com/cb",
            state="state_1",
            code_challenge="challenge_1",
        )

        assert url == "https://relay.io/auth/sess_123"
        mock_create.assert_called_once()

        # Verify saved in cache
        cached = provider.cache.get_and_delete("sess_123")
        assert cached is not None
        assert cached.client_id == "client_1"
        assert cached.private_key_b64 == "exported_priv_key"

    @pytest.mark.asyncio
    @patch("mcp_core.oauth.provider.poll_for_result", new_callable=AsyncMock)
    @patch("mcp_core.oauth.provider.import_private_key")
    async def test_exchange_code_s256_success(self, mock_import, mock_poll, provider):
        # Setup cache
        code_verifier = "thissixteenbyte"
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        pre_auth = PreAuthSession(
            session_id="code_123",
            client_id="client_1",
            redirect_uri="https://example.com/cb",
            state="state_1",
            code_challenge=code_challenge,
            code_challenge_method="S256",
            private_key_b64="priv_b64",
            passphrase="pass",
            expires_at=int(time.time()) + 100,
        )
        provider.cache.save(pre_auth)

        mock_poll.return_value = {"user": "bob"}

        def user_id_extractor(d):
            return d["user"]

        token, creds = await provider.exchange_code(
            code="code_123",
            code_verifier=code_verifier,
            user_id_extractor=user_id_extractor,
        )

        assert token == "mock_jwt"
        assert creds == {"user": "bob"}
        provider.jwt_issuer.issue_access_token.assert_called_with(sub="bob")

    @pytest.mark.asyncio
    async def test_exchange_code_invalid_code(self, provider):
        with pytest.raises(ValueError, match="invalid_grant: Expired or invalid code"):
            await provider.exchange_code("unknown", "verifier", lambda x: "id")

    @pytest.mark.asyncio
    async def test_exchange_code_pkce_failure(self, provider):
        pre_auth = PreAuthSession(
            session_id="code_123",
            client_id="client_1",
            redirect_uri="https://example.com/cb",
            state="state_1",
            code_challenge="wrong_challenge",
            code_challenge_method="S256",
            private_key_b64="priv_b64",
            passphrase="pass",
            expires_at=int(time.time()) + 100,
        )
        provider.cache.save(pre_auth)

        with pytest.raises(ValueError, match="invalid_grant: PKCE verification failed"):
            await provider.exchange_code("code_123", "some_verifier", lambda x: "id")

    @pytest.mark.asyncio
    @patch("mcp_core.oauth.provider.poll_for_result", new_callable=AsyncMock)
    @patch("mcp_core.oauth.provider.import_private_key")
    async def test_exchange_code_plain_success(self, mock_import, mock_poll, provider):
        code_verifier = "plain_verifier"
        pre_auth = PreAuthSession(
            session_id="code_123",
            client_id="client_1",
            redirect_uri="https://example.com/cb",
            state="state_1",
            code_challenge=code_verifier,
            code_challenge_method="plain",
            private_key_b64="priv_b64",
            passphrase="pass",
            expires_at=int(time.time()) + 100,
        )
        provider.cache.save(pre_auth)

        mock_poll.return_value = {"user": "alice"}

        token, creds = await provider.exchange_code(
            code="code_123",
            code_verifier=code_verifier,
            user_id_extractor=lambda d: d["user"],
        )
        assert token == "mock_jwt"

    @pytest.mark.asyncio
    async def test_exchange_code_unsupported_method(self, provider):
        pre_auth = PreAuthSession(
            session_id="code_123",
            client_id="client_1",
            redirect_uri="https://example.com/cb",
            state="state_1",
            code_challenge="challenge",
            code_challenge_method="unknown",
            private_key_b64="priv_b64",
            passphrase="pass",
            expires_at=int(time.time()) + 100,
        )
        provider.cache.save(pre_auth)

        with pytest.raises(ValueError, match="unsupported_challenge_method"):
            await provider.exchange_code("code_123", "verifier", lambda x: "id")

    @pytest.mark.asyncio
    @patch("mcp_core.oauth.provider.poll_for_result", new_callable=AsyncMock)
    @patch("mcp_core.oauth.provider.import_private_key")
    async def test_exchange_code_extractor_failure(self, mock_import, mock_poll, provider):
        pre_auth = PreAuthSession(
            session_id="code_123",
            client_id="client_1",
            redirect_uri="https://example.com/cb",
            state="state_1",
            code_challenge="verifier",
            code_challenge_method="plain",
            private_key_b64="priv_b64",
            passphrase="pass",
            expires_at=int(time.time()) + 100,
        )
        provider.cache.save(pre_auth)
        mock_poll.return_value = {"something": "else"}

        with pytest.raises(ValueError, match="server_error: Unable to extract user_id"):
            await provider.exchange_code("code_123", "verifier", lambda x: None)
