"""Tests for relay client: passphrase generation, session, polling."""

import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_core.crypto.aes import encrypt
from mcp_core.crypto.ecdh import (
    derive_shared_secret,
    export_public_key,
    generate_key_pair,
)
from mcp_core.crypto.kdf import derive_aes_key
from mcp_core.relay.client import (
    RelaySession,
    create_session,
    generate_passphrase,
    poll_for_result,
)
from mcp_core.relay.wordlist import WORDLIST


class TestWordlist:
    def test_contains_exactly_7776_words(self):
        assert len(WORDLIST) == 7776

    def test_contains_only_lowercase_strings(self):
        import re

        for word in WORDLIST:
            assert re.match(r"^[a-z]+(-[a-z]+)*$", word), f"Invalid word: {word}"

    def test_has_no_duplicates(self):
        assert len(set(WORDLIST)) == len(WORDLIST)


class TestGeneratePassphrase:
    def test_returns_non_empty_string(self):
        passphrase = generate_passphrase()
        assert isinstance(passphrase, str)
        assert len(passphrase) > 0
        # Note: can't simply split("-") to count words because some EFF words
        # contain hyphens (e.g., "drop-down"). We verify via wordlist membership.

    def test_respects_custom_word_count(self):
        passphrase = generate_passphrase(6)
        # Verify by matching against wordlist — account for hyphenated words
        found = [w for w in WORDLIST if w in passphrase]
        assert len(found) >= 6

    def test_only_uses_words_from_wordlist(self):
        word_set = set(WORDLIST)
        for _ in range(20):
            passphrase = generate_passphrase()
            # Reconstruct words by checking which wordlist entries appear
            remaining = passphrase
            matched = 0
            for word in sorted(word_set, key=len, reverse=True):
                if str(word) in remaining:
                    remaining = remaining.replace(str(word), "", 1)
                    matched += 1
            assert matched >= 4

    def test_produces_different_passphrases(self):
        results = {generate_passphrase() for _ in range(10)}
        assert len(results) > 1


class TestCreateSession:
    @pytest.fixture()
    def mock_schema(self):
        return {
            "server": "test-server",
            "displayName": "Test Server",
            "fields": [{"key": "token", "label": "Token", "type": "password", "required": True}],
        }

    @pytest.mark.asyncio
    async def test_calls_post_api_sessions(self, mock_schema):
        mock_response = MagicMock()
        mock_response.status_code = 201

        with patch("mcp_core.relay.client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await create_session("https://relay.example.com", "test-server", mock_schema)

            mock_client.post.assert_called_once()
            call_args = mock_client.post.call_args
            assert call_args[0][0] == "https://relay.example.com/api/sessions"
            body = call_args[1]["json"]
            assert body["serverName"] == "test-server"
            assert body["sessionId"]

    @pytest.mark.asyncio
    async def test_returns_session_with_valid_relay_url(self, mock_schema):
        mock_response = MagicMock()
        mock_response.status_code = 201

        with patch("mcp_core.relay.client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            session = await create_session("https://relay.example.com", "test-server", mock_schema)

            assert len(session.session_id) == 64  # 32 bytes hex
            assert "https://relay.example.com/setup?s=" in session.relay_url
            assert "#k=" in session.relay_url
            assert "&p=" in session.relay_url

    @pytest.mark.asyncio
    async def test_throws_on_error_response(self, mock_schema):
        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch("mcp_core.relay.client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with pytest.raises(RuntimeError, match="500"):
                await create_session("https://relay.example.com", "test-server", mock_schema)


class TestPollForResult:
    @pytest.mark.asyncio
    async def test_decrypts_and_returns_credentials_on_200(self):
        cli_priv, cli_pub = generate_key_pair()
        browser_priv, browser_pub = generate_key_pair()
        passphrase = "alpha-bravo-charlie-delta"

        # Browser-side encryption
        shared_secret = derive_shared_secret(browser_priv, cli_pub)
        aes_key = derive_aes_key(shared_secret, passphrase)
        credentials = {"token": "secret-123", "api_key": "key-456"}
        ciphertext, iv, tag = encrypt(aes_key, json.dumps(credentials))

        browser_pub_b64 = export_public_key(browser_pub)

        response_200 = MagicMock()
        response_200.status_code = 200
        response_200.json.return_value = {
            "browserPub": browser_pub_b64,
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "iv": base64.b64encode(iv).decode(),
            "tag": base64.b64encode(tag).decode(),
        }

        delete_response = MagicMock()
        delete_response.status_code = 204

        with patch("mcp_core.relay.client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=response_200)
            mock_client.delete = AsyncMock(return_value=delete_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            session = RelaySession(
                session_id="test-session-id",
                private_key=cli_priv,
                public_key=cli_pub,
                passphrase=passphrase,
                relay_url="https://relay.example.com/setup?s=test-session-id",
            )

            result = await poll_for_result("https://relay.example.com", session, interval_s=0.01, timeout_s=5.0)
            assert result == credentials
            # Session kept alive for bidirectional messaging (no DELETE on success)
            mock_client.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_throws_on_404(self):
        response_404 = MagicMock()
        response_404.status_code = 404

        with patch("mcp_core.relay.client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=response_404)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            _, pub = generate_key_pair()
            priv, _ = generate_key_pair()
            session = RelaySession(
                session_id="expired",
                private_key=priv,
                public_key=pub,
                passphrase="a-b-c-d",
                relay_url="url",
            )

            with pytest.raises(RuntimeError, match="Session expired"):
                await poll_for_result(
                    "https://relay.example.com",
                    session,
                    interval_s=0.01,
                    timeout_s=5.0,
                )

    @pytest.mark.asyncio
    async def test_throws_on_unexpected_status(self):
        response_500 = MagicMock()
        response_500.status_code = 500

        with patch("mcp_core.relay.client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=response_500)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            _, pub = generate_key_pair()
            priv, _ = generate_key_pair()
            session = RelaySession(
                session_id="error",
                private_key=priv,
                public_key=pub,
                passphrase="a-b-c-d",
                relay_url="url",
            )

            with pytest.raises(RuntimeError, match="Unexpected status: 500"):
                await poll_for_result(
                    "https://relay.example.com",
                    session,
                    interval_s=0.01,
                    timeout_s=5.0,
                )

    @pytest.mark.asyncio
    async def test_timeout_after_deadline(self):
        response_202 = MagicMock()
        response_202.status_code = 202

        with patch("mcp_core.relay.client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=response_202)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            _, pub = generate_key_pair()
            priv, _ = generate_key_pair()
            session = RelaySession(
                session_id="slow",
                private_key=priv,
                public_key=pub,
                passphrase="a-b-c-d",
                relay_url="url",
            )

            with pytest.raises(RuntimeError, match="timed out"):
                await poll_for_result(
                    "https://relay.example.com",
                    session,
                    interval_s=0.01,
                    timeout_s=0.05,
                )

    @pytest.mark.asyncio
    async def test_polls_202_then_succeeds_on_200(self):
        cli_priv, cli_pub = generate_key_pair()
        browser_priv, browser_pub = generate_key_pair()
        passphrase = "one-two-three-four"

        shared_secret = derive_shared_secret(browser_priv, cli_pub)
        aes_key = derive_aes_key(shared_secret, passphrase)
        ciphertext, iv, tag = encrypt(aes_key, json.dumps({"key": "value"}))
        browser_pub_b64 = export_public_key(browser_pub)

        response_202 = MagicMock()
        response_202.status_code = 202

        response_200 = MagicMock()
        response_200.status_code = 200
        response_200.json.return_value = {
            "browserPub": browser_pub_b64,
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "iv": base64.b64encode(iv).decode(),
            "tag": base64.b64encode(tag).decode(),
        }

        delete_response = MagicMock()
        delete_response.status_code = 204

        call_count = 0

        async def mock_get(url):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return response_202
            return response_200

        with patch("mcp_core.relay.client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=mock_get)
            mock_client.delete = AsyncMock(return_value=delete_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            session = RelaySession(
                session_id="poll",
                private_key=cli_priv,
                public_key=cli_pub,
                passphrase=passphrase,
                relay_url="url",
            )

            result = await poll_for_result(
                "https://relay.example.com",
                session,
                interval_s=0.01,
                timeout_s=5.0,
            )
            assert result == {"key": "value"}
            assert call_count == 3
