import httpx
import pytest
from unittest.mock import AsyncMock, MagicMock

from mcp_core.relay.client import RelaySession, create_session, poll_for_result


@pytest.mark.asyncio
async def test_create_session_reuses_client():
    mock_response = MagicMock()
    mock_response.status_code = 201

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post.return_value = mock_response
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False

    schema = {"server": "test"}

    # Pass the mock client
    await create_session("https://relay.example.com", "test-server", schema, client=mock_client)

    # Verify post was called on the provided client
    mock_client.post.assert_called_once()
    # Verify the client was NOT closed (aclose for AsyncClient)
    assert mock_client.aclose.call_count == 0


@pytest.mark.asyncio
async def test_poll_for_result_reuses_client():
    mock_response_200 = MagicMock()
    mock_response_200.status_code = 200

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get.return_value = mock_response_200
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False

    # Mock a valid RelaySession
    mock_session = MagicMock(spec=RelaySession)
    mock_session.session_id = "test-session"

    # It will fail on response.json() or further crypto, but we want to check the call
    with pytest.raises(Exception):
        await poll_for_result("https://relay.example.com", mock_session, client=mock_client, timeout_s=0.1)

    assert mock_client.get.called
    assert mock_client.aclose.call_count == 0
