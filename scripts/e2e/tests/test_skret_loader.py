"""Tests for skret_loader: AWS SSM Parameter Store reader."""

from unittest.mock import MagicMock, patch

import pytest


def test_load_namespace_returns_short_keys() -> None:
    fake_response = {
        "Parameters": [
            {
                "Name": "/better-notion-mcp/prod/NOTION_INTEGRATION_TOKEN",
                "Value": "secret_xxx",
            },
            {
                "Name": "/better-notion-mcp/prod/MCP_DCR_SERVER_SECRET",
                "Value": "dcr_yyy",
            },
        ]
    }
    with patch("boto3.client") as mock_client:
        client = MagicMock()
        client.get_parameters_by_path.return_value = fake_response
        mock_client.return_value = client

        from e2e.skret_loader import load_namespace

        result = load_namespace("/better-notion-mcp/prod")
    assert result == {
        "NOTION_INTEGRATION_TOKEN": "secret_xxx",
        "MCP_DCR_SERVER_SECRET": "dcr_yyy",
    }


def test_load_namespace_handles_pagination() -> None:
    page1 = {
        "Parameters": [{"Name": "/ns/prod/A", "Value": "1"}],
        "NextToken": "token2",
    }
    page2 = {
        "Parameters": [{"Name": "/ns/prod/B", "Value": "2"}],
    }
    with patch("boto3.client") as mock_client:
        client = MagicMock()
        client.get_parameters_by_path.side_effect = [page1, page2]
        mock_client.return_value = client

        from e2e.skret_loader import load_namespace

        result = load_namespace("/ns/prod")

    assert result == {"A": "1", "B": "2"}
    assert client.get_parameters_by_path.call_count == 2


def test_load_namespace_required_raises_on_missing() -> None:
    with patch("boto3.client") as mock_client:
        client = MagicMock()
        client.get_parameters_by_path.return_value = {"Parameters": []}
        mock_client.return_value = client

        from e2e.skret_loader import load_namespace_required

        with pytest.raises(KeyError, match="NOTION_INTEGRATION_TOKEN"):
            load_namespace_required(
                "/better-notion-mcp/prod",
                required=["NOTION_INTEGRATION_TOKEN"],
            )


def test_load_namespace_required_treats_optional_as_optional() -> None:
    fake_response = {"Parameters": [{"Name": "/ns/prod/A", "Value": "1"}]}
    with patch("boto3.client") as mock_client:
        client = MagicMock()
        client.get_parameters_by_path.return_value = fake_response
        mock_client.return_value = client

        from e2e.skret_loader import load_namespace_required

        result = load_namespace_required("/ns/prod", required=["A"], optional=["B"])
    assert result == {"A": "1"}
