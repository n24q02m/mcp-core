"""Tests for OAuthMiddleware (Task C3).

Uses `starlette.testclient.TestClient` + a minimal Starlette app that wraps
a single protected route with `OAuthMiddleware`, and a real `JWTIssuer`
keyed off a pytest `tmp_path` so each test is hermetic.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mcp_core.oauth.jwt_issuer import JWTIssuer
from mcp_core.transport.oauth_middleware import OAuthMiddleware

RESOURCE_METADATA_URL = "https://example.invalid/.well-known/oauth-protected-resource"


async def _protected_route(request: Request) -> JSONResponse:
    """Echo the validated claims so tests can assert on `request.state.user`."""
    user = getattr(request.state, "user", None)
    return JSONResponse({"user": user})


def _build_app(jwt_issuer: JWTIssuer) -> Starlette:
    return Starlette(
        routes=[Route("/test", _protected_route)],
        middleware=[
            Middleware(
                OAuthMiddleware,
                jwt_issuer=jwt_issuer,
                resource_metadata_url=RESOURCE_METADATA_URL,
            )
        ],
    )


@pytest.fixture
def jwt_issuer(tmp_path: Path) -> JWTIssuer:
    return JWTIssuer(server_name="test", keys_dir=tmp_path / "jwt-keys")


@pytest.fixture
def client(jwt_issuer: JWTIssuer) -> TestClient:
    return TestClient(_build_app(jwt_issuer))


def test_missing_token_returns_401(client: TestClient) -> None:
    response = client.get("/test")
    assert response.status_code == 401
    www_auth = response.headers.get("www-authenticate", "")
    assert "Bearer" in www_auth
    assert "resource_metadata=" in www_auth
    assert RESOURCE_METADATA_URL in www_auth


def test_invalid_token_returns_401_invalid_token(client: TestClient) -> None:
    response = client.get(
        "/test",
        headers={"Authorization": "Bearer invalid.jwt.token"},
    )
    assert response.status_code == 401
    www_auth = response.headers.get("www-authenticate", "")
    assert 'error="invalid_token"' in www_auth
    assert "resource_metadata=" in www_auth


def test_valid_token_proceeds_to_200(jwt_issuer: JWTIssuer, client: TestClient) -> None:
    token = jwt_issuer.issue_access_token(sub="user-123")
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["user"] is not None
    assert body["user"]["sub"] == "user-123"
    assert body["user"]["iss"] == "test"
    assert body["user"]["aud"] == "test"


def test_bearer_scheme_case_insensitive(jwt_issuer: JWTIssuer, client: TestClient) -> None:
    token = jwt_issuer.issue_access_token(sub="user-456")
    response = client.get(
        "/test",
        headers={"Authorization": f"bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["user"]["sub"] == "user-456"
