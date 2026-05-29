"""OAuth 2.1 well-known metadata generators (RFC 8414 + RFC 9728)."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.requests import Request


def derive_base_url(request: Request) -> str:
    """Derive the public base URL from the request.

    Resolution order:
    1. ``PUBLIC_URL`` env var -- trusted, explicit. This is the
       remote-deploy convention (oci-vm-prod) where the container sits
       behind CF Tunnel -> Caddy (HTTP internal) but is served to clients
       over HTTPS. Starlette's ``request.base_url`` reflects the scheme
       the ASGI server saw (HTTP from the proxy), so without this override
       OAuth 2.1 metadata would leak ``http://`` as the issuer and strict
       clients reject the discovery document.
    2. Starlette ``request.base_url`` -- uses ``X-Forwarded-Proto`` /
       ``X-Forwarded-Host`` when ``ProxyHeadersMiddleware`` is mounted,
       otherwise the raw socket scheme.
    """
    public_url = os.environ.get("PUBLIC_URL")
    if public_url:
        return public_url.rstrip("/")
    return str(request.base_url).rstrip("/")


def authorization_server_metadata(issuer_url: str) -> dict:
    """RFC 8414 OAuth Authorization Server Metadata."""
    return {
        "issuer": issuer_url,
        "authorization_endpoint": f"{issuer_url}/authorize",
        "token_endpoint": f"{issuer_url}/token",
        "registration_endpoint": f"{issuer_url}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["offline_access"],
    }


def protected_resource_metadata(
    resource: str,
    authorization_servers: list[str],
) -> dict:
    """RFC 9728 OAuth Protected Resource Metadata."""
    return {
        "resource": resource,
        "authorization_servers": authorization_servers,
        "bearer_methods_supported": ["header"],
    }
