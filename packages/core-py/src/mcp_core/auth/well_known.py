"""OAuth 2.1 well-known metadata generators (RFC 8414 + RFC 9728)."""

from __future__ import annotations


def authorization_server_metadata(issuer_url: str) -> dict:
    """RFC 8414 OAuth Authorization Server Metadata."""
    return {
        "issuer": issuer_url,
        "authorization_endpoint": f"{issuer_url}/authorize",
        "token_endpoint": f"{issuer_url}/token",
        "registration_endpoint": f"{issuer_url}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
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
