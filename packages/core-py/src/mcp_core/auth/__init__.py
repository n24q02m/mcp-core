"""MCP Core authentication module."""

from mcp_core.auth.bundled_client import (
    BundledClientSpec,
    ResolvedClient,
    resolve_bundled_client,
    token_client_mismatch,
)
from mcp_core.auth.credential_form import render_credential_form
from mcp_core.auth.local_oauth_app import (
    CredentialsCallback,
    StepCallback,
    SubjectContext,
    create_local_oauth_app,
)
from mcp_core.auth.well_known import (
    authorization_server_metadata,
    derive_base_url,
    protected_resource_metadata,
)

__all__ = [
    "BundledClientSpec",
    "ResolvedClient",
    "resolve_bundled_client",
    "token_client_mismatch",
    "CredentialsCallback",
    "StepCallback",
    "SubjectContext",
    "create_local_oauth_app",
    "render_credential_form",
    "authorization_server_metadata",
    "derive_base_url",
    "protected_resource_metadata",
]
