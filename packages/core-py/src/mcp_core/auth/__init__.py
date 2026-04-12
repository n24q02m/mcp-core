"""MCP Core authentication module."""

from mcp_core.auth.credential_form import render_credential_form
from mcp_core.auth.local_oauth_app import create_local_oauth_app
from mcp_core.auth.well_known import authorization_server_metadata, protected_resource_metadata

__all__ = [
    "create_local_oauth_app",
    "render_credential_form",
    "authorization_server_metadata",
    "protected_resource_metadata",
]
