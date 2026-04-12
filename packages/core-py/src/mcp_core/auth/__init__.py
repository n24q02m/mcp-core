"""MCP Core authentication module."""

from mcp_core.auth.credential_form import render_credential_form
from mcp_core.auth.well_known import authorization_server_metadata, protected_resource_metadata

__all__ = ["render_credential_form", "authorization_server_metadata", "protected_resource_metadata"]
