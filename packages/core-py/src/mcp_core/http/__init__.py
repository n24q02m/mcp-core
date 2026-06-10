"""SSRF-safe HTTP utilities (shared primitive — see reuse-mcp-core.md)."""

from mcp_core.http.ssrf import (
    AsyncSSRFSafeTransport,
    SSRFBlockedError,
    get_ssrf_safe_async_client,
    is_multi_user_mode,
    validate_url_and_get_ip,
    vet_api_base,
)

__all__ = [
    "AsyncSSRFSafeTransport",
    "SSRFBlockedError",
    "get_ssrf_safe_async_client",
    "is_multi_user_mode",
    "validate_url_and_get_ip",
    "vet_api_base",
]
