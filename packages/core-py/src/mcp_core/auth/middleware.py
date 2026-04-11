"""OAuth 2.1 transport middleware for Streamable HTTP servers.

Rejects unauthenticated requests with HTTP 401 + WWW-Authenticate header
per MCP Streamable HTTP 2025-11-25 spec + OAuth 2.1 (RFC 9470).

Allows `/.well-known/*`, `/authorize`, `/token`, `/health` to bypass auth so
clients can discover the authorization server and complete the OAuth dance.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.types import ASGIApp


class OAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: "ASGIApp",
        *,
        resource_metadata_url: str,
        token_verifier: Callable[[str], Awaitable[Any]],
    ) -> None:
        super().__init__(app)
        self._metadata_url = resource_metadata_url
        self._verify = token_verifier
        self.kwargs = {
            "resource_metadata_url": resource_metadata_url,
            "token_verifier": token_verifier,
        }

    async def dispatch(
        self,
        request: "Request",
        call_next: Callable[["Request"], Awaitable["Response"]],
    ) -> "Response":
        path = request.url.path
        if path.startswith(("/.well-known/", "/authorize", "/token", "/health")):
            return await call_next(request)
        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return JSONResponse(
                {
                    "error": "unauthorized",
                    "error_description": "Bearer token required",
                },
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer resource_metadata="{self._metadata_url}"'
                    ),
                },
            )
        token = auth_header.split(" ", 1)[1]
        try:
            principal = await self._verify(token)
        except Exception:
            return JSONResponse(
                {"error": "invalid_token"},
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer error="invalid_token", '
                        f'resource_metadata="{self._metadata_url}"'
                    ),
                },
            )
        request.state.principal = principal
        return await call_next(request)
