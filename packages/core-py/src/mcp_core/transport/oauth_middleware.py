"""OAuth 2.1 Bearer token middleware for MCP Streamable HTTP transport.

Validates `Authorization: Bearer <jwt>` headers against a `JWTIssuer`. On
failure, responds with HTTP 401 and an RFC 6750 / OAuth 2.1 compliant
`WWW-Authenticate` header that advertises the protected resource metadata
URL (per RFC 9728 "OAuth 2.0 Protected Resource Metadata").

On success, the decoded claims are attached to `request.state.user` so
downstream tool handlers can consume the caller identity without repeating
credential validation. No tool-level credential checks are required.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import jwt as pyjwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.types import ASGIApp

    from mcp_core.oauth.jwt_issuer import JWTIssuer


class OAuthMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that validates OAuth 2.1 Bearer access tokens.

    Accepts a `JWTIssuer` (not a full OAuthProvider) for loose coupling -- the
    transport layer only cares about token verification, not issuance or
    relay flows. On missing / invalid / expired token, returns 401 with the
    RFC 6750 Bearer challenge pointing at the protected resource metadata URL.
    """

    def __init__(
        self,
        app: ASGIApp,
        jwt_issuer: JWTIssuer,
        *,
        resource_metadata_url: str,
    ) -> None:
        super().__init__(app)
        self._jwt_issuer = jwt_issuer
        self._resource_metadata_url = resource_metadata_url

    @property
    def jwt_issuer(self) -> JWTIssuer:
        return self._jwt_issuer

    @property
    def resource_metadata_url(self) -> str:
        return self._resource_metadata_url

    def _challenge_header(self, error: str | None = None) -> dict[str, str]:
        """Build the WWW-Authenticate header value.

        Per RFC 6750 section 3, the Bearer challenge carries optional
        auth-params including `error` and the `resource_metadata` extension
        from RFC 9728.
        """
        parts = [f'Bearer resource_metadata="{self._resource_metadata_url}"']
        if error:
            parts.append(f'error="{error}"')
        return {"WWW-Authenticate": ", ".join(parts)}

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        auth_header = request.headers.get("authorization")
        if not auth_header:
            return Response(status_code=401, headers=self._challenge_header())

        # RFC 6750 section 2.1: the auth scheme name is case-insensitive.
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return Response(
                status_code=401,
                headers=self._challenge_header(error="invalid_token"),
            )

        try:
            claims = self._jwt_issuer.verify_access_token(token.strip())
        except pyjwt.PyJWTError:
            return Response(
                status_code=401,
                headers=self._challenge_header(error="invalid_token"),
            )

        request.state.user = claims
        return await call_next(request)
