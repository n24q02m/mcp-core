"""Bundled OAuth/API client identity resolution (BYO override chain).

Precedence, top to bottom:
    1. CLI flag pair   (validated: both-or-neither when the provider needs a secret)
    2. Env var pair    (same validation)
    3. Bundled default (public-by-design identifiers), unless disabled via
       the USE_BUNDLED_* kill-switch env var -> fail loud.

The bundled identifiers shipped by the servers (Google Desktop OAuth client,
Microsoft public client, Telegram api_id/api_hash) are public by design; BYO
exists for quota isolation and org policy, not because the defaults leaked.

An OAuth refresh_token is bound to the client_id that minted it. Refreshing
with a different client's secret sends the provider a pair that never
existed (invalid_client) surfaced as an auth error, so callers MUST check
token_client_mismatch() and clear the stored token when it returns True.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal, Optional

_FALSEY = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True)
class BundledClientSpec:
    """Declares one provider's client-identity sources."""

    provider: str
    env_id: str
    env_secret: str
    bundled_id: str
    bundled_secret: str
    use_bundled_env: str
    requires_secret: bool = True


@dataclass(frozen=True)
class ResolvedClient:
    """Effective client identity plus which layer supplied it."""

    client_id: str
    client_secret: str
    source: Literal["cli", "env", "bundled"]


def _validated_pair(spec: BundledClientSpec, cid: str, secret: str, origin: str) -> Optional[tuple[str, str]]:
    if secret and not cid:
        raise ValueError(f"{spec.provider}: {origin} secret was given without an id; set both together")
    if cid and spec.requires_secret and not secret:
        raise ValueError(f"{spec.provider}: {origin} id and secret must be set together")
    if cid:
        return (cid, secret)
    return None


def resolve_bundled_client(
    spec: BundledClientSpec,
    cli_id: Optional[str] = None,
    cli_secret: Optional[str] = None,
) -> ResolvedClient:
    """Resolve the effective client identity for one provider."""
    pair = _validated_pair(spec, cli_id or "", cli_secret or "", "--client-id/--client-secret")
    if pair is not None:
        return ResolvedClient(pair[0], pair[1], "cli")

    pair = _validated_pair(
        spec,
        os.environ.get(spec.env_id, ""),
        os.environ.get(spec.env_secret, ""),
        f"{spec.env_id}/{spec.env_secret}",
    )
    if pair is not None:
        return ResolvedClient(pair[0], pair[1], "env")

    if os.environ.get(spec.use_bundled_env, "").strip().lower() in _FALSEY:
        raise RuntimeError(
            f"{spec.provider}: {spec.use_bundled_env} disables the bundled client and no override "
            f"was provided; set {spec.env_id}/{spec.env_secret} or pass --client-id/--client-secret"
        )
    return ResolvedClient(spec.bundled_id, spec.bundled_secret, "bundled")


def token_client_mismatch(token: Optional[dict], effective_client_id: str) -> bool:
    """True when a stored OAuth token was minted by a different client_id.

    A token that never recorded its client_id is treated as mismatched:
    one clean re-auth is cheaper than a mixed id/secret pair that surfaces
    as an unfixable auth error.
    """
    if token is None:
        return False
    return token.get("client_id") != effective_client_id
