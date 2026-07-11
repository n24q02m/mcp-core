"""Per-plugin encrypted credential store.

Layout:
    Stdio / HTTP single-user: ~/.<plugin>-mcp/config.json
    HTTP multi-user:          ~/.<plugin>-mcp/subs/<sub>/config.json

Encryption:
    Stdio / single-user: AES-GCM with machine-bound key persisted at
        ~/.<plugin>-mcp/.secret (auto-generated, 32 bytes, 0600).
    HTTP multi-user:    AES-GCM with key derived via PBKDF2-HMAC-SHA256
        (600,000 iterations) from env CREDENTIAL_SECRET, salt
        f"{plugin}:{sub}".

Replaces deprecated mcp_core.storage.config_file (shared config.enc) which
caused multi-daemon path-drift contention with platformdirs version skew.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from mcp_core.storage.backends import CredentialBackend, _atomic_write_bytes, backend_from_env

logger = logging.getLogger(__name__)

_UNSAFE_RE = re.compile(r"[^a-zA-Z0-9._-]")


def _cred_path(plugin_name: str, sub: Optional[str]) -> Path:
    # Underscore is allowed because the OAuth AS mints sub = secrets.token_urlsafe(),
    # whose base64url alphabet includes "_" and "-"; rejecting "_" failed ~half of all
    # per-sub credential saves with "Invalid sub". "." stays allowed for version-style
    # segments, so traversal is blocked by the explicit ".." check (the char class
    # alone would let ".." through) plus "/" remaining outside the class.
    if not plugin_name or _UNSAFE_RE.search(plugin_name) or ".." in plugin_name:
        raise ValueError("Invalid plugin_name")
    if sub is not None and (not sub or _UNSAFE_RE.search(sub) or ".." in sub):
        raise ValueError("Invalid sub")

    base = Path.home() / f".{plugin_name}-mcp"
    if sub:
        return base / "subs" / sub / "config.json"
    return base / "config.json"


def _machine_key_path(plugin_name: str) -> Path:
    return Path.home() / f".{plugin_name}-mcp" / ".secret"


def _load_or_generate_machine_key(plugin_name: str) -> bytes:
    secret_path = _machine_key_path(plugin_name)
    if secret_path.exists():
        return secret_path.read_bytes()
    key = secrets.token_bytes(32)
    _atomic_write_bytes(secret_path, key)
    return key


def _derive_multi_user_key(plugin_name: str, sub: str) -> bytes:
    master = os.environ.get("CREDENTIAL_SECRET")
    if not master:
        raise RuntimeError("CREDENTIAL_SECRET env required for HTTP multi-user mode")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=f"{plugin_name}:{sub}".encode("utf-8"),
        iterations=600_000,
    )
    return kdf.derive(master.encode("utf-8"))


class PerPluginStore:
    """Per-plugin encrypted credential store.

    See module docstring for layout and key derivation rules.
    """

    def __init__(
        self,
        plugin_name: str,
        sub: Optional[str] = None,
        backend: Optional[CredentialBackend] = None,
        sub_key: Optional[str] = None,
    ) -> None:
        self.plugin_name = plugin_name
        self.sub = sub
        self.sub_key = sub_key
        self.cred_path = _cred_path(plugin_name, sub)
        leaf = sub_key or "config"
        self.cred_key = f"{plugin_name}/subs/{sub}/{leaf}" if sub else f"{plugin_name}/{leaf}"
        self._backend = backend if backend is not None else backend_from_env()

    def _key(self) -> bytes:
        if self.sub:
            return _derive_multi_user_key(self.plugin_name, self.sub)
        return _load_or_generate_machine_key(self.plugin_name)

    def load(self) -> Optional[dict]:
        blob = self._backend.get(self.cred_key)
        if blob is None:
            return None
        if len(blob) < 13:
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.error(
                "Credential blob for %s is corrupt or the encryption key changed; "
                "treating as not configured (re-run setup to restore)",
                self.cred_key,
            )
            return None
        nonce, ciphertext = blob[:12], blob[12:]
        aesgcm = AESGCM(self._key())
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.error(
                "Credential blob for %s is corrupt or the encryption key changed; "
                "treating as not configured (re-run setup to restore)",
                self.cred_key,
            )
            return None
        return json.loads(plaintext)

    def save(self, payload: dict) -> None:
        plaintext = json.dumps(payload).encode("utf-8")
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self._key())
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        self._backend.put(self.cred_key, nonce + ciphertext)

    def clear(self) -> None:
        self._backend.delete(self.cred_key)
