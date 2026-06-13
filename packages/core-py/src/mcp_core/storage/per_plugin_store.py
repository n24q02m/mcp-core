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
import os
import re
import secrets
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from mcp_core.storage.backends import CredentialBackend, LocalFsBackend


def _cred_path(plugin_name: str, sub: Optional[str]) -> Path:
    unsafe = re.compile(r"[^a-zA-Z0-9.-]")
    if not plugin_name or unsafe.search(plugin_name):
        raise ValueError("Invalid plugin_name")
    if sub is not None and (not sub or unsafe.search(sub)):
        raise ValueError("Invalid sub")

    base = Path.home() / f".{plugin_name}-mcp"
    if sub:
        return base / "subs" / sub / "config.json"
    return base / "config.json"


def _machine_key_path(plugin_name: str) -> Path:
    return Path.home() / f".{plugin_name}-mcp" / ".secret"


def _load_or_generate_machine_key(plugin_name: str) -> bytes:
    secret_path = _machine_key_path(plugin_name)
    secret_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if secret_path.exists():
        return secret_path.read_bytes()
    key = secrets.token_bytes(32)
    secret_path.write_bytes(key)
    if os.name != "nt":
        os.chmod(secret_path, 0o600)
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
    ) -> None:
        self.plugin_name = plugin_name
        self.sub = sub
        self.cred_path = _cred_path(plugin_name, sub)
        self.cred_key = f"{plugin_name}/subs/{sub}/config" if sub else f"{plugin_name}/config"
        self._backend = backend if backend is not None else LocalFsBackend()

    def _key(self) -> bytes:
        if self.sub:
            return _derive_multi_user_key(self.plugin_name, self.sub)
        return _load_or_generate_machine_key(self.plugin_name)

    def load(self) -> Optional[dict]:
        blob = self._backend.get(self.cred_key)
        if blob is None:
            return None
        if len(blob) < 13:
            return None
        nonce, ciphertext = blob[:12], blob[12:]
        aesgcm = AESGCM(self._key())
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
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
