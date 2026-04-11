"""Per-user encrypted credential store for MCP HTTP modes."""

import json
import os
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class IUserCredentialStore(ABC):
    @abstractmethod
    def save_credentials(self, user_id: str, config: dict) -> None:
        pass

    @abstractmethod
    def get_credentials(self, user_id: str) -> dict | None:
        pass

    @abstractmethod
    def delete_credentials(self, user_id: str) -> None:
        pass


class SqliteUserStore(IUserCredentialStore):
    def __init__(self, db_path: Path, master_key: bytes):
        """
        Args:
            db_path: Path to the SQLite DB file.
            master_key: 32-byte AES key for at-rest encryption.
        """
        self.db_path = db_path
        self._master_key = master_key

        # Ensure directory exists with strict permissions (owner-only access).
        # 0o700 = owner read+write+exec only; group/other denied. This is the
        # secure default for a credential store directory.
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if self.db_path.parent.exists() and os.name != "nt":
            self.db_path.parent.chmod(0o700)

        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    encrypted_config BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )

    def _encrypt(self, plaintext: str) -> bytes:
        iv = os.urandom(12)
        aesgcm = AESGCM(self._master_key)
        # return IV + combined(ciphertext+tag)
        combined = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
        return iv + combined

    def _decrypt(self, payload: bytes) -> str:
        iv = payload[:12]
        combined = payload[12:]
        aesgcm = AESGCM(self._master_key)
        plaintext_bytes = aesgcm.decrypt(iv, combined, None)
        return plaintext_bytes.decode("utf-8")

    def save_credentials(self, user_id: str, config: dict) -> None:
        import time

        now = int(time.time())
        json_str = json.dumps(config)
        encrypted = self._encrypt(json_str)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (user_id, encrypted_config, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    encrypted_config=excluded.encrypted_config,
                    updated_at=excluded.updated_at
                """,
                (user_id, encrypted, now, now),
            )

    def get_credentials(self, user_id: str) -> dict | None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT encrypted_config FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()

        if not row:
            return None

        try:
            json_str = self._decrypt(row[0])
            return json.loads(json_str)
        except Exception:
            return None

    def delete_credentials(self, user_id: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
