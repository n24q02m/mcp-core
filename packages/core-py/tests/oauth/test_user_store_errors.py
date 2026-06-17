import os
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from mcp_core.oauth.user_store import SqliteUserStore


@pytest.fixture
def master_key() -> bytes:
    return os.urandom(32)


def test_sqlite_user_store_init_with_directory(tmp_path: Path, master_key: bytes):
    db_dir = tmp_path / "test_dir"
    db_dir.mkdir()
    with pytest.raises(RuntimeError, match="Database path cannot be a directory"):
        SqliteUserStore(db_dir, master_key)


def test_sqlite_user_store_init_with_empty_path(master_key: bytes):
    # Empty path resolves to current directory '.'
    with pytest.raises(RuntimeError, match="Database path cannot be a directory"):
        SqliteUserStore(Path(""), master_key)


def test_sqlite_user_store_init_mkdir_error(tmp_path: Path, master_key: bytes):
    db_path = tmp_path / "sub" / "users.db"

    with patch.object(Path, "mkdir", side_effect=OSError("Permission denied")):
        with pytest.raises(RuntimeError, match="Failed to initialize database"):
            SqliteUserStore(db_path, master_key)


def test_sqlite_user_store_init_db_error(tmp_path: Path, master_key: bytes):
    db_path = tmp_path / "users.db"

    with patch("sqlite3.connect", side_effect=sqlite3.Error("Mocked DB error")):
        with pytest.raises(RuntimeError, match="Failed to initialize database"):
            SqliteUserStore(db_path, master_key)


def test_sqlite_user_store_init_chmod_error(tmp_path: Path, master_key: bytes):
    if os.name == "nt":
        pytest.skip("chmod not enforced on Windows in this implementation")

    db_dir = tmp_path / "secure_dir"
    db_path = db_dir / "users.db"

    with patch("os.chmod", side_effect=OSError("Mocked chmod error")):
        with pytest.raises(RuntimeError, match="Failed to initialize database"):
            SqliteUserStore(db_path, master_key)
