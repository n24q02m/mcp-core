import os
import sqlite3
from pathlib import Path
import pytest
from mcp_core.oauth.user_store import SqliteUserStore
from unittest.mock import patch


@pytest.fixture
def master_key() -> bytes:
    return os.urandom(32)


def test_sqlite_user_store_init_is_directory(tmp_path: Path, master_key: bytes):
    db_path = tmp_path / "is_a_dir"
    db_path.mkdir()
    with pytest.raises(ValueError, match="db_path must be a file"):
        SqliteUserStore(db_path, master_key)


def test_sqlite_user_store_init_empty_path(master_key: bytes):
    db_path = Path("")
    # Path("") is "." which is a directory
    with pytest.raises(ValueError, match="db_path must be a file"):
        SqliteUserStore(db_path, master_key)


def test_sqlite_user_store_init_chmod_failure(tmp_path: Path, master_key: bytes):
    db_path = tmp_path / "dir" / "users.db"
    with patch("pathlib.Path.chmod") as mock_chmod:
        mock_chmod.side_effect = PermissionError("Permission denied")
        with pytest.raises(RuntimeError, match="Failed to create or set permissions"):
            SqliteUserStore(db_path, master_key)


def test_sqlite_user_store_init_mkdir_failure(tmp_path: Path, master_key: bytes):
    db_path = tmp_path / "dir" / "users.db"
    with patch("pathlib.Path.mkdir") as mock_mkdir:
        mock_mkdir.side_effect = PermissionError("Permission denied")
        with pytest.raises(RuntimeError, match="Failed to create or set permissions"):
            SqliteUserStore(db_path, master_key)


def test_sqlite_user_store_init_db_error(tmp_path: Path, master_key: bytes):
    db_path = tmp_path / "users.db"
    with patch("sqlite3.connect") as mock_connect:
        mock_connect.side_effect = sqlite3.Error("Mocked DB error")
        with pytest.raises(RuntimeError, match="Failed to initialize user store database"):
            SqliteUserStore(db_path, master_key)
