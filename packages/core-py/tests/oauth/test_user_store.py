import os
import sqlite3
from pathlib import Path

import pytest
from mcp_core.oauth.user_store import SqliteUserStore


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test_users.db"


@pytest.fixture
def master_key() -> bytes:
    return os.urandom(32)


def test_sqlite_user_store_init_valid_key(db_path: Path, master_key: bytes):
    store = SqliteUserStore(db_path, master_key)
    assert store.db_path == db_path
    assert store._master_key == master_key
    assert db_path.exists()


def test_sqlite_user_store_init_invalid_key(db_path: Path):
    with pytest.raises(ValueError, match="master_key must be exactly 32 bytes"):
        SqliteUserStore(db_path, os.urandom(31))
    with pytest.raises(ValueError, match="master_key must be exactly 32 bytes"):
        SqliteUserStore(db_path, os.urandom(33))


def test_sqlite_user_store_directory_permissions(tmp_path: Path, master_key: bytes):
    db_dir = tmp_path / "secure_dir"
    db_path = db_dir / "users.db"
    SqliteUserStore(db_path, master_key)

    if os.name != "nt":
        # Check that permissions are 0o700 (drwx------)
        assert (db_dir.stat().st_mode & 0o777) == 0o700


def test_sqlite_user_store_save_and_get(db_path: Path, master_key: bytes):
    store = SqliteUserStore(db_path, master_key)
    user_id = "user123"
    config = {"key": "value", "nested": {"a": 1}}

    store.save_credentials(user_id, config)
    retrieved = store.get_credentials(user_id)

    assert retrieved == config


def test_sqlite_user_store_update_credentials(db_path: Path, master_key: bytes):
    store = SqliteUserStore(db_path, master_key)
    user_id = "user123"
    config1 = {"v": 1}
    config2 = {"v": 2}

    store.save_credentials(user_id, config1)
    store.save_credentials(user_id, config2)
    retrieved = store.get_credentials(user_id)

    assert retrieved == config2


def test_sqlite_user_store_get_non_existent(db_path: Path, master_key: bytes):
    store = SqliteUserStore(db_path, master_key)
    assert store.get_credentials("unknown") is None


def test_sqlite_user_store_delete_credentials(db_path: Path, master_key: bytes):
    store = SqliteUserStore(db_path, master_key)
    user_id = "user123"
    store.save_credentials(user_id, {"v": 1})
    assert store.get_credentials(user_id) is not None

    store.delete_credentials(user_id)
    assert store.get_credentials(user_id) is None


def test_sqlite_user_store_decryption_failure(db_path: Path, master_key: bytes):
    store = SqliteUserStore(db_path, master_key)
    user_id = "user123"
    store.save_credentials(user_id, {"v": 1})

    # Create a new store with a different key for the same DB
    different_key = os.urandom(32)
    store2 = SqliteUserStore(db_path, different_key)

    # Decryption should fail and return None
    assert store2.get_credentials(user_id) is None


def test_sqlite_user_store_corrupt_payload(db_path: Path, master_key: bytes):
    store = SqliteUserStore(db_path, master_key)
    user_id = "user123"
    store.save_credentials(user_id, {"v": 1})

    # Manually corrupt the data in the DB
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE users SET encrypted_config = ?", (b"invalid_data",))

    assert store.get_credentials(user_id) is None
