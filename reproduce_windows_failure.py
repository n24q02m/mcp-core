import os
import sqlite3
from pathlib import Path
import pytest
from unittest.mock import patch
from mcp_core.oauth.user_store import SqliteUserStore

def test_failure():
    master_key = os.urandom(32)
    db_path = Path("dir/users.db")

    print("Testing with os.name = 'nt'")
    with patch("os.name", "nt"):
        with patch("pathlib.Path.mkdir") as mock_mkdir:
            # mkdir is still called
            with patch("pathlib.Path.chmod") as mock_chmod:
                mock_chmod.side_effect = PermissionError("Permission denied")
                try:
                    SqliteUserStore(db_path, master_key)
                    print("Success (No error raised)")
                except Exception as e:
                    print(f"Caught exception: {type(e).__name__}: {e}")

if __name__ == "__main__":
    test_failure()
