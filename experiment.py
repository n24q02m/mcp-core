import sqlite3
import os
import shutil
from pathlib import Path
from mcp_core.oauth.user_store import SqliteUserStore

master_key = os.urandom(32)

def cleanup():
    for d in ["test_file"]:
        p = Path(d)
        if p.exists():
            p.unlink()

cleanup()

print("--- Testing path where parent is a file ---")
parent_file = Path("test_file")
parent_file.touch()
db_path = parent_file / "users.db"
try:
    SqliteUserStore(db_path, master_key)
except Exception as e:
    print(f"Caught {type(e).__name__}: {e}")
finally:
    cleanup()
