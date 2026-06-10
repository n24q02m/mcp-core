import os
import sqlite3
from pathlib import Path
from mcp_core.oauth.user_store import SqliteUserStore

master_key = os.urandom(32)

print("--- Test 1: db_path is a directory ---")
db_dir = Path("test_dir")
db_dir.mkdir(exist_ok=True)
try:
    store = SqliteUserStore(db_dir, master_key)
except Exception as e:
    print(f"Caught expected exception: {type(e).__name__}: {e}")

print("\n--- Test 2: db_path in read-only directory ---")
ro_dir = Path("ro_dir")
ro_dir.mkdir(exist_ok=True)
db_path = ro_dir / "users.db"
# Make directory read-only
ro_dir.chmod(0o500)
try:
    store = SqliteUserStore(db_path, master_key)
except Exception as e:
    print(f"Caught expected exception: {type(e).__name__}: {e}")
finally:
    ro_dir.chmod(0o700)
    ro_dir.rmdir()
    if db_dir.exists():
        db_dir.rmdir()
