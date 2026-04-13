"""Encrypted config file management.

Reads/writes ~/.config/mcp/config.enc with the same format as the TS version.
"""

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from platformdirs import user_config_dir

from mcp_core.storage.encryption import (
    LEGACY_PBKDF2_ITERATIONS,
    PBKDF2_ITERATIONS,
    decrypt_data,
    derive_file_key,
    derive_passphrase_key,
    encrypt_data,
)
from mcp_core.storage.machine_id import get_machine_id, get_username

_DEFAULT_CONFIG_PATH = Path(user_config_dir("mcp", appauthor=False)) / "config.enc"
_MAX_RETRIES = 3
_BASE_DELAY_S = 0.1

# Allow overriding config path for testing
_config_path_override: str | None = None


def set_config_path(path: str | None) -> None:
    """Override config file path (for testing). Pass None to reset."""
    global _config_path_override
    _config_path_override = path


def _get_config_path() -> Path:
    if _config_path_override is not None:
        return Path(_config_path_override)
    return _DEFAULT_CONFIG_PATH


# Cache the derived file key to avoid expensive PBKDF2 iterations on every config read/write.
# This significantly speeds up successive configuration accesses within the same process.
_cached_key: bytes | None = None


def clear_key_cache_for_testing() -> None:
    """Clear the cached key for testing."""
    global _cached_key
    _cached_key = None


def _get_key() -> bytes:
    global _cached_key
    if _cached_key is not None:
        return _cached_key
    machine_id = get_machine_id()
    username = get_username()
    _cached_key = derive_file_key(machine_id, username)
    return _cached_key


def _with_retry(fn: Any) -> Any:
    """Retry function on file busy errors."""
    for attempt in range(_MAX_RETRIES):
        try:
            return fn()
        except OSError as err:
            is_busy = getattr(err, "errno", None) in (11, 16, 35)  # EAGAIN, EBUSY, etc
            if not is_busy or attempt == _MAX_RETRIES - 1:
                raise
            time.sleep(_BASE_DELAY_S * (2**attempt))
    msg = "Unreachable"
    raise RuntimeError(msg)


def _load_store() -> dict[str, Any]:
    config_path = _get_config_path()
    if not config_path.exists():
        return {"version": 1, "servers": {}}

    machine_id = get_machine_id()
    username = get_username()
    data = config_path.read_bytes()

    try:
        key = derive_file_key(machine_id, username, PBKDF2_ITERATIONS)
        json_str = decrypt_data(key, data)
        return json.loads(json_str)
    except Exception as err:
        try:
            legacy_key = derive_file_key(machine_id, username, LEGACY_PBKDF2_ITERATIONS)
            json_str = decrypt_data(legacy_key, data)
            store = json.loads(json_str)
            # Auto-migrate to current iterations
            _save_store(store)
            return store
        except Exception:
            raise err from None


def _save_store(store: dict[str, Any]) -> None:
    config_path = _get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    key = _get_key()
    encrypted = encrypt_data(key, json.dumps(store))

    def _write() -> None:
        config_path.write_bytes(encrypted)

    _with_retry(_write)


def schedule_reload_exit() -> None:
    """Schedule a process exit so an MCP client can respawn the server and pick
    up fresh credentials from disk.

    Only relevant for stdio-mode servers whose client supervises restart. HTTP-
    mode servers update credentials in-process and MUST NOT call this — an exit
    mid-OAuth-device-code flow kills the user's verification window. Skipped
    under pytest (PYTEST_CURRENT_TEST) and when MCP_NO_RELOAD is set.
    """
    if "PYTEST_CURRENT_TEST" not in os.environ and "MCP_NO_RELOAD" not in os.environ:

        def _exit() -> None:
            time.sleep(1.0)
            os._exit(0)

        threading.Thread(target=_exit, daemon=True).start()


def read_config(server_name: str) -> dict[str, str] | None:
    """Read config for a server.

    Args:
        server_name: Server identifier.

    Returns:
        Config dict or None if not found.
    """
    store = _load_store()
    return store["servers"].get(server_name)


def write_config(server_name: str, config: dict[str, str]) -> None:
    """Write config for a server (merges with existing servers).

    Args:
        server_name: Server identifier.
        config: Key-value config dict.
    """
    store = _load_store()
    store["servers"][server_name] = config
    _save_store(store)


def delete_config(server_name: str) -> None:
    """Delete config for a server.

    Removes the config file entirely if no servers remain.

    Args:
        server_name: Server identifier.
    """
    store = _load_store()
    store["servers"].pop(server_name, None)

    config_path = _get_config_path()
    if not store["servers"]:
        if config_path.exists():
            config_path.unlink()
    else:
        _save_store(store)


def list_configs() -> list[str]:
    """List all configured server names.

    Returns:
        List of server name strings.
    """
    store = _load_store()
    return list(store["servers"].keys())


def export_config(passphrase: str) -> bytes:
    """Export all configs encrypted with a passphrase.

    Args:
        passphrase: Passphrase to encrypt export data.

    Returns:
        Encrypted bytes.
    """
    store = _load_store()
    key = derive_passphrase_key(passphrase)
    return encrypt_data(key, json.dumps(store))


def import_config(passphrase: str, data: bytes) -> None:
    """Import configs from encrypted export data, merging into local config.

    Args:
        passphrase: Passphrase to decrypt import data.
        data: Encrypted bytes from export_config.

    Raises:
        cryptography.exceptions.InvalidTag: If passphrase is wrong.
    """
    try:
        key = derive_passphrase_key(passphrase, PBKDF2_ITERATIONS)
        json_str = decrypt_data(key, data)
    except Exception as err:
        try:
            legacy_key = derive_passphrase_key(passphrase, LEGACY_PBKDF2_ITERATIONS)
            json_str = decrypt_data(legacy_key, data)
        except Exception:
            raise err from None
    imported = json.loads(json_str)

    store = _load_store()
    for name, config in imported["servers"].items():
        store["servers"][name] = config
    _save_store(store)
