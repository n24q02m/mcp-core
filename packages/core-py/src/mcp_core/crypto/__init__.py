"""Cryptographic primitives for mcp-core.

Migrated from mcp-relay-core (now archived). Provides:

- aes: AES-256-GCM primitives (encrypt, decrypt)
- ecdh: ECDH P-256 key exchange (key pairs, shared secret)
- kdf: HKDF-SHA256 key derivation
- encryption: PBKDF2-based AES-256-GCM file encryption
- machine_id: cross-platform machine ID + username detection
- config_file: encrypted ~/.config/mcp/config.enc reader/writer
- session_lock: file-based session lock to prevent duplicate relay sessions
- mode: server mode marker (local vs configured)
- resolver: env -> file -> defaults config resolution
"""

from mcp_core.crypto.aes import decrypt, encrypt
from mcp_core.crypto.config_file import (
    delete_config,
    export_config,
    import_config,
    list_configs,
    read_config,
    set_config_path,
    write_config,
)
from mcp_core.crypto.ecdh import (
    derive_shared_secret,
    export_private_key,
    export_public_key,
    generate_key_pair,
    import_private_key,
    import_public_key,
)
from mcp_core.crypto.encryption import (
    LEGACY_PBKDF2_ITERATIONS,
    PBKDF2_ITERATIONS,
    decrypt_data,
    derive_file_key,
    derive_passphrase_key,
    encrypt_data,
)
from mcp_core.crypto.kdf import derive_aes_key
from mcp_core.crypto.machine_id import get_machine_id, get_username
from mcp_core.crypto.mode import ServerMode, clear_mode, get_mode, set_local_mode
from mcp_core.crypto.resolver import ConfigSource, ResolvedConfig, resolve_config
from mcp_core.crypto.session_lock import (
    SessionInfo,
    acquire_session_lock,
    release_session_lock,
    set_lock_dir,
    write_session_lock,
)

__all__ = [
    # aes
    "decrypt",
    "encrypt",
    # ecdh
    "derive_shared_secret",
    "export_private_key",
    "export_public_key",
    "generate_key_pair",
    "import_private_key",
    "import_public_key",
    # kdf
    "derive_aes_key",
    # encryption
    "LEGACY_PBKDF2_ITERATIONS",
    "PBKDF2_ITERATIONS",
    "decrypt_data",
    "derive_file_key",
    "derive_passphrase_key",
    "encrypt_data",
    # machine_id
    "get_machine_id",
    "get_username",
    # config_file
    "delete_config",
    "export_config",
    "import_config",
    "list_configs",
    "read_config",
    "set_config_path",
    "write_config",
    # mode
    "ServerMode",
    "clear_mode",
    "get_mode",
    "set_local_mode",
    # resolver
    "ConfigSource",
    "ResolvedConfig",
    "resolve_config",
    # session_lock
    "SessionInfo",
    "acquire_session_lock",
    "release_session_lock",
    "set_lock_dir",
    "write_session_lock",
]
