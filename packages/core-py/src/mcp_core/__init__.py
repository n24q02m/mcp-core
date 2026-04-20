"""Zero-env-config credential relay for MCP servers."""

__version__ = "0.1.0"

from mcp_core.crypto.aes import decrypt, encrypt
from mcp_core.crypto.ecdh import (
    derive_shared_secret,
    export_private_key as export_private_key,
    export_public_key,
    generate_key_pair,
    import_private_key as import_private_key,
    import_public_key,
)
from mcp_core.crypto.kdf import derive_aes_key

# Delegated OAuth 2.1 AS (upstream redirect / device code) for remote multi-user.
from mcp_core.auth.delegated_oauth_app import (
    FlowType,
    TokenCallback,
    UpstreamOAuthConfig,
    create_delegated_oauth_app,
)

# OAuth 2.1 multi-user infrastructure (HTTP mode)
from mcp_core.oauth import (
    InMemoryAuthCache,
    IOAuthSessionCache,
    IUserCredentialStore,
    JWTIssuer,
    OAuthProvider,
    PreAuthSession,
    SqliteUserStore,
)
from mcp_core.relay.browser import try_open_browser
from mcp_core.relay.client import (
    RelaySession,
    create_session,
    generate_passphrase,
    notify_complete,
    poll_for_responses,
    poll_for_result,
    send_message,
)
from mcp_core.storage.config_file import (
    delete_config,
    export_config,
    import_config,
    list_configs,
    read_config,
    schedule_reload_exit,
    write_config,
)
from mcp_core.storage.mode import clear_mode, get_mode, set_local_mode
from mcp_core.storage.resolver import resolve_config
from mcp_core.storage.session_lock import (
    SessionInfo,
    acquire_session_lock,
    release_session_lock,
    write_session_lock,
)

__all__ = [
    "decrypt",
    "derive_aes_key",
    "derive_shared_secret",
    "export_public_key",
    "generate_key_pair",
    "import_public_key",
    "encrypt",
    "RelaySession",
    "create_session",
    "generate_passphrase",
    "notify_complete",
    "poll_for_responses",
    "poll_for_result",
    "send_message",
    "try_open_browser",
    "delete_config",
    "export_config",
    "import_config",
    "list_configs",
    "read_config",
    "schedule_reload_exit",
    "write_config",
    "resolve_config",
    "SessionInfo",
    "acquire_session_lock",
    "write_session_lock",
    "release_session_lock",
    "set_local_mode",
    "get_mode",
    "clear_mode",
    "InMemoryAuthCache",
    "IOAuthSessionCache",
    "IUserCredentialStore",
    "JWTIssuer",
    "OAuthProvider",
    "PreAuthSession",
    "SqliteUserStore",
    "FlowType",
    "TokenCallback",
    "UpstreamOAuthConfig",
    "create_delegated_oauth_app",
]
