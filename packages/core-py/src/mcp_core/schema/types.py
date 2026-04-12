"""Schema types for relay configuration.

Uses TypedDict for lightweight type definitions matching the TS interfaces.
"""

from typing import TypedDict


class ConfigField(TypedDict, total=False):
    """A single configuration field."""

    key: str
    label: str
    type: str  # 'text' | 'password' | 'number' | 'tel' | 'url' | 'email' | 'select'
    placeholder: str
    helpUrl: str
    helpText: str
    default: str
    choices: list[str]
    required: bool
    validation: str


class ConfigMode(TypedDict):
    """A configuration mode (e.g., Bot Token vs User Token)."""

    id: str
    label: str
    description: str
    fields: list[ConfigField]


class OAuthRoute(TypedDict):
    """OAuth2 device code route."""

    match: list[str]
    action: str  # 'oauth2_device_code'
    message: str
    oauthConfig: dict[str, object]


class CredentialsRoute(TypedDict):
    """Credentials route."""

    match: list[str]
    action: str  # 'credentials'
    fields: list[ConfigField]


class DynamicFlow(TypedDict):
    """Dynamic flow with entry field and routes."""

    entryField: ConfigField
    routes: list[OAuthRoute | CredentialsRoute]


class CapabilityInfo(TypedDict, total=False):
    """A single capability description shown on the credential form."""

    label: str
    priority: str  # 'high' | 'medium' | 'low'
    description: str


class RelayConfigSchema(TypedDict, total=False):
    """Top-level relay configuration schema."""

    server: str
    displayName: str
    description: str
    modes: list[ConfigMode]
    fields: list[ConfigField]
    optional: list[ConfigField]
    dynamicFlow: DynamicFlow
    capabilityInfo: list[CapabilityInfo]
