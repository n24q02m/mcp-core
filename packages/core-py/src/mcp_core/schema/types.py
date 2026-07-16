"""Schema types for relay configuration.

Uses TypedDict for lightweight type definitions matching the TS interfaces.
"""

from typing import TypedDict


class ConfigField(TypedDict, total=False):
    """A single configuration field."""

    key: str
    label: str
    # 'text' | 'password' | 'number' | 'tel' | 'url' | 'email' | 'select'
    # | 'model-chain' | 'search-chain'
    type: str
    placeholder: str
    helpUrl: str
    helpText: str
    default: str
    choices: list[str]
    required: bool
    validation: str
    # --- model-chain / search-chain widget (shared chip+drag+derive-keys UI) ---
    task: str  # 'embedding' | 'rerank' | 'chat' | 'summary' | 'understand' | 'search'
    suggestedModels: list[str]  # model-chain: curated provider/model suggestions;
    # search-chain: the selectable named backends (e.g. ['searxng','tavily',...])
    hasLocal: bool  # True -> empty chain falls back to a local leg
    # --- search-chain widget only (named backends, no model-prefix inference) ---
    providerKeys: dict[str, str]  # backend name -> credential ENV var (drives derive-keys)
    noun: str  # empty-chain badge noun (default 'models'); e.g. 'backends'
    localLabel: str  # empty-chain badge local-leg label (default 'local ONNX')
    # --- derived credential field only ---
    derived: bool  # True -> hidden until a chain chip references its provider


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


class TabGroup(TypedDict, total=False):
    """A credential-form tab (schema-level ``tabs`` capability).

    Each tab is a mutually-exclusive credential mode; only the active tab's
    fields are submitted. See ``render_credential_form`` tabbed path.
    """

    id: str  # required — tab identity, used for the panel id + active selection
    label: str  # required — tab button text
    fields: list[ConfigField]  # required — the tab's own fields


class CardGroup(TypedDict, total=False):
    """A repeatable field group (schema-level ``cardGroup`` capability).

    Renders Add/Remove cards, each cloning ``fields``; submitted as a JSON array
    under ``key`` (e.g. ``{"accounts": [{...}, {...}]}``).
    """

    key: str  # required — submitted payload key holding the card array
    fields: list[ConfigField]  # required — fields cloned into every card
    itemLabel: str  # per-card noun (default 'Item'); e.g. 'Account'
    heading: str  # section heading above the cards (default '<itemLabel>s')
    addButtonLabel: str  # Add-button text (default '+ Add')
    minItems: int  # cards seeded on load + Remove floor (default 1)
    titleField: str  # field key whose value labels each card


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
    # --- schema-level credential-UI capabilities (mutually exclusive with a
    # flat ``fields`` list; see credential_form.render_credential_form) ---
    tabs: list[TabGroup]
    cardGroup: CardGroup
