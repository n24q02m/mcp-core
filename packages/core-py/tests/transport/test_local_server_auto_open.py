"""Tests for the auto-open browser gate in ``run_local_server``.

The gate uses ``is_schema_complete`` (not the legacy ``existing_config is None``)
so peer-share paths writing partial entries do not suppress the relay form.
These tests exercise the gate logic directly without spinning up a real uvicorn
server (the gate decision is the unit under test, not the HTTP plumbing).
"""

import pytest

from mcp_core.auth.credential_form import is_schema_complete


SCHEMA_REQUIRED_TOKEN = {
    "server": "demo",
    "fields": [
        {"key": "TOKEN", "label": "Token", "required": True},
    ],
}


def test_gate_opens_when_no_config():
    assert is_schema_complete(None, SCHEMA_REQUIRED_TOKEN) is False


def test_gate_skips_when_required_field_present():
    assert is_schema_complete({"TOKEN": "x"}, SCHEMA_REQUIRED_TOKEN) is True


def test_gate_opens_when_peer_shared_keys_do_not_satisfy_schema():
    """Regression for the wet-mcp bug: CRG share-keys writes JINA/GEMINI to
    wet's config.enc, but wet's schema requires GOOGLE_DRIVE_CLIENT_ID. The
    pre-fix gate returned ``existing_config is None`` → False (since some keys
    exist) → no auto-open. The new gate checks schema completeness."""
    schema_with_gdrive = {
        "server": "wet-mcp-like",
        "fields": [
            {"key": "JINA_AI_API_KEY", "label": "Jina", "required": False},
            {"key": "GOOGLE_DRIVE_CLIENT_ID", "label": "GDrive", "required": True},
        ],
    }
    peer_shared = {"JINA_AI_API_KEY": "shared_jina_key_from_crg"}
    assert is_schema_complete(peer_shared, schema_with_gdrive) is False


def test_gate_uses_setup_complete_for_all_optional_schema():
    """For all-optional schemas the only signal of "user submitted" is the
    explicit ``_setup_complete`` flag set by ``mark_setup_complete``."""
    schema_all_optional = {
        "server": "crg-like",
        "fields": [
            {"key": "JINA_AI_API_KEY", "label": "Jina", "required": False},
            {"key": "GEMINI_API_KEY", "label": "Gemini", "required": False},
        ],
    }
    assert is_schema_complete({}, schema_all_optional) is False
    assert is_schema_complete({"_setup_complete": "true"}, schema_all_optional) is True
    assert is_schema_complete({"_setup_complete": "false"}, schema_all_optional) is False
    assert is_schema_complete({"JINA_AI_API_KEY": "k"}, schema_all_optional) is False


def test_gate_falls_back_to_null_check_when_no_schema():
    """Some servers (e.g. godot) have no relay_schema. The gate must still
    work — fall back to ``existing_config is not None``."""

    # In run_local_server, the actual logic is:
    #   config_complete = (
    #       is_schema_complete(existing_config, relay_schema)
    #       if relay_schema is not None
    #       else existing_config is not None
    #   )
    relay_schema = None
    existing_config = None
    config_complete = (
        is_schema_complete(existing_config, relay_schema)
        if relay_schema is not None
        else existing_config is not None
    )
    assert config_complete is False

    existing_config = {"any_key": "any_value"}
    config_complete = (
        is_schema_complete(existing_config, relay_schema)
        if relay_schema is not None
        else existing_config is not None
    )
    assert config_complete is True
