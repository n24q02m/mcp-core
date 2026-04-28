import pytest
from mcp_core.auth.credential_form import is_schema_complete


SCHEMA_2_REQUIRED_1_OPTIONAL = {
    "server": "demo",
    "fields": [
        {"name": "API_KEY", "label": "API Key", "required": True},
        {"name": "BASE_URL", "label": "Base URL", "required": True},
        {"name": "TIMEOUT", "label": "Timeout", "required": False},
    ],
}

SCHEMA_ALL_OPTIONAL = {
    "server": "demo-optional",
    "fields": [
        {"name": "OPT_A", "label": "Opt A", "required": False},
        {"name": "OPT_B", "label": "Opt B", "required": False},
    ],
}


def test_none_config_is_incomplete():
    assert is_schema_complete(None, SCHEMA_2_REQUIRED_1_OPTIONAL) is False


def test_empty_config_is_incomplete():
    assert is_schema_complete({}, SCHEMA_2_REQUIRED_1_OPTIONAL) is False


def test_partial_required_is_incomplete():
    assert is_schema_complete({"API_KEY": "k"}, SCHEMA_2_REQUIRED_1_OPTIONAL) is False


def test_all_required_present_is_complete():
    config = {"API_KEY": "k", "BASE_URL": "https://x"}
    assert is_schema_complete(config, SCHEMA_2_REQUIRED_1_OPTIONAL) is True


def test_required_present_optional_missing_is_complete():
    config = {"API_KEY": "k", "BASE_URL": "https://x"}
    assert is_schema_complete(config, SCHEMA_2_REQUIRED_1_OPTIONAL) is True


def test_required_present_with_empty_string_is_incomplete():
    config = {"API_KEY": "k", "BASE_URL": ""}
    assert is_schema_complete(config, SCHEMA_2_REQUIRED_1_OPTIONAL) is False


def test_all_optional_schema_with_setup_complete_flag_true_is_complete():
    config = {"_setup_complete": True}
    assert is_schema_complete(config, SCHEMA_ALL_OPTIONAL) is True


def test_all_optional_schema_without_flag_is_incomplete():
    assert is_schema_complete({}, SCHEMA_ALL_OPTIONAL) is False


def test_all_optional_schema_with_flag_false_is_incomplete():
    assert is_schema_complete({"_setup_complete": False}, SCHEMA_ALL_OPTIONAL) is False
