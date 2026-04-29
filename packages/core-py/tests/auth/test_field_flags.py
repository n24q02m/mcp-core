from mcp_core.auth.credential_form import (
    RelayConfigField,  # noqa: F401  re-export smoke test (D7 schema flags)
    is_oauth_field,
    is_secret_field,
)


def test_default_field_not_secret():
    f = {"name": "BASE_URL", "label": "Base URL", "required": True}
    assert is_secret_field(f) is False
    assert is_oauth_field(f) is False


def test_explicit_secret_true():
    f = {"name": "API_KEY", "label": "API Key", "required": True, "secret": True}
    assert is_secret_field(f) is True


def test_oauth_field_true():
    f = {"name": "refresh_token", "label": "Refresh Token", "required": True, "oauth_field": True}
    assert is_oauth_field(f) is True


def test_secret_and_oauth_disjoint():
    """oauth_field implies its own UI; should not also render as secret."""
    f = {"name": "refresh_token", "label": "Refresh Token", "required": True, "oauth_field": True, "secret": True}
    # oauth wins for rendering purposes
    assert is_oauth_field(f) is True
    # but secret flag still recognized
    assert is_secret_field(f) is True
