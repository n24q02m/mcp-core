"""Tests for the D7 pre-fill renderer + merge helper.

Covers ``render_field`` (single-field HTML emitter with secret-protection +
oauth_field button rendering) and ``merge_submission`` (form POST handler
that preserves an existing secret when the submitted value is empty).
"""

from mcp_core.auth.local_oauth_app import merge_submission, render_field

SCHEMA_FIELDS = [
    {"name": "BASE_URL", "label": "Base URL", "required": True},
    {"name": "API_KEY", "label": "API Key", "required": True, "secret": True},
    {"name": "REFRESH_TOKEN", "label": "Refresh", "required": False, "oauth_field": True},
]


def test_render_non_secret_with_value():
    html = render_field(SCHEMA_FIELDS[0], current_value="https://api.example.com")
    assert 'value="https://api.example.com"' in html
    assert 'name="BASE_URL"' in html


def test_render_non_secret_empty():
    html = render_field(SCHEMA_FIELDS[0], current_value=None)
    assert 'value=""' in html or "value" not in html.split('name="BASE_URL"')[1].split(">")[0]


def test_render_secret_with_value():
    html = render_field(SCHEMA_FIELDS[1], current_value="sk_live_xxx")
    assert "sk_live_xxx" not in html
    assert "configured" in html.lower()
    assert 'value=""' in html


def test_render_secret_empty():
    html = render_field(SCHEMA_FIELDS[1], current_value=None)
    assert 'placeholder="API Key"' in html or "API Key" in html
    assert 'value=""' in html or "value" not in html.split('name="API_KEY"')[1].split(">")[0]


def test_render_oauth_field_button():
    html = render_field(SCHEMA_FIELDS[2], current_value="rt_xxx")
    assert "rt_xxx" not in html
    assert "Re-authorize" in html or "reauthorize" in html.lower()
    assert 'aria-label="Re-authorize Refresh"' in html


def test_merge_preserves_secret_on_empty():
    current = {"BASE_URL": "old", "API_KEY": "secret-old"}
    submitted = {"BASE_URL": "new", "API_KEY": ""}
    result = merge_submission(current, submitted, SCHEMA_FIELDS)
    assert result["BASE_URL"] == "new"
    assert result["API_KEY"] == "secret-old"


def test_merge_replaces_secret_on_new_value():
    current = {"API_KEY": "old"}
    submitted = {"API_KEY": "new"}
    result = merge_submission(current, submitted, [SCHEMA_FIELDS[1]])
    assert result["API_KEY"] == "new"


def test_merge_replaces_non_secret_on_empty():
    current = {"BASE_URL": "old"}
    submitted = {"BASE_URL": ""}
    result = merge_submission(current, submitted, [SCHEMA_FIELDS[0]])
    assert result["BASE_URL"] == ""
