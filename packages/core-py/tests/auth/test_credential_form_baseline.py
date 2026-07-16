"""Backward-compat guard for the flat credential form.

Schemas that declare neither ``tabs`` nor ``cardGroup`` must render byte-for-byte
identical to the pre-W4.1 renderer. ``fixtures/base_form_baseline.html`` is a
golden capture; any drift here means an existing server (wet/mnemo/crg/notion)
could see its form change unexpectedly.
"""

from pathlib import Path

from mcp_core.auth.credential_form import render_credential_form

_FIXTURE = Path(__file__).parent / "fixtures" / "base_form_baseline.html"

_BASELINE_SCHEMA = {
    "server": "golden-server",
    "displayName": "Golden Server",
    "description": "Backward-compat baseline form.",
    "fields": [
        {
            "key": "API_TOKEN",
            "label": "API Token",
            "type": "password",
            "placeholder": "sk-...",
            "required": True,
            "helpText": "Get your key",
            "helpUrl": "https://example.com/keys",
        },
        {"key": "WORKSPACE", "label": "Workspace", "type": "text", "required": False},
    ],
    "capabilityInfo": [{"label": "Search", "priority": "high", "description": "Search the web"}],
}


def test_flat_form_is_byte_identical_to_golden():
    html = render_credential_form(
        _BASELINE_SCHEMA,
        submit_url="/authorize?nonce=golden",
        prefill={"API_TOKEN": "pre-filled"},
        include_username_field=True,
    )
    assert html == _FIXTURE.read_text(encoding="utf-8")


def test_flat_form_has_no_feature_markup():
    """A plain schema never emits tab/card scaffolding."""
    html = render_credential_form({"server": "s", "displayName": "S", "fields": []}, submit_url="/a")
    assert 'role="tablist"' not in html
    assert "card-group-container" not in html
    assert "<style>" not in html.split("</head>")[1]  # no in-body feature <style>
