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


# ---------------------------------------------------------------------------
# W4.4 light-mode: the shell + feature CSS declare a ``prefers-color-scheme:
# light`` override and ``color-scheme: light dark`` so the form is legible in a
# light OS theme instead of the previous dark-only hardcode.
# ---------------------------------------------------------------------------

_TABS_SCHEMA = {
    "server": "s",
    "displayName": "S",
    "tabs": [{"id": "a", "label": "A", "fields": [{"key": "K", "label": "K", "type": "text"}]}],
}
_CARD_SCHEMA = {
    "server": "s",
    "displayName": "S",
    "cardGroup": {"key": "items", "fields": [{"key": "K", "label": "K", "type": "text"}]},
}


def test_flat_form_declares_light_mode():
    html = render_credential_form(_BASELINE_SCHEMA, submit_url="/a")
    assert "color-scheme: light dark" in html
    assert "@media (prefers-color-scheme: light)" in html


def test_tab_form_declares_light_mode():
    html = render_credential_form(_TABS_SCHEMA, submit_url="/a")
    # Shell light block + tab-specific light overrides.
    assert "@media (prefers-color-scheme: light)" in html
    assert html.count("@media (prefers-color-scheme: light)") >= 2


def test_card_form_declares_light_mode():
    html = render_credential_form(_CARD_SCHEMA, submit_url="/a")
    assert "@media (prefers-color-scheme: light)" in html
    assert html.count("@media (prefers-color-scheme: light)") >= 2


# ---------------------------------------------------------------------------
# WS3-7c: the shared form shell declares a Content-Security-Policy meta so the
# self-contained page runs its own inline script/style but loads nothing
# external. Applies to every form the shell renders (flat + tabs + cards).
# ---------------------------------------------------------------------------

_CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'"


def test_flat_form_has_csp_meta():
    html = render_credential_form(_BASELINE_SCHEMA, submit_url="/a")
    assert f'<meta http-equiv="Content-Security-Policy" content="{_CSP}" />' in html


def test_tab_form_has_csp_meta():
    html = render_credential_form(_TABS_SCHEMA, submit_url="/a")
    assert 'http-equiv="Content-Security-Policy"' in html
    assert _CSP in html


def test_card_form_has_csp_meta():
    html = render_credential_form(_CARD_SCHEMA, submit_url="/a")
    assert 'http-equiv="Content-Security-Policy"' in html
    assert _CSP in html
