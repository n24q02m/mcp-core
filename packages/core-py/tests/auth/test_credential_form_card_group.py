"""Tests for the schema-level ``cardGroup`` capability in the credential form."""

import json

from mcp_core.auth.credential_form import render_credential_form

_CARD_SCHEMA = {
    "server": "better-email-mcp",
    "displayName": "Email MCP",
    "description": "Configure one or more email accounts.",
    "cardGroup": {
        "key": "accounts",
        "itemLabel": "Account",
        "heading": "Email Accounts",
        "addButtonLabel": "+ Add Another Account",
        "minItems": 1,
        "titleField": "email",
        "fields": [
            {
                "key": "email",
                "label": "Email Address",
                "type": "email",
                "required": True,
                "placeholder": "you@example.com",
            },
            {"key": "password", "label": "Password", "type": "password", "required": True},
            {"key": "imap_host", "label": "IMAP Host", "type": "text", "required": False, "helpText": "Optional."},
        ],
    },
}


def _render(**kwargs):
    return render_credential_form(_CARD_SCHEMA, submit_url="/authorize?nonce=abc", **kwargs)


def test_renders_card_group_scaffolding():
    html = _render()
    assert 'id="card-group-container"' in html
    assert 'id="card-group-add"' in html
    assert "+ Add Another Account" in html
    assert "Email Accounts" in html


def test_field_spec_is_embedded_for_the_js_builder():
    html = _render()
    assert "var CARD_FIELDS = " in html
    assert 'GROUP_KEY = "accounts"' in html
    assert 'TITLE_FIELD = "email"' in html
    assert 'ITEM_LABEL = "Account"' in html
    assert "MIN_ITEMS = 1" in html
    # Every declared field key survives into the spec.
    for key in ("email", "password", "imap_host"):
        assert key in html


def test_submit_serialises_cards_as_array_under_group_key():
    html = _render()
    assert "payload[GROUP_KEY] = items" in html
    assert "collectCards" in html
    # Indexed field name format accounts[<uid>].<key>.
    assert 'GROUP_KEY + "[" + cardUid + "]." + spec.key' in html


def test_add_and_remove_wired():
    html = _render()
    assert "createCard" in html
    assert 'addBtn.addEventListener("click"' in html
    assert "card.remove()" in html
    assert "MIN_ITEMS" in html  # remove hidden while at/below the floor


def test_supports_outlook_style_device_code_followup():
    html = _render()
    assert "oauth_device_code" in html
    assert "setup-status" in html
    assert "renderOAuthDeviceCode" in html


def test_safe_redirect_guard_present():
    html = _render()
    assert "safeRedirect" in html
    assert 'parsed.protocol === "http:"' in html


def test_min_items_seeds_multiple_cards():
    schema = json.loads(json.dumps(_CARD_SCHEMA))
    schema["cardGroup"]["minItems"] = 3
    html = render_credential_form(schema, submit_url="/a")
    assert "MIN_ITEMS = 3" in html


def test_field_spec_json_escapes_angle_brackets():
    """The embedded JSON must not let a crafted field value close the <script>."""
    schema = json.loads(json.dumps(_CARD_SCHEMA))
    schema["cardGroup"]["fields"][0]["placeholder"] = "</script><script>alert(1)</script>"
    html = render_credential_form(schema, submit_url="/a")
    assert "</script><script>alert(1)" not in html
    assert "\\u003c/script>" in html


def test_group_key_escaped_in_js_literal():
    schema = json.loads(json.dumps(_CARD_SCHEMA))
    schema["cardGroup"]["key"] = 'x";alert(1);var y="'
    html = render_credential_form(schema, submit_url="/a")
    assert 'GROUP_KEY = "x";alert(1)' not in html


def test_uses_safe_dom_methods():
    html = _render()
    assert "createElement" in html
    assert "textContent" in html


def test_username_field_opt_in_with_cards():
    html = _render(include_username_field=True)
    assert html.count('name="__sub_username"') == 1


def test_invalid_submit_points_the_screen_reader_at_a_visible_message():
    """``aria-errormessage`` is inert unless the element it names is rendered.

    The card-group submit handler hides the status box on entry, so the branch
    that marks a field invalid has to bring it back -- otherwise the reference
    resolves to a ``display: none`` node and the screen reader announces the
    field as invalid with no reason attached.
    """
    html = _render()
    branch = html.split("if (!form.checkValidity())")[1].split("return;")[0]
    assert 'showStatus("error"' in branch
    assert 'setAttribute("aria-invalid", "true")' in branch
    assert 'setAttribute("aria-errormessage", "status-box")' in branch
    assert 'id="status-box"' in html
