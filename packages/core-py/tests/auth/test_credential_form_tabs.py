"""Tests for the schema-level ``tabs`` capability in the credential form."""

from mcp_core.auth.credential_form import render_credential_form

_TABS_SCHEMA = {
    "server": "better-telegram-mcp",
    "displayName": "Telegram MCP",
    "description": "Bot token or phone login.",
    "tabs": [
        {
            "id": "bot",
            "label": "Bot Mode",
            "fields": [
                {
                    "key": "TELEGRAM_BOT_TOKEN",
                    "label": "Bot Token",
                    "type": "password",
                    "required": True,
                    "placeholder": "123456:ABC-DEF...",
                    "helpText": "Get from @BotFather",
                    "helpUrl": "https://core.telegram.org/bots#botfather",
                }
            ],
        },
        {
            "id": "user",
            "label": "User Mode",
            "fields": [
                {
                    "key": "TELEGRAM_PHONE",
                    "label": "Phone Number",
                    "type": "tel",
                    "required": True,
                    "placeholder": "+84...",
                }
            ],
        },
    ],
}


def _render(**kwargs):
    return render_credential_form(_TABS_SCHEMA, submit_url="/authorize?nonce=abc", **kwargs)


def test_renders_tablist_with_one_button_per_tab():
    html = _render()
    assert 'role="tablist"' in html
    assert html.count('role="tab"') == 2
    assert html.count('role="tabpanel"') == 2
    assert 'id="tab-bot"' in html and 'id="tab-user"' in html
    assert 'id="panel-bot"' in html and 'id="panel-user"' in html
    assert "Bot Mode" in html and "User Mode" in html


def test_first_tab_is_active_by_default():
    html = _render()
    assert 'id="tab-bot" class="tab active"' in html
    assert 'aria-selected="true"' in html
    assert 'id="panel-bot" class="tab-panel active"' in html
    # The non-active tab is not selected.
    assert 'id="tab-user" class="tab"' in html


def test_initial_tab_option_activates_named_tab():
    html = _render(initial_tab="user")
    assert 'id="tab-user" class="tab active"' in html
    assert 'id="panel-user" class="tab-panel active"' in html
    assert 'id="tab-bot" class="tab"' in html


def test_unknown_initial_tab_falls_back_to_first():
    html = _render(initial_tab="does-not-exist")
    assert 'id="tab-bot" class="tab active"' in html


def test_each_panel_contains_its_own_fields():
    html = _render()
    bot_panel = html.split('id="panel-bot"')[1].split('id="panel-user"')[0]
    user_panel = html.split('id="panel-user"')[1].split("</form>")[0]
    assert 'name="TELEGRAM_BOT_TOKEN"' in bot_panel
    assert 'name="TELEGRAM_BOT_TOKEN"' not in user_panel
    assert 'name="TELEGRAM_PHONE"' in user_panel
    assert 'name="TELEGRAM_PHONE"' not in bot_panel


def test_submit_collects_only_active_panel_fields():
    """The submit handler scopes collection to the active panel."""
    html = _render()
    assert 'document.querySelector(".tab-panel.active")' in html
    assert 'activePanel ? activePanel.querySelectorAll(".field-input")' in html


def test_keyboard_arrow_navigation_is_wired():
    html = _render()
    assert "ArrowRight" in html
    assert "ArrowLeft" in html


def test_includes_multi_step_otp_handlers():
    """Tab forms retain OTP / 2FA multi-step chaining."""
    html = _render()
    assert "otp_required" in html
    assert "password_required" in html
    assert "showStepInput" in html
    assert "/otp" in html


def test_follows_redirect_url_on_success():
    html = _render()
    assert "window.location.replace(pendingRedirectUrl)" in html


def test_prefill_lands_in_tab_field():
    html = _render(prefill={"TELEGRAM_PHONE": "+84900000000"})
    assert 'value="+84900000000"' in html


def test_escapes_user_supplied_tab_values():
    schema = {
        "server": "s",
        "displayName": "S",
        "tabs": [
            {
                "id": "x",
                "label": "<script>alert(1)</script>",
                "fields": [{"key": "K", "label": "<img src=x onerror=alert(1)>", "type": "text"}],
            }
        ],
    }
    html = render_credential_form(schema, submit_url="/a")
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_username_field_opt_in_with_tabs():
    html = _render(include_username_field=True)
    assert html.count('name="__sub_username"') == 1


def test_uses_safe_dom_methods():
    html = _render()
    assert "createElement" in html
    assert "textContent" in html
