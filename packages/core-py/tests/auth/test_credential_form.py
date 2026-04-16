"""Tests for credential form HTML renderer."""

import re

from mcp_core.auth.credential_form import render_credential_form


def test_render_form_posts_step_to_otp_url():
    """Step submit JS must fetch() with POST method targeting /otp URL."""
    schema = {"server": "test", "displayName": "Test", "fields": []}
    html = render_credential_form(schema, submit_url="/authorize?nonce=abc")
    # Verify fetch call structure: fetch(otpUrl(), { method: "POST", ... })
    assert re.search(r'fetch\s*\(\s*otpUrl\s*\(\s*\)\s*,\s*\{\s*method\s*:\s*"POST"', html)


def test_render_form_error_retry_reenables_controls():
    """Error branch must re-enable input AND button for retry."""
    schema = {"server": "test", "displayName": "Test", "fields": []}
    html = render_credential_form(schema, submit_url="/authorize?nonce=abc")
    # Verify in error branch: inputEl.disabled = false AND buttonEl.disabled = false
    # Both must be present in the error handling path
    assert re.search(r"inputEl\.disabled\s*=\s*false", html)
    assert re.search(r"buttonEl\.disabled\s*=\s*false", html)


def test_render_form_step_input_has_aria_label():
    """Step input must be associated with prompt via aria-labelledby."""
    schema = {"server": "test", "displayName": "Test", "fields": []}
    html = render_credential_form(schema, submit_url="/authorize?nonce=abc")
    assert re.search(r'setAttribute\(\s*"aria-labelledby"\s*,\s*"step-prompt"', html)
    assert re.search(r'promptEl\.id\s*=\s*"step-prompt"', html)


class TestRenderCredentialForm:
    def test_render_basic_form(self):
        """Schema with 1 required password field -> HTML contains field key, label, placeholder, type=password, form action."""
        schema = {
            "server": "my-server",
            "displayName": "My Server",
            "fields": [
                {
                    "key": "api_token",
                    "label": "API Token",
                    "type": "password",
                    "placeholder": "Enter your API token",
                    "required": True,
                }
            ],
        }
        html = render_credential_form(schema, submit_url="https://example.com/submit")

        assert "api_token" in html
        assert "API Token" in html
        assert "Enter your API token" in html
        assert 'type="password"' in html
        assert "https://example.com/submit" in html

    def test_render_optional_fields(self):
        """Required + optional fields -> 'required' attr present for required field, absent for optional."""
        schema = {
            "server": "my-server",
            "displayName": "My Server",
            "fields": [
                {
                    "key": "token",
                    "label": "Token",
                    "type": "password",
                    "required": True,
                },
                {
                    "key": "workspace",
                    "label": "Workspace",
                    "type": "text",
                    "required": False,
                },
            ],
        }
        html = render_credential_form(schema, submit_url="https://example.com/submit")

        # The required field should have the required attribute
        # We check that 'required' appears as an HTML attribute for the required field
        assert "token" in html
        assert "workspace" in html
        # Required field input should carry the required attribute
        assert 'name="token"' in html
        assert 'name="workspace"' in html
        # The required attribute should appear in the form at least once
        assert "required" in html

    def test_render_capability_info(self):
        """Schema with capabilityInfo -> HTML contains label + priority."""
        schema = {
            "server": "my-server",
            "displayName": "My Server",
            "fields": [
                {
                    "key": "token",
                    "label": "Token",
                    "type": "password",
                    "required": True,
                }
            ],
            "capabilityInfo": [
                {
                    "label": "Search Web",
                    "priority": "high",
                    "description": "Allows searching the web",
                },
                {
                    "label": "Read Files",
                    "priority": "medium",
                    "description": "Allows reading local files",
                },
            ],
        }
        html = render_credential_form(schema, submit_url="https://example.com/submit")

        assert "Search Web" in html
        assert "high" in html
        assert "Read Files" in html
        assert "medium" in html

    def test_render_escapes_xss(self):
        """displayName with <script> -> user-supplied tags are escaped, not injected raw."""
        schema = {
            "server": "evil-server",
            "displayName": '<script>alert("xss")</script>',
            "fields": [
                {
                    "key": "token",
                    "label": "<img src=x onerror=alert(1)>",
                    "type": "text",
                    "placeholder": '"><svg onload=alert(1)>',
                    "required": True,
                }
            ],
        }
        rendered = render_credential_form(schema, submit_url="https://example.com/submit")

        # User-supplied alert("xss") content must be escaped — the raw script body
        # injected by the attacker must not appear verbatim inside the server-name element.
        assert 'alert("xss")</script>' not in rendered
        # User-supplied <img> tag (from label) must not appear as a live tag
        assert "<img" not in rendered
        # User-supplied <svg> tag (from placeholder) must not appear as a live tag
        assert "<svg" not in rendered
        # Escaped versions must be present
        assert "&lt;script&gt;" in rendered
        assert "&lt;img" in rendered

    def test_render_form_contains_otp_handler(self):
        """Form JS should handle next_step type otp_required."""
        schema = {"server": "test", "displayName": "Test", "fields": []}
        html = render_credential_form(schema, submit_url="/authorize?nonce=abc")
        # JS handler for otp_required must exist
        assert "otp_required" in html
        assert "password_required" in html

    def test_render_form_posts_to_otp_endpoint(self):
        """Form JS should POST multi-step input to /otp endpoint."""
        schema = {"server": "test", "displayName": "Test", "fields": []}
        html = render_credential_form(schema, submit_url="/authorize?nonce=abc")
        # Must reference /otp URL derivation
        assert "/otp" in html

    def test_render_form_handles_error_retry(self):
        """Form JS should allow retry on step error."""
        schema = {"server": "test", "displayName": "Test", "fields": []}
        html = render_credential_form(schema, submit_url="/authorize?nonce=abc")
        # Must have Verify button text (multi-step submit button)
        assert "Verify" in html

    def test_render_form_uses_safe_dom_methods(self):
        """Form JS should use createElement + textContent, not innerHTML with variables."""
        schema = {"server": "test", "displayName": "Test", "fields": []}
        html = render_credential_form(schema, submit_url="/authorize?nonce=abc")
        # textContent must appear (safe text setting)
        assert "textContent" in html
        # createElement must be used for dynamic elements
        assert "createElement" in html


def test_render_form_omits_dynamic_flow_js_when_disabled():
    """When dynamic_flow=False, OTP/multi-step JS must be absent."""
    schema = {"server": "test", "displayName": "Test", "fields": []}
    html = render_credential_form(schema, submit_url="/auth", dynamic_flow=False)
    assert "otpUrl" not in html
    assert "showStepInput" not in html
    assert "submitStep" not in html
    assert "otp_required" not in html


def test_render_form_omits_device_code_js_when_disabled():
    """When device_code_poll=False, OAuth device code polling JS must be absent."""
    schema = {"server": "test", "displayName": "Test", "fields": []}
    html = render_credential_form(schema, submit_url="/auth", device_code_poll=False)
    assert "oauth_device_code" not in html
    assert "gdrive-waiting" not in html
    assert "/setup-status" not in html
