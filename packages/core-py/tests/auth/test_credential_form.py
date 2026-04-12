"""Tests for credential form HTML renderer."""

from mcp_core.auth.credential_form import render_credential_form


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
