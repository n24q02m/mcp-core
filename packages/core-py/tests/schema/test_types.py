"""Tests for schema types."""

from mcp_core.schema.types import (
    ConfigField,
    ConfigMode,
    CredentialsRoute,
    DynamicFlow,
    OAuthRoute,
    RelayConfigSchema,
)

from ..constants import GOOGLE_CLIENT_ID


class TestSchemaTypes:
    def test_simple_fields_schema(self):
        schema: RelayConfigSchema = {
            "server": "telegram",
            "displayName": "Telegram MCP",
            "fields": [
                {
                    "key": "api_id",
                    "label": "API ID",
                    "type": "text",
                    "placeholder": "12345678",
                    "helpUrl": "https://my.telegram.org/apps",
                    "helpText": "Get your API ID from my.telegram.org",
                    "required": True,
                    "validation": r"^\d+$",
                },
                {
                    "key": "api_hash",
                    "label": "API Hash",
                    "type": "password",
                    "required": True,
                },
                {
                    "key": "phone",
                    "label": "Phone Number",
                    "type": "tel",
                    "placeholder": "+1234567890",
                    "required": True,
                },
            ],
        }
        assert schema["server"] == "telegram"
        assert len(schema["fields"]) == 3
        assert "modes" not in schema
        assert "dynamicFlow" not in schema

    def test_modes_schema(self):
        schema: RelayConfigSchema = {
            "server": "slack",
            "displayName": "Slack MCP",
            "modes": [
                {
                    "id": "bot",
                    "label": "Bot Token",
                    "description": "Use a Slack Bot token",
                    "fields": [
                        {
                            "key": "bot_token",
                            "label": "Bot Token",
                            "type": "password",
                            "required": True,
                        }
                    ],
                },
                {
                    "id": "user",
                    "label": "User Token",
                    "description": "Use a Slack User token",
                    "fields": [
                        {
                            "key": "user_token",
                            "label": "User Token",
                            "type": "password",
                            "required": True,
                        }
                    ],
                },
            ],
        }
        assert len(schema["modes"]) == 2
        assert schema["modes"][0]["id"] == "bot"

    def test_dynamic_flow_schema(self):
        entry_field: ConfigField = {
            "key": "provider",
            "label": "Email Provider",
            "type": "select",
            "choices": ["gmail", "outlook", "custom"],
            "required": True,
        }

        oauth_route: OAuthRoute = {
            "match": ["gmail"],
            "action": "oauth2_device_code",
            "message": "Sign in with Google",
            "oauthConfig": {
                "clientId": GOOGLE_CLIENT_ID,
                "scopes": ["https://mail.google.com/"],
            },
        }

        cred_route: CredentialsRoute = {
            "match": ["custom"],
            "action": "credentials",
            "fields": [
                {
                    "key": "smtp_host",
                    "label": "SMTP Host",
                    "type": "text",
                    "required": True,
                },
                {
                    "key": "smtp_port",
                    "label": "SMTP Port",
                    "type": "number",
                    "default": "587",
                },
                {
                    "key": "username",
                    "label": "Username",
                    "type": "email",
                    "required": True,
                },
                {
                    "key": "password",
                    "label": "Password",
                    "type": "password",
                    "required": True,
                },
            ],
        }

        flow: DynamicFlow = {
            "entryField": entry_field,
            "routes": [oauth_route, cred_route],
        }

        schema: RelayConfigSchema = {
            "server": "email",
            "displayName": "Email MCP",
            "dynamicFlow": flow,
        }

        assert schema["dynamicFlow"] is not None
        assert len(schema["dynamicFlow"]["routes"]) == 2
        assert schema["dynamicFlow"]["routes"][0]["action"] == "oauth2_device_code"
        assert schema["dynamicFlow"]["routes"][1]["action"] == "credentials"

    def test_optional_fields(self):
        schema: RelayConfigSchema = {
            "server": "notion",
            "displayName": "Notion MCP",
            "fields": [
                {
                    "key": "token",
                    "label": "Integration Token",
                    "type": "password",
                    "required": True,
                },
            ],
            "optional": [
                {
                    "key": "workspace_id",
                    "label": "Workspace ID",
                    "type": "text",
                    "helpText": "Optional filter",
                },
            ],
        }
        assert len(schema["optional"]) == 1
        assert "required" not in schema["optional"][0]

    def test_config_mode_interface(self):
        mode: ConfigMode = {
            "id": "api_key",
            "label": "API Key",
            "description": "Authenticate with an API key",
            "fields": [
                {
                    "key": "api_key",
                    "label": "API Key",
                    "type": "password",
                    "required": True,
                },
            ],
        }
        assert mode["id"] == "api_key"
        assert len(mode["fields"]) == 1
