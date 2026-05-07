import os
import sys

# Add src to path
sys.path.append(os.path.abspath("src"))

from mcp_core.auth.credential_form import render_credential_form

schema = {
    "server": "test-server",
    "displayName": "Test Server",
    "description": "A server for testing UI refactor",
    "fields": [
        {
            "key": "api_key",
            "label": "API Key",
            "type": "password",
            "placeholder": "sk-...",
            "required": True,
            "helpText": "Get your key from the dashboard"
        },
        {
            "key": "endpoint",
            "label": "Endpoint URL",
            "type": "url",
            "placeholder": "https://api.example.com",
            "required": False
        }
    ],
    "capabilityInfo": [
        {
            "label": "Read Access",
            "priority": "high",
            "description": "Read all your data"
        },
        {
            "label": "Write Access",
            "priority": "medium",
            "description": "Modify your data"
        }
    ]
}

html = render_credential_form(schema, submit_url="/authorize?nonce=123")

with open("test_form.html", "w") as f:
    f.write(html)

print("Generated test_form.html")
