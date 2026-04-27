"""Render docker-compose.test.yml from per-server Jinja template + matrix config.

Each repo has a dedicated template under ``templates/``. Credentials from the
skret loader are passed in lowercase (e.g. ``GEMINI_API_KEY`` -> ``gemini_api_key``)
so Jinja ``{% if x is defined and x %}`` blocks can omit env entries when a key
is absent — important for optional credentials like Cohere.
"""

from __future__ import annotations

from pathlib import Path

import jinja2

REPO_TO_TEMPLATE: dict[str, str] = {
    "better-notion-mcp": "compose-notion.yml.j2",
    "better-email-mcp": "compose-email.yml.j2",
    "better-telegram-mcp": "compose-telegram.yml.j2",
    "wet-mcp": "compose-wet.yml.j2",
    "mnemo-mcp": "compose-mnemo.yml.j2",
    "better-code-review-graph": "compose-crg.yml.j2",
    "imagine-mcp": "compose-imagine.yml.j2",
    "better-godot-mcp": "compose-godot.yml.j2",
}

# nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
# Generates docker-compose YAML for ephemeral test deployments, not HTML.
# No XSS surface: output is consumed only by ``docker compose -f``.
_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=False,
    keep_trailing_newline=True,
    undefined=jinja2.Undefined,
)


def render_compose(
    config: dict,
    deployment: str,
    creds: dict[str, str],
    host_port: int,
    image_tag: str = "beta",
) -> str:
    repo = config["repo"]
    if repo not in REPO_TO_TEMPLATE:
        raise KeyError(f"No compose template for repo: {repo}")

    tmpl = _env.get_template(REPO_TO_TEMPLATE[repo])
    ctx = {
        "deployment": deployment,
        "host_port": host_port,
        "image_tag": image_tag,
        "mcp_dcr_server_secret": creds.get("MCP_DCR_SERVER_SECRET", ""),
        **{k.lower(): v for k, v in creds.items()},
    }
    # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
    return tmpl.render(**ctx)
