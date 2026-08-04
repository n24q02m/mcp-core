#!/usr/bin/env python3
"""Regression tests for the stable-release downstream issue fan-out."""

from __future__ import annotations

import re
from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[1] / ".github" / "workflows" / "cd.yml"
)

REQUIRED_DOWNSTREAM = {
    "better-notion-mcp",
    "better-email-mcp",
    "better-telegram-mcp",
    "wet-mcp",
    "mnemo-mcp",
    "better-code-review-graph",
    "better-godot-mcp",
    "imagine-mcp",
    "better-workspace-mcp",
    "qwen3-embed",
    "web-core",
    "claude-plugins",
}


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _shell_assignment(text: str, name: str) -> set[str]:
    match = re.search(rf'^\s*{re.escape(name)}="([^"]+)"$', text, re.MULTILINE)
    assert match is not None, f"missing downstream assignment: {name}"
    return set(match.group(1).split())


def test_app_token_covers_every_downstream_repo() -> None:
    text = _workflow_text()
    start = text.index("repositories: >-")
    end = text.index("\n\n      - name:", start)
    token_repos = set(
        repo.strip()
        for repo in text[start:end].replace("repositories: >-", "").split(",")
        if repo.strip()
    )
    assert token_repos == REQUIRED_DOWNSTREAM


def test_issue_fanout_covers_pin_and_tracking_consumers() -> None:
    text = _workflow_text()
    pin_repos = _shell_assignment(text, "TS_DOWNSTREAM") | _shell_assignment(
        text, "PY_DOWNSTREAM"
    )
    tracking_repos = _shell_assignment(text, "TRACKING_DOWNSTREAM")

    assert pin_repos == {
        "better-notion-mcp",
        "better-email-mcp",
        "better-telegram-mcp",
        "wet-mcp",
        "mnemo-mcp",
        "better-code-review-graph",
        "better-godot-mcp",
        "imagine-mcp",
        "better-workspace-mcp",
    }
    assert tracking_repos == {"qwen3-embed", "web-core", "claude-plugins"}
    assert "for repo in $TRACKING_DOWNSTREAM; do" in text


if __name__ == "__main__":
    test_app_token_covers_every_downstream_repo()
    test_issue_fanout_covers_pin_and_tracking_consumers()
    print("OK: release cascade tests passed")
