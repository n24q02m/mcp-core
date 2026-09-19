#!/usr/bin/env python3
"""Regression tests for the stable-release downstream issue fan-out."""

from __future__ import annotations

import re
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "cd.yml"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _job_text(name: str) -> str:
    # Jobs in this file are separated by `  # ====...` banner comments.
    text = _workflow_text()
    start = text.index(f"\n  {name}:")
    next_banner = text.find("\n  # ====", start + 1)
    end = next_banner if next_banner != -1 else len(text)
    return text[start:end]


def _shell_assignment(text: str, name: str) -> set[str]:
    match = re.search(rf'^\s*{re.escape(name)}="([^"]+)"$', text, re.MULTILINE)
    assert match is not None, f"missing downstream assignment: {name}"
    return set(match.group(1).split())


def _code_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]


def test_app_token_does_not_pin_repositories() -> None:
    """The downstream token step must stay installation-scoped.

    A pinned ``repositories:`` list 422s the whole job the moment any listed
    repo becomes invisible to the installation — qwen3-embed's 2026-09 archive
    killed "Create downstream bump issues" on every stable release (#829 and
    later). Per-repo failures belong to the fan-out step as ::warning::s.
    """
    job_text = _job_text("create-downstream-issues")
    # A `repositories:` input (10-space step indentation) under any step of
    # THIS job would reintroduce the hard 422 on the first repo the
    # installation loses.
    assert not re.search(r"^ {10}repositories:", job_text, re.MULTILINE)
    # The archived repo must be gone from workflow code (comments may explain
    # why).
    assert not any("qwen3-embed" in ln for ln in _code_lines(_workflow_text()))


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
    # qwen3-embed archived 2026-09 (continues as fastretrieval); tracking
    # issues in an archived repo are dead letter and the installation cannot
    # see it anymore.
    assert tracking_repos == {"web-core", "claude-plugins"}
    assert "for repo in $TRACKING_DOWNSTREAM; do" in text


if __name__ == "__main__":
    test_app_token_does_not_pin_repositories()
    test_issue_fanout_covers_pin_and_tracking_consumers()
    print("OK: release cascade tests passed")
