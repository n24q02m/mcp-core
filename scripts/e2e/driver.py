"""E2E driver entry point.

Usage:
    python -m e2e.driver <config-id>    # run single config
    python -m e2e.driver t0             # run all T0-only configs
    python -m e2e.driver all            # run full matrix

The driver loops over the matrix.yaml configs:

* T0-only: shells out to per-repo test commands (pytest / bun test / build / lint).
* T2 non-interaction: docker-compose up -> wait health -> auto-fill relay -> run mcp.ClientSession.
* T2 interaction: same as above plus poll user-gate status while user clicks.
"""

from __future__ import annotations

import argparse
import asyncio
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from e2e.client_runner import run_e2e_http, wait_for_health
from e2e.compose_renderer import render_compose
from e2e.ports import allocate_port
from e2e.relay_filler import fill_relay_form
from e2e.skret_loader import load_namespace_required
from e2e.user_gate import announce_and_wait

MATRIX_PATH = Path(__file__).parent / "matrix.yaml"

# Top-level tool names per repo. Verified against the N+2 standard tool layout
# (domain tools + config + help). Tools added beyond this list are tolerated;
# missing tools fail the E2E with a clear AssertionError.
EXPECTED_TOOLS: dict[str, list[str]] = {
    "better-notion-mcp": [
        "search",
        "page",
        "database",
        "block",
        "comment",
        "user",
        "config",
        "help",
    ],
    "better-email-mcp": ["message", "thread", "draft", "search", "config", "help"],
    "better-telegram-mcp": ["message", "chat", "media", "contact", "config", "help"],
    "wet-mcp": ["search", "extract", "media", "library", "config", "help"],
    "mnemo-mcp": ["memory", "config", "help"],
    "better-code-review-graph": [
        "graph",
        "query",
        "review",
        "config",
        "setup",
        "help",
    ],
    "imagine-mcp": ["generate", "config", "help"],
    "better-godot-mcp": [
        "scene",
        "node",
        "script",
        "asset",
        "run",
        "config",
        "help",
    ],
}

# T0 commands per repo. Run from the repo root (cwd = ../../<repo> relative to
# this driver). Using ``shell=False`` and a list keeps Windows/Bash parity.
T0_COMMANDS: dict[str, list[str]] = {
    "mcp-core": ["bun", "test"],
    "qwen3-embed": ["uv", "run", "pytest"],
    "web-core": ["bun", "run", "build"],
    "claude-plugins": ["bun", "run", "validate"],
    "better-godot-mcp": ["bun", "test"],
}


def load_matrix() -> list[dict]:
    return yaml.safe_load(MATRIX_PATH.read_text(encoding="utf-8"))["configs"]


def run_t0_config(config: dict) -> None:
    repo = config["repo"]
    cmd = T0_COMMANDS.get(repo)
    if cmd is None:
        raise ValueError(f"No T0 command registered for repo: {repo}")
    repo_root = Path(__file__).parent.parent.parent.parent / repo
    if not repo_root.exists():
        raise FileNotFoundError(f"Repo not found at {repo_root}")
    print(
        f"[driver] {config['id']}: {' '.join(cmd)} (cwd={repo_root})", file=sys.stderr
    )
    subprocess.run(cmd, cwd=repo_root, check=True)


def run_t2_config(config: dict, deployment: str) -> None:
    print(f"\n[driver] === {config['id']} ({deployment}) ===", file=sys.stderr)

    skret_keys = config.get("skret_keys", [])
    skret_optional = set(config.get("skret_optional", []))
    required = [k for k in skret_keys if k not in skret_optional]
    creds = (
        load_namespace_required(config["skret_namespace"], required=required)
        if skret_keys
        else {}
    )

    port = allocate_port()
    compose_yaml = render_compose(
        config, deployment=deployment, creds=creds, host_port=port
    )

    with tempfile.TemporaryDirectory() as td:
        compose_file = Path(td) / "docker-compose.yml"
        compose_file.write_text(compose_yaml, encoding="utf-8")

        subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "up", "-d"],
            check=True,
        )
        try:
            base_url = f"http://127.0.0.1:{port}"
            wait_for_health(base_url)

            if config["auth"] != "none":
                fill_relay_form(base_url, creds=creds)

            if config["tier"] == "t2-interaction":
                announce_and_wait(
                    config["user_gate"],
                    relay_url=f"{base_url}/authorize",
                    poll_url=f"{base_url}/setup-status",
                )

            asyncio.run(run_e2e_http(base_url, EXPECTED_TOOLS[config["repo"]]))
            print(f"[driver] PASS {config['id']} ({deployment})", file=sys.stderr)
        finally:
            subprocess.run(
                ["docker", "compose", "-f", str(compose_file), "down", "-v"],
                check=False,
            )


def run_config(config: dict, deployment: str = "local") -> None:
    if config["tier"] == "t0-only":
        run_t0_config(config)
    else:
        run_t2_config(config, deployment=deployment)


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP E2E driver")
    parser.add_argument("target", help="config id, 't0', or 'all'")
    parser.add_argument("--deployment", default="local", choices=["local", "remote"])
    args = parser.parse_args()

    matrix = load_matrix()
    if args.target == "t0":
        targets = [c for c in matrix if c["tier"] == "t0-only"]
    elif args.target == "all":
        targets = matrix
    else:
        targets = [c for c in matrix if c["id"] == args.target]
        if not targets:
            sys.exit(f"Unknown config: {args.target}")

    failed: list[str] = []
    for c in targets:
        try:
            for dep in c.get("deployment", [args.deployment]):
                run_config(c, deployment=dep)
        except Exception as e:
            print(f"[driver] FAIL {c['id']}: {e}", file=sys.stderr)
            failed.append(c["id"])

    if failed:
        sys.exit(f"E2E failures: {failed}")


if __name__ == "__main__":
    main()
