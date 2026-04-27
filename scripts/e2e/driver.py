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
from e2e.oauth_client import acquire_jwt, acquire_jwt_via_upstream_consent
from e2e.ports import allocate_port
from e2e.skret_loader import load_namespace_required
from e2e.user_gate import announce_and_wait

MATRIX_PATH = Path(__file__).parent / "matrix.yaml"

# Top-level tool names per repo. Verified against the N+2 standard tool layout
# (domain tools + config + help). Tools added beyond this list are tolerated;
# missing tools fail the E2E with a clear AssertionError.
EXPECTED_TOOLS: dict[str, list[str]] = {
    # Verified 2026-04-27 against tools/list: 10 composite tools per
    # CLAUDE.md (pages, databases, blocks, users, workspace, comments,
    # content_convert, file_uploads + config + help). Earlier matrix used
    # singular forms ("page", "block", "user") which never matched.
    "better-notion-mcp": [
        "pages",
        "databases",
        "blocks",
        "users",
        "workspace",
        "comments",
        "content_convert",
        "file_uploads",
        "config",
        "help",
    ],
    # Verified 2026-04-27: actual tools are attachments, config, folders,
    # help, messages, send (6 tools). Earlier "message/thread/draft/search"
    # set was speculative.
    "better-email-mcp": [
        "attachments",
        "folders",
        "messages",
        "send",
        "config",
        "help",
    ],
    "better-telegram-mcp": ["message", "chat", "media", "contact", "config", "help"],
    # Verified 2026-04-27: actual tools are config, extract, help, media,
    # search (5 tools). "library" was in the original matrix but never
    # registered by the server.
    "wet-mcp": ["search", "extract", "media", "config", "help"],
    "mnemo-mcp": ["memory", "config", "help"],
    "better-code-review-graph": [
        "graph",
        "query",
        "review",
        "config",
        "help",
    ],
    "imagine-mcp": ["generate", "config", "help"],
    # Godot ships 17 composite mega-tools (per CLAUDE.md). Verified against
    # tools/list 2026-04-26: animation, audio, config, editor, help, input_map,
    # navigation, nodes, physics, project, resources, scenes, scripts, shader,
    # signals, tilemap, ui. The N+2 (config + help + N domain) standard holds.
    "better-godot-mcp": [
        "animation",
        "audio",
        "editor",
        "input_map",
        "navigation",
        "nodes",
        "physics",
        "project",
        "resources",
        "scenes",
        "scripts",
        "shader",
        "signals",
        "tilemap",
        "ui",
        "config",
        "help",
    ],
}

# T0 commands per repo. Run from the repo root (cwd = ../../<repo> relative to
# this driver). Verified 2026-04-26 against actual repo build systems:
# - mcp-core monorepo uses bun for TS + uv for Python; bun test runs both via
#   the workspace + pre-commit conventions.
# - qwen3-embed is uv-managed Python (pytest covers Modal worker stubs).
# - web-core is uv-managed Python despite the name (pyproject.toml; no package.json).
# - claude-plugins ships a Python validator script for marketplace.json.
# - better-godot-mcp is TypeScript-first under bun.
# Each entry is a list of (relative_cwd, argv) pairs run sequentially.
# Empty string for ``relative_cwd`` means "repo root". A failure in any step
# fails the whole config.
#
# Notes per repo:
# - mcp-core is a monorepo: TS in packages/core-ts (vitest via ``bun run
#   test`` — NOT ``bun test`` which is Bun's built-in runner with broken
#   vitest-compat), Python in packages/core-py (pytest).
# - qwen3-embed / web-core: uv-managed Python.
# - claude-plugins: Python validator script for marketplace.json.
# - better-godot-mcp: TypeScript-first under bun (vitest).
T0_COMMANDS: dict[str, list[tuple[str, list[str]]]] = {
    "mcp-core": [
        ("packages/core-ts", ["bun", "run", "test"]),
        ("packages/core-py", ["uv", "run", "pytest", "--tb=short", "-q"]),
    ],
    # qwen3-embed: integration tests need ~1.2GB GGUF download — CLAUDE.md
    # spec is "CI chỉ chạy unit tests", so the driver mirrors that.
    "qwen3-embed": [("", ["uv", "run", "pytest", "-m", "not integration"])],
    # web-core: launch the venv python DIRECTLY (skip ``uv run`` wrapper).
    # When the driver itself is under ``uv run``, a nested ``uv run`` in
    # web-core triggers a Python 3.13 GC access violation on Windows during
    # cpython ast.parse / getstatementrange_ast. The venv is pre-synced via
    # the repo's own pre-commit / mise tasks.
    "web-core": [("", [".venv/Scripts/python.exe", "-m", "pytest"])],
    "claude-plugins": [("", ["python3", "scripts/validate_marketplace.py"])],
    "better-godot-mcp": [("", ["bun", "run", "test"])],
}


def load_matrix() -> list[dict]:
    return yaml.safe_load(MATRIX_PATH.read_text(encoding="utf-8"))["configs"]


def run_t0_config(config: dict) -> None:
    repo = config["repo"]
    steps = T0_COMMANDS.get(repo)
    if steps is None:
        raise ValueError(f"No T0 command registered for repo: {repo}")
    repo_root = Path(__file__).parent.parent.parent.parent / repo
    if not repo_root.exists():
        raise FileNotFoundError(f"Repo not found at {repo_root}")

    # Strip UV_*/VIRTUAL_ENV/PYTHONHOME/PYTHONPATH so the child Python
    # process resolves its own venv + stdlib cleanly. PYTHONHOME inherited
    # from a parent ``uv run`` (which runs Python 3.14 under uv's managed
    # interpreter) made web-core's 3.13 venv crash with 0xC0000005 in
    # cpython ast.parse during pytest GC on Windows. Removing the parent's
    # interpreter env vars cures it.
    import os as _os

    child_env = {
        k: v
        for k, v in _os.environ.items()
        if not k.startswith("UV")
        and k not in {"VIRTUAL_ENV", "PYTHONHOME", "PYTHONPATH"}
    }

    for rel_cwd, cmd in steps:
        cwd = repo_root / rel_cwd if rel_cwd else repo_root
        # If the first arg looks like a repo-relative venv path
        # (``.venv/Scripts/python.exe``), resolve it absolute relative to
        # cwd. ``subprocess.run`` does not honour cwd for argv[0] PATH lookup
        # on Windows, so a bare relative path triggers ENOENT.
        resolved = list(cmd)
        if resolved and resolved[0].startswith(".venv/"):
            resolved[0] = str((cwd / resolved[0]).resolve())
        print(
            f"[driver] {config['id']}: {' '.join(cmd)} (cwd={cwd})",
            file=sys.stderr,
        )
        subprocess.run(resolved, cwd=cwd, check=True, env=child_env)


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

            access_token: str | None = None
            if config["auth"] == "oauth" and config["tier"] == "t2-interaction":
                # Delegated OAuth (notion-oauth): /authorize 302 redirects
                # browser to the upstream provider for consent. The driver
                # binds a local callback listener, hands the upstream URL
                # to the user via announce_and_wait-style banner, and
                # exchanges the captured code for a JWT.
                def _announce(upstream_url: str) -> None:
                    bar = "=" * 60
                    print(f"\n{bar}", file=sys.stderr)
                    print(
                        f"[USER ACTION REQUIRED] {config['user_gate']}",
                        file=sys.stderr,
                    )
                    print("Open this URL in your browser:", file=sys.stderr)
                    print(f"  {upstream_url}", file=sys.stderr)
                    print(f"{bar}\n", file=sys.stderr)

                access_token = asyncio.run(
                    acquire_jwt_via_upstream_consent(base_url, _announce)
                )
            elif config["auth"] != "none":
                # Drive the OAuth 2.1 PKCE flow: GET /authorize form, POST
                # creds, /token-exchange auth code → JWT for /mcp Bearer.
                access_token = asyncio.run(acquire_jwt(base_url, creds=creds))

                if config["tier"] == "t2-interaction":
                    announce_and_wait(
                        config["user_gate"],
                        relay_url=f"{base_url}/authorize",
                        poll_url=f"{base_url}/setup-status",
                    )

            asyncio.run(
                run_e2e_http(
                    base_url,
                    EXPECTED_TOOLS[config["repo"]],
                    access_token=access_token,
                )
            )
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

    # Aggregate targets ('t0', 'all') re-invoke ourselves per config so each
    # subprocess runs in a clean environment. Otherwise nested-uv state from
    # the previous config leaks into the next (vitest 2-test flake on Windows
    # observed 2026-04-26 when chaining mcp-core-ci into the t0 sweep).
    if args.target in {"t0", "all"}:
        if args.target == "t0":
            ids = [c["id"] for c in matrix if c["tier"] == "t0-only"]
        else:
            ids = [c["id"] for c in matrix]
        failed: list[str] = []
        for cid in ids:
            print(
                f"\n[driver] >>> spawning fresh subprocess for {cid}", file=sys.stderr
            )
            r = subprocess.run(
                [sys.executable, "-m", "e2e.driver", cid],
                cwd=Path(__file__).parent,
            )
            if r.returncode != 0:
                failed.append(cid)
        if failed:
            sys.exit(f"E2E failures: {failed}")
        return

    targets = [c for c in matrix if c["id"] == args.target]
    if not targets:
        sys.exit(f"Unknown config: {args.target}")

    failed = []
    for c in targets:
        try:
            for dep in c.get("deployment", [args.deployment]):
                run_config(c, deployment=dep)
        except Exception as e:
            import traceback

            print(f"[driver] FAIL {c['id']}: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            failed.append(c["id"])

    if failed:
        sys.exit(f"E2E failures: {failed}")


if __name__ == "__main__":
    main()
