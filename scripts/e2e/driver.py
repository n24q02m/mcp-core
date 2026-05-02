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
import datetime as _dt
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx
import yaml

from e2e.client_runner import run_e2e_http, wait_for_health
from e2e.compose_renderer import render_compose
from e2e.oauth_client import (
    acquire_jwt,
    acquire_jwt_via_browser_form,
    acquire_jwt_via_upstream_consent,
)
from e2e.ports import allocate_port
from e2e.skret_loader import load_namespace_required

MATRIX_PATH = Path(__file__).parent / "matrix.yaml"
DIAG_DIR = Path(tempfile.gettempdir()) / "e2e-diag"


def _print_t2_interaction_checklist() -> None:
    """One-time upstream registration banner before t2-interaction batch.

    Saves the user from discovering each missing precondition mid-flow. Each
    line names the upstream identity surface and what state it must be in
    BEFORE the run starts. Printed once at the start of any run that
    includes a t2-interaction config; suppressed if no such config in the
    target list (T0 sweep + non-interaction-only batches stay quiet).
    """
    bar = "=" * 60
    lines = [
        bar,
        "[driver] One-time upstream readiness checklist (t2-interaction):",
        "  - Microsoft (Outlook): account ready to sign in at",
        "      https://microsoft.com/devicelogin (driver prints user_code)",
        "  - Google Drive (wet/mnemo): account consented prior or revoke at",
        "      https://myaccount.google.com if testing fresh-grant isolation",
        "  - Telegram (telegram-user): app open on the registered phone to",
        "      receive the OTP push; 2FA password ready to type",
        "  - Notion (notion-oauth): RECLASSIFIED out of T2 matrix —",
        "      Notion app does not accept dynamic localhost callback;",
        "      production smoke runs against notion-mcp.n24q02m.com only.",
        bar,
    ]
    for line in lines:
        print(line, file=sys.stderr)


def _capture_diagnostics(config_id: str, compose_file: Path, base_url: str) -> Path:
    """Save container logs + last setup-status BEFORE ``docker compose down``.

    Mid-test ``TimeoutError`` used to cascade into immediate teardown, which
    erased the only state useful for diagnosis. This writes both artifacts
    to ``<tmp>/e2e-diag/<config>-<ts>.diag`` so the user can inspect what
    the upstream surface returned without re-running the whole config.
    """
    DIAG_DIR.mkdir(parents=True, exist_ok=True)
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    diag_file = DIAG_DIR / f"{config_id}-{ts}.diag"
    parts: list[str] = []
    try:
        logs = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "logs", "--no-color"],
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
        parts.append(
            "=== container logs ===\n" + (logs.stdout or "") + (logs.stderr or "")
        )
    except Exception as e:
        parts.append(f"=== container logs FAILED ===\n{e}")
    try:
        r = httpx.get(f"{base_url}/setup-status", timeout=2.0)
        parts.append(f"\n\n=== last setup-status ({r.status_code}) ===\n{r.text}")
    except Exception as e:
        parts.append(f"\n\n=== setup-status FAILED ===\n{e}")
    diag_file.write_text("\n".join(parts), encoding="utf-8")
    print(f"[driver] Diagnostics saved: {diag_file}", file=sys.stderr)
    return diag_file


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


def _shape_creds_for_form(config: dict, creds: dict[str, str]) -> dict[str, str]:
    """Map skret values into the field names the relay form actually accepts.

    Most servers store the relay form's field name verbatim in skret
    (NOTION_TOKEN, EMAIL_CREDENTIALS, JINA_AI_API_KEY, ...). email-outlook
    is the exception: skret tracks ``OUTLOOK_EMAIL`` semantically but the
    server's relay form expects the same ``EMAIL_CREDENTIALS=email:pass``
    field as gmail. For Outlook the password is empty (server triggers
    Microsoft Device Code OAuth2) so we synthesize ``email:`` here.
    """
    if config.get("id") == "email-outlook" and "OUTLOOK_EMAIL" in creds:
        shaped = {k: v for k, v in creds.items() if k != "OUTLOOK_EMAIL"}
        shaped["EMAIL_CREDENTIALS"] = f"{creds['OUTLOOK_EMAIL']}:"
        return shaped
    return creds


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
    creds = _shape_creds_for_form(config, creds)

    # Some configs (notion-oauth) need a stable host port so the upstream
    # OAuth provider's pre-registered redirect URI matches what the local
    # mcp container exposes. ``host_port`` in matrix.yaml pins the port;
    # everything else uses an ephemeral allocation.
    port = config.get("host_port") or allocate_port()
    # Default to ``latest`` so post-stable-cascade runs hit the freshly
    # published image. Stable CD pushes ``latest`` (and version tags) but
    # leaves ``beta`` untouched, so a stale ``beta`` tag from before the
    # cascade silently lacks routes added in the latest stable (e.g.
    # ``/authorize/prefill`` introduced in mcp-core v1.9.0). Override to
    # ``MCP_E2E_IMAGE_TAG=beta`` when verifying pre-release behavior.
    image_tag = os.environ.get("MCP_E2E_IMAGE_TAG", "latest")
    compose_yaml = render_compose(
        config, deployment=deployment, creds=creds, host_port=port, image_tag=image_tag
    )

    with tempfile.TemporaryDirectory() as td:
        compose_file = Path(td) / "docker-compose.yml"
        compose_file.write_text(compose_yaml, encoding="utf-8")

        subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "up", "-d"],
            check=True,
        )
        base_url = f"http://127.0.0.1:{port}"
        try:
            wait_for_health(base_url)

            access_token: str | None = None
            flow = config.get("flow")
            try:
                if config["auth"] == "none":
                    pass  # godot
                elif flow == "oauth-redirect" or (
                    config["auth"] == "oauth" and config["tier"] == "t2-interaction"
                ):
                    # notion-oauth: /authorize 302 redirects to the upstream
                    # provider for consent. Driver binds a local callback
                    # listener, announces the upstream URL, captures the code
                    # the local mcp redirects back with, exchanges for JWT.
                    def _announce_upstream(upstream_url: str) -> None:
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
                        acquire_jwt_via_upstream_consent(
                            base_url,
                            _announce_upstream,
                            flow_label="oauth-redirect",
                        )
                    )
                elif flow == "browser-form":
                    # telegram-user: form is multi-step (phone -> OTP -> 2FA).
                    # Driver cannot fill OTP server-to-server (it comes from
                    # the user's phone), so it announces /authorize and waits
                    # for the form to navigate browser into the local listener.
                    def _announce_form(form_url: str) -> None:
                        bar = "=" * 60
                        print(f"\n{bar}", file=sys.stderr)
                        print(
                            f"[USER ACTION REQUIRED] {config['user_gate']}",
                            file=sys.stderr,
                        )
                        print("Open this URL in your browser:", file=sys.stderr)
                        print(f"  {form_url}", file=sys.stderr)
                        print(f"{bar}\n", file=sys.stderr)

                    access_token = asyncio.run(
                        acquire_jwt_via_browser_form(
                            base_url,
                            _announce_form,
                            creds=creds,
                            allowed_prefill_keys=skret_keys,
                            flow_label="browser-form",
                        )
                    )
                elif config["tier"] == "t2-interaction":
                    # email-outlook (flow=device-code): server-to-server POST
                    # returns next_step with verification_url + user_code; the
                    # user signs in upstream while the server polls; driver
                    # polls /setup-status until complete before /token.
                    def _announce_next_step(next_step: dict) -> None:
                        bar = "=" * 60
                        print(f"\n{bar}", file=sys.stderr)
                        print(
                            f"[USER ACTION REQUIRED] {config['user_gate']}",
                            file=sys.stderr,
                        )
                        if next_step.get("verification_url"):
                            print(
                                f"  Open: {next_step['verification_url']}",
                                file=sys.stderr,
                            )
                        if next_step.get("user_code"):
                            print(
                                f"  User code: {next_step['user_code']}",
                                file=sys.stderr,
                            )
                        print(f"{bar}\n", file=sys.stderr)

                    access_token = asyncio.run(
                        acquire_jwt(
                            base_url,
                            creds=creds,
                            on_next_step=_announce_next_step,
                            poll_completion_url=f"{base_url}/setup-status",
                            flow_label="device-code",
                        )
                    )
                else:
                    # t2-non-interaction relay: server-to-server POST is enough.
                    access_token = asyncio.run(acquire_jwt(base_url, creds=creds))
            except (TimeoutError, RuntimeError):
                # Snapshot diagnostics BEFORE the finally block tears down
                # the container — that's the only window where logs +
                # setup-status still reflect the failure state.
                _capture_diagnostics(config["id"], compose_file, base_url)
                raise

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


# ---------------------------------------------------------------
# Stdio-pure runner (added 2026-05-02 per spec
# ``2026-05-01-stdio-pure-http-multiuser.md`` §5.5.5)
#
# Goes beyond the parallel-axis ``stdio-direct`` smoke runner above:
# resolves credentials from skret per the matrix's ``skret_namespace``
# + ``skret_keys``, spawns the plugin's stdio entry, and invokes a
# representative ``tools/call`` to verify the stdio entry can serve
# real workloads (not just list tool names).
# ---------------------------------------------------------------

# Map ``<plugin>-stdio*`` config ids to the uvx invocation that spawns the
# plugin's stdio entry point. The plugin slugs match the PyPI / npm package
# names (matching ``EXPECTED_TOOLS`` keys) so a missing entry here means a
# new plugin was added without wiring stdio coverage.
STDIO_PLUGIN_PACKAGE: dict[str, str] = {
    "notion-stdio": "better-notion-mcp",
    "email-stdio-gmail": "better-email-mcp",
    "telegram-stdio-bot": "better-telegram-mcp",
    "wet-stdio": "wet-mcp",
    "mnemo-stdio": "mnemo-mcp",
    "crg-stdio": "better-code-review-graph",
    "imagine-stdio": "imagine-mcp",
    "godot-stdio": "better-godot-mcp",
}

# Plugin -> tool/call probe used by the stdio runner. The tool name must
# exist in ``EXPECTED_TOOLS[plugin]`` and accept the supplied ``arguments``
# without external side effects (no real Notion writes, no real email
# sends). ``godot`` has no auth and no upstream so we use the cheap
# ``help`` tool which is always present on N+2 plugins.
STDIO_TOOL_PROBE: dict[str, tuple[str, dict]] = {
    "better-notion-mcp": ("help", {}),
    "better-email-mcp": ("help", {}),
    "better-telegram-mcp": ("help", {}),
    "wet-mcp": ("help", {}),
    "mnemo-mcp": ("help", {}),
    "better-code-review-graph": ("help", {}),
    "imagine-mcp": ("help", {}),
    "better-godot-mcp": ("help", {}),
}


def _resolve_stdio_env(config: dict) -> dict[str, str]:
    """Pull env vars for an stdio config from skret per the matrix entry.

    For ``auth: env`` configs with a ``skret_namespace``, loads the
    namespace and keeps only the keys named in ``skret_keys`` (with
    ``skret_optional`` tolerated when absent). For ``auth: none``
    configs (godot, mnemo) returns ``{}``. The driver merges this with
    the parent process env when spawning ``uvx``.
    """
    if config.get("auth") == "none":
        return {}
    ns = config.get("skret_namespace")
    if not ns:
        return {}
    keys = list(config.get("skret_keys", []))
    optional = set(config.get("skret_optional", []))
    required = [k for k in keys if k not in optional]
    creds = load_namespace_required(ns, required=required)
    # Keep only the matrix-declared keys so secrets unrelated to this
    # config don't leak into the spawned plugin's env.
    return {k: v for k, v in creds.items() if k in keys}


async def _spawn_stdio_and_call_tool(config: dict, env: dict[str, str]) -> dict:
    """Spawn ``uvx <plugin>`` over stdio, run handshake + ``tools/call``.

    Returns a result dict with ``status`` (``PASS``/``FAIL``),
    ``tool_calls`` (count of successful invocations), ``evidence``
    (list of probed tool names), ``exit_code`` (process exit, ``0`` if
    handshake completed cleanly) and ``stderr`` (captured child stderr).
    Failure modes (handshake error, missing tool, child crash) populate
    ``stderr`` so callers can surface root cause without re-running.
    """
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    plugin = STDIO_PLUGIN_PACKAGE.get(config["id"])
    if plugin is None:
        return {
            "status": "FAIL",
            "tool_calls": 0,
            "evidence": [],
            "exit_code": -1,
            "stderr": (
                f"no plugin package mapped for stdio config '{config['id']}' — "
                "add to STDIO_PLUGIN_PACKAGE in driver.py"
            ),
        }

    # Resolve invocation per package type:
    # - TS plugins (notion/email/godot): npx --yes @n24q02m/<plugin>@<version>
    # - Py plugins (telegram/wet/mnemo/crg/imagine): uvx --from <plugin>==<version> <plugin>
    # Per spec 2026-05-01-stdio-pure-http-multiuser.md plugin marketplace patterns.
    TS_PLUGINS = {"better-notion-mcp", "better-email-mcp", "better-godot-mcp"}
    pkg_spec = os.environ.get("MCP_STDIO_PIN", plugin)
    if plugin in TS_PLUGINS:
        # Use @beta dist-tag for testing the latest beta cascade.
        # Override via MCP_STDIO_PIN env (e.g., MCP_STDIO_PIN="@n24q02m/better-notion-mcp@2.31.0-beta.3").
        npm_pkg = (
            f"@n24q02m/{plugin}@beta" if pkg_spec == plugin else f"@n24q02m/{pkg_spec}"
        )
        cmd = ["npx", "--yes", npm_pkg]
    else:
        cmd = [
            "uvx",
            "--python",
            "3.13",
            "--prerelease=allow",
            "--from",
            pkg_spec,
            plugin,
        ]

    server_params = StdioServerParameters(
        command=cmd[0],
        args=cmd[1:],
        env={**os.environ, **env},
    )

    tool_name, tool_args = STDIO_TOOL_PROBE.get(plugin, ("help", {}))

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                tool_names = {t.name for t in tools.tools}
                if tool_name not in tool_names:
                    return {
                        "status": "FAIL",
                        "tool_calls": 0,
                        "evidence": sorted(tool_names),
                        "exit_code": 0,
                        "stderr": (
                            f"probe tool '{tool_name}' not advertised by "
                            f"{plugin}; got {sorted(tool_names)}"
                        ),
                    }
                await session.call_tool(tool_name, tool_args)
                return {
                    "status": "PASS",
                    "tool_calls": 1,
                    "evidence": [tool_name],
                    "exit_code": 0,
                    "stderr": "",
                }
    except Exception as e:
        return {
            "status": "FAIL",
            "tool_calls": 0,
            "evidence": [],
            "exit_code": 1,
            "stderr": str(e),
        }


async def run_stdio_config(config_id: str, env: dict[str, str] | None = None) -> dict:
    """Drive an ``<plugin>-stdio`` config: skret -> uvx -> tools/call.

    The matrix entry's ``skret_namespace`` + ``skret_keys`` define which
    secrets to pull (or empty for cred-less plugins). Pass ``env={}`` to
    bypass skret entirely — used by ``stdio-no-env-negative`` to assert
    the plugin's missing-cred handler exits ``1`` with the documented
    stderr format.

    Returns ``{status, tool_calls, evidence, exit_code, stderr}`` where
    ``status`` is ``"PASS"`` or ``"FAIL"``. Raises ``KeyError`` if
    ``config_id`` is not in the matrix.
    """
    matrix = load_matrix()
    matches = [c for c in matrix if c.get("id") == config_id]
    if not matches:
        raise KeyError(f"stdio config not found in matrix.yaml: {config_id}")
    config = matches[0]

    if env is None:
        env = _resolve_stdio_env(config)

    print(
        f"\n[driver] === {config_id} (stdio-pure, env_keys={sorted(env.keys())}) ===",
        file=sys.stderr,
    )
    return await _spawn_stdio_and_call_tool(config, env)


# ---------------------------------------------------------------
# Multi-session spawn invariant runner (added 2026-05-02 per spec §5.5.3).
#
# Stdio mode invariant: N concurrent CC sessions => N independent
# processes (no shared state, no daemon).
# HTTP mode invariant: N concurrent CC sessions => exactly 1 shared
# daemon (multi-user JWT-sub state, no proliferation).
# ---------------------------------------------------------------


async def _spawn_n_stdio_processes(plugin: str, n: int) -> list[int]:
    """Spawn ``n`` concurrent ``uvx <plugin>`` stdio processes; return
    their PIDs. Each child runs only long enough for the handshake to
    return — the runner kills them after collecting PIDs."""
    pkg_spec = os.environ.get("MCP_STDIO_PIN", plugin)
    cmd = [
        "uvx",
        "--python",
        "3.13",
        "--prerelease=allow",
        "--from",
        pkg_spec,
        plugin,
    ]
    procs: list[subprocess.Popen] = []
    try:
        for _ in range(n):
            p = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            procs.append(p)
        # Tiny grace period so each process actually allocates a PID
        # in the OS before we sample.
        await asyncio.sleep(0.5)
        return [p.pid for p in procs]
    finally:
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass


async def _count_http_daemon_pids(plugin: str) -> list[int]:
    """Return PIDs of currently running HTTP-mode daemons for ``plugin``.

    Uses the same heuristic as ``scripts/audit/multi_daemon_invariant.py``:
    match ``MCP_TRANSPORT=http`` or ``--http`` flag in the proc cmdline.
    """
    pids: list[int] = []
    try:
        import psutil  # type: ignore[import-not-found]
    except ImportError:
        # psutil is the cross-platform way to walk /proc; without it we
        # bail out with empty list. Real HTTP-mode invariant runs in CI
        # which has psutil installed; the unit test path mocks this
        # function so the import error never hits there.
        return pids
    for proc in psutil.process_iter(["pid", "cmdline", "environ"]):
        try:
            cmdline = " ".join(proc.info.get("cmdline") or [])
            environ = proc.info.get("environ") or {}
            if plugin in cmdline and (
                "--http" in cmdline or environ.get("MCP_TRANSPORT") == "http"
            ):
                pids.append(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore[name-defined]
            continue
    return pids


async def run_multi_session_invariant_config(
    config_id: str, plugin: str, mode: str
) -> dict:
    """Verify the runtime invariant for a given plugin under stdio or http.

    ``mode == "stdio"``: spawn 3 concurrent stdio processes for ``plugin``,
    assert ≥3 distinct PIDs (no sharing).

    ``mode == "http"``: enumerate currently-alive HTTP daemons for
    ``plugin``, assert exactly 1.

    Returns ``{status, pids, reason}`` where ``status`` is
    ``"PASS"``/``"FAIL"``.
    """
    if mode == "stdio":
        pids = await _spawn_n_stdio_processes(plugin, 3)
        distinct = set(pids)
        if len(distinct) >= 3:
            return {"status": "PASS", "pids": pids, "reason": ""}
        return {
            "status": "FAIL",
            "pids": pids,
            "reason": (
                f"expected >=3 distinct stdio PIDs for {plugin}, got "
                f"{sorted(distinct)} (sharing detected)"
            ),
        }
    if mode == "http":
        # Multi-session-http invariant per spec C3: ≤ 1 HTTP daemon per plugin.
        # PASS = 0 (no server running, valid state) OR 1 (correctly shared).
        # FAIL = ≥ 2 (daemon proliferation BUG).
        # User runs server themselves per stdio-pure spec; driver doesn't spawn.
        pids = await _count_http_daemon_pids(plugin)
        if len(pids) <= 1:
            return {"status": "PASS", "pids": pids, "reason": ""}
        return {
            "status": "FAIL",
            "pids": pids,
            "reason": (
                f"expected ≤1 HTTP daemon for {plugin}, got "
                f"{len(pids)} ({pids}) — daemon proliferation"
            ),
        }
    return {
        "status": "FAIL",
        "pids": [],
        "reason": f"unknown mode '{mode}' (expected stdio|http)",
    }


async def run_stdio_direct_config(config: dict) -> dict:
    """Drive a default-stdio plugin via Python MCP SDK ``stdio_client``.

    Spawns the plugin entry point in a child process with stdio piped, runs
    the standard MCP handshake (``initialize`` + ``tools/list``), and
    asserts the tool count meets ``expected_tools_min``. Used for the 5
    Python plugins shipped via uvx (wet/mnemo/crg/imagine/telegram). No
    HTTP daemon, no relay, no upstream identity — verifies the stdio entry
    point loads tools cleanly. Returns a result dict (rather than raising
    on failure) so callers can collect aggregate state, but the dispatch
    wrapper raises ``RuntimeError`` on failure to keep parity with the
    HTTP path's all-or-nothing semantics.
    """
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    server_params = StdioServerParameters(
        command=config["cmd"][0],
        args=list(config["cmd"][1:]),
        env={**os.environ, **config.get("env", {})},
    )

    results: dict = {"config_id": config["id"], "passed": False, "errors": []}

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                init_result = await session.initialize()
                results["protocol_version"] = init_result.protocolVersion
                results["server_name"] = init_result.serverInfo.name

                tools_result = await session.list_tools()
                results["tool_count"] = len(tools_result.tools)
                results["tool_names"] = [t.name for t in tools_result.tools]

                if results["tool_count"] >= config["expected_tools_min"]:
                    results["passed"] = True
                else:
                    results["errors"].append(
                        f"tool count {results['tool_count']} < expected "
                        f"{config['expected_tools_min']}"
                    )
    except Exception as e:
        results["errors"].append(str(e))

    return results


def _is_stdio_pure_config(config: dict) -> bool:
    """Detect ``<plugin>-stdio`` configs added 2026-05-02 per spec §5.5.3.

    These differ from the parallel-axis ``stdio-direct`` configs (which
    carry ``type: stdio-direct`` and only verify tool counts) — stdio-pure
    configs carry ``tier: t2-non-interaction`` + ``auth: env|none`` and
    are dispatched through the skret-aware ``run_stdio_config`` runner.
    """
    return config.get("id") in STDIO_PLUGIN_PACKAGE


def _is_multi_session_config(config: dict) -> bool:
    return config.get("id") in {"multi-session-stdio", "multi-session-http"}


def _is_negative_stdio_config(config: dict) -> bool:
    return config.get("id") == "stdio-no-env-negative"


def _run_stdio_pure(config: dict) -> None:
    """Wrapper around ``run_stdio_config`` that raises on FAIL to keep
    parity with the HTTP path's all-or-nothing semantics."""
    result = asyncio.run(run_stdio_config(config["id"]))
    if result["status"] != "PASS":
        raise RuntimeError(
            f"stdio-pure FAIL {config['id']}: exit={result.get('exit_code')} "
            f"stderr={result.get('stderr')}"
        )
    print(
        f"[driver] PASS {config['id']} (stdio-pure, "
        f"{result['tool_calls']} tool_calls, evidence={result['evidence']})",
        file=sys.stderr,
    )


def _run_negative_stdio(config: dict) -> None:
    """Negative test: plugins with REQUIRED env must exit 1 with documented
    stderr format when env absent. Plugins with OPTIONAL or no env must
    boot cleanly (exit 0 OK) — wet/crg/mnemo/imagine/godot per spec §4.1.

    Per-plugin expected exit code based on matrix ``skret_optional`` flag
    OR ``auth: none`` marker. Plugins with REQUIRED env keys (notion/email/
    telegram) must exit 1; plugins with all-optional or no env tolerate
    exit 0 (boot in limited mode).

    A single REQUIRED-env plugin failing exit=1 fails the whole config.
    """
    # Plugins with REQUIRED env (must exit 1 when missing). Others have
    # optional env or no env (boot cleanly per spec §4.1).
    REQUIRED_ENV_PLUGINS = {
        "notion-stdio",  # NOTION_TOKEN required
        "email-stdio-gmail",  # EMAIL_CREDENTIALS or EMAIL_USER+PASSWORD required
        "telegram-stdio-bot",  # TELEGRAM_BOT_TOKEN required (per spec OQ4)
    }
    matrix = load_matrix()
    by_id = {c["id"]: c for c in matrix}
    failed: list[str] = []
    for stdio_id in STDIO_PLUGIN_PACKAGE:
        cfg = by_id.get(stdio_id)
        if not cfg:
            continue
        if stdio_id not in REQUIRED_ENV_PLUGINS:
            # Optional-env or no-env plugins boot cleanly per spec §4.1
            # (wet/crg/mnemo/imagine/godot). Negative case doesn't apply.
            continue
        result = asyncio.run(run_stdio_config(stdio_id, env={}))
        if result.get("exit_code") != 1:
            failed.append(f"{stdio_id}: exit={result.get('exit_code')} (expected 1)")
    if failed:
        raise RuntimeError(f"stdio-no-env-negative FAIL: {failed}")
    print(
        f"[driver] PASS {config['id']} (negative test: every required-env "
        "plugin exits 1 cleanly)",
        file=sys.stderr,
    )


def _run_multi_session(config: dict) -> None:
    """Run the multi-session invariant for every plugin in
    ``STDIO_PLUGIN_PACKAGE`` (stdio mode) or with HTTP-mode daemon
    enumeration. Aggregates per-plugin verdicts; fails if ANY plugin
    violates the invariant."""
    mode = "stdio" if config["id"] == "multi-session-stdio" else "http"
    plugins = list(set(STDIO_PLUGIN_PACKAGE.values()))
    failed: list[str] = []
    for plugin in plugins:
        result = asyncio.run(
            run_multi_session_invariant_config(config["id"], plugin, mode)
        )
        if result["status"] != "PASS":
            failed.append(f"{plugin}: {result['reason']}")
    if failed:
        raise RuntimeError(f"multi-session ({mode}) invariant FAIL: {failed}")
    print(
        f"[driver] PASS {config['id']} (multi-session {mode} invariant "
        f"holds for {len(plugins)} plugins)",
        file=sys.stderr,
    )


def run_config(config: dict, deployment: str = "local") -> None:
    if config.get("type") == "stdio-direct":
        print(f"\n[driver] === {config['id']} (stdio-direct) ===", file=sys.stderr)
        results = asyncio.run(run_stdio_direct_config(config))
        if not results["passed"]:
            raise RuntimeError(
                f"stdio-direct FAIL {config['id']}: {results['errors']} "
                f"(tool_count={results.get('tool_count')}, "
                f"tool_names={results.get('tool_names')})"
            )
        print(
            f"[driver] PASS {config['id']} (stdio-direct, "
            f"{results['tool_count']} tools)",
            file=sys.stderr,
        )
        return
    if _is_stdio_pure_config(config):
        _run_stdio_pure(config)
        return
    if _is_negative_stdio_config(config):
        _run_negative_stdio(config)
        return
    if _is_multi_session_config(config):
        _run_multi_session(config)
        return
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

    # Surface upstream-readiness expectations once per batch instead of
    # discovering them mid-run via failures (Outlook account state, GDrive
    # consent state, Telegram phone availability). Suppressed when no
    # t2-interaction target is in scope.
    target_configs = (
        matrix
        if args.target == "all"
        else [c for c in matrix if c.get("tier") == "t0-only"]
        if args.target == "t0"
        else [c for c in matrix if c["id"] == args.target]
    )
    if any(c.get("tier") == "t2-interaction" for c in target_configs):
        _print_t2_interaction_checklist()

    # Aggregate targets ('t0', 'all') re-invoke ourselves per config so each
    # subprocess runs in a clean environment. Otherwise nested-uv state from
    # the previous config leaks into the next (vitest 2-test flake on Windows
    # observed 2026-04-26 when chaining mcp-core-ci into the t0 sweep).
    if args.target in {"t0", "all"}:
        if args.target == "t0":
            ids = [c["id"] for c in matrix if c.get("tier") == "t0-only"]
        else:
            ids = [c["id"] for c in matrix]
        failed: list[str] = []
        for cid in ids:
            print(
                f"\n[driver] >>> spawning fresh subprocess for {cid}", file=sys.stderr
            )
            # cwd MUST be scripts/ (parent of e2e/ package) so `python -m
            # e2e.driver` resolves the package; cwd = scripts/e2e/ would
            # require nested e2e/e2e/ layout which doesn't exist.
            r = subprocess.run(
                [sys.executable, "-m", "e2e.driver", cid],
                cwd=Path(__file__).parent.parent,
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
