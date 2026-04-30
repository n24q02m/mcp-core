"""Smart Stdio Proxy.

Implements the "Smart Daemon Manager" pattern: when an IDE spawns this via
stdio, it checks if the background HTTP daemon is running (by probing the
OS-level LifecycleLocks). If not, it spawns the daemon detached. It then
forwards stdin/stdout JSON-RPC to the daemon's HTTP /mcp endpoint.

Lock file format (written by run_local_server):
    {pid}\\n{port}\\n{token}\\n<padding>

The token is a long-lived RS256 JWT issued at daemon startup. The proxy reads
it from the lock file (without acquiring the lock) so it can authenticate
against the daemon's BearerMCPApp without going through the browser OAuth flow.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
from filelock import FileLock, Timeout
from loguru import logger

from mcp_core.lifecycle.lock import LifecycleLock


@dataclass
class _SseEvent:
    event: str
    data: str


def _iter_sse(response: httpx.Response) -> Iterator[_SseEvent]:
    """Yield parsed SSE events from an already-opened ``httpx.Response`` stream.

    Replaces ``httpx_sse.connect_sse`` which unconditionally overwrites the
    ``Accept`` header to ``text/event-stream`` — that breaks MCP Streamable
    HTTP servers (FastMCP 3.2+) which require
    ``Accept: application/json, text/event-stream`` and return 406 otherwise.

    SSE format per the WHATWG spec: events are separated by blank lines; each
    event is a sequence of ``field: value`` lines. We track only ``event``
    and ``data`` since the MCP transport doesn't use ``id``/``retry``.
    """
    event_name = "message"
    data_parts: list[str] = []

    def _flush() -> Iterator[_SseEvent]:
        nonlocal event_name, data_parts
        if data_parts:
            yield _SseEvent(event=event_name, data="\n".join(data_parts))
        event_name = "message"
        data_parts = []

    for raw in response.iter_lines():
        # ``iter_lines`` strips the newline but returns "" for blank separator lines.
        line = raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
        if line == "":
            yield from _flush()
            continue
        if line.startswith(":"):
            # Comment line — ignore.
            continue
        if ":" in line:
            field, _, value = line.partition(":")
            value = value[1:] if value.startswith(" ") else value
        else:
            field, value = line, ""
        if field == "event":
            event_name = value
        elif field == "data":
            data_parts.append(value)
        # Other fields (id, retry) intentionally ignored.

    # Final flush if stream ended without trailing blank line.
    yield from _flush()


def _current_mcp_core_version() -> str:
    """Return the installed ``n24q02m-mcp-core`` version, or ``0.0.0`` if unknown.

    Used by ``load_capabilities_cache`` to invalidate stale caches after an
    upgrade — a cache produced by mcp-core 1.9.0 is unsafe to serve once the
    user installs 2.0.0 because the protocol or capabilities surface may
    have changed.
    """
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("n24q02m-mcp-core")
    except PackageNotFoundError:
        return "0.0.0"


def cache_path_for_lock(lock_path: Path) -> Path:
    """Cache file lives next to the lock file with a ``.tools.json`` suffix.

    Co-locating cache + lock makes cleanup trivial: deleting a stale lock by
    its filename pattern can also delete its companion cache without a
    separate sweep step.
    """
    return lock_path.with_suffix(".tools.json")


def persist_capabilities_cache(
    lock_path: Path,
    server_name: str,
    server_version: str,
    capabilities: dict,
    tools: list[dict],
) -> None:
    """Write the daemon's MCP capabilities + ``tools/list`` response to disk.

    Called once after FastMCP fully initializes. Subsequent stdio-proxy
    invocations can serve ``initialize`` and ``tools/list`` immediately from
    this cache while the daemon is cold-starting, so Claude Code sees the
    full tool surface within ~1s of session start instead of ~30-60s.
    """
    payload = {
        "serverInfo": {"name": server_name, "version": server_version},
        "capabilities": capabilities,
        "tools": tools,
    }
    cache_path = cache_path_for_lock(lock_path)
    cache_path.write_text(json.dumps(payload), encoding="utf-8")


def load_capabilities_cache(lock_path: Path, validate_version: bool = False) -> dict | None:
    """Read cached capabilities. Returns None if the file is missing, malformed,
    or — when ``validate_version`` is True — written by a different mcp-core
    version. Callers serving handshake requests from the cache should pass
    ``validate_version=True`` to avoid serving stale tool surfaces after an
    upgrade.
    """
    cache_path = cache_path_for_lock(lock_path)
    if not cache_path.exists():
        return None
    try:
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if validate_version:
        cached_version = cache.get("serverInfo", {}).get("version")
        if cached_version != _current_mcp_core_version():
            return None
    return cache


def handle_initialize_from_cache(lock_path: Path, request: dict) -> dict | None:
    """Build a JSON-RPC ``initialize`` response from cached capabilities.

    Returns ``None`` when no usable cache exists (caller should bridge to the
    live daemon instead). The cache is validated against the running mcp-core
    version, so an upgraded core never serves stale handshake responses.
    """
    cache = load_capabilities_cache(lock_path, validate_version=True)
    if cache is None:
        return None
    params = request.get("params") or {}
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": {
            "protocolVersion": params.get("protocolVersion", "2025-11-25"),
            # Capability dict (incl. listChanged) sourced from cache;
            # persist_capabilities_cache writes True per D17.1.
            "capabilities": cache.get("capabilities", {}),
            "serverInfo": cache.get("serverInfo", {}),
        },
    }


def handle_tools_list_from_cache(lock_path: Path, request: dict) -> dict | None:
    """Build a JSON-RPC ``tools/list`` response from cached tools.

    Returns ``None`` when no usable cache exists (caller bridges to live
    daemon instead). Uses the same version-validated cache loader as
    ``handle_initialize_from_cache``.
    """
    cache = load_capabilities_cache(lock_path, validate_version=True)
    if cache is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": {"tools": cache.get("tools", [])},
    }


def daemon_relay_url(server_name: str) -> str:
    """Return the relay form URL for the alive daemon of ``server_name``.

    Walks the per-user lock directory, parses the first ``<server>-*.lock``
    that contains valid 4/5/6-line metadata, and constructs
    ``http://127.0.0.1:<port>/setup?token=<jwt>`` so a Bridge can render a
    user-facing setup link without going through the OAuth handshake. Used
    by D9 ``need_setup_envelope`` (Task 1.7) and by the auto-respawn flow
    in Task 1.11.

    Raises ``RuntimeError`` when no parseable lock file exists for the
    server. Callers that prefer a soft signal should call
    ``daemon_is_alive`` first.
    """
    from mcp_core.lifecycle.lock import _lock_dir, parse_lock

    locks_dir = _lock_dir()
    if not locks_dir.exists():
        raise RuntimeError(f"no alive daemon for {server_name}")
    for lock_path in locks_dir.glob(f"{server_name}-*.lock"):
        try:
            meta = parse_lock(lock_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        return f"http://127.0.0.1:{meta.port}/setup?token={meta.token}"
    raise RuntimeError(f"no alive daemon for {server_name}")


def daemon_is_alive(server_name: str) -> bool:
    """Return ``True`` when at least one parseable lock file for
    ``server_name`` references a process the OS reports as alive.

    Used by the Bridge when deciding whether ``need_setup`` envelopes
    should bridge to a live daemon or trigger an auto-respawn.
    """
    from mcp_core.lifecycle.lock import _is_alive, _lock_dir, parse_lock

    locks_dir = _lock_dir()
    if not locks_dir.exists():
        return False
    for lock_path in locks_dir.glob(f"{server_name}-*.lock"):
        try:
            meta = parse_lock(lock_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if _is_alive(meta):
            return True
    return False


def daemon_cred_state(server_name: str) -> str:
    """Return the latest known ``cred_state`` for ``server_name``.

    Reads the first parseable lock file and returns its 5th line. Returns
    ``"unconfigured"`` if no lock exists, so callers can branch safely on
    a single string without nullable handling.
    """
    from mcp_core.lifecycle.lock import _lock_dir, parse_lock

    locks_dir = _lock_dir()
    if not locks_dir.exists():
        return "unconfigured"
    for lock_path in locks_dir.glob(f"{server_name}-*.lock"):
        try:
            meta = parse_lock(lock_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        return meta.cred_state
    return "unconfigured"


# Bridge auto-respawn (D8, Task 1.11)
#
# When a tool call fails because the underlying daemon has died, the Bridge
# spawns a fresh daemon and retries — but only once per tool_call_id, so a
# pathological caller can't infinite-loop the spawn path. ``BridgeAutoRespawn``
# tracks the per-call cap; ``daemon_respawn`` performs the actual spawn under
# a cross-process file lock so concurrent bridges don't race to spawn N
# daemons for the same server.
MAX_RESPAWN_PER_CALL_ID = 1
_RESPAWN_TRACK_TTL_SEC = 5 * 60


def _respawn_lock_path() -> Path:
    """Path of the file lock guarding ``daemon_respawn``.

    Co-located with the per-user lock directory so a single ``rm -rf`` of the
    user's mcp config wipes lock state too. Created lazily by ``FileLock``;
    we materialize the parent directory at module import time below.
    """
    return Path.home() / ".config" / "mcp" / "locks" / ".respawn.lock"


_respawn_lock_path().parent.mkdir(parents=True, exist_ok=True)
_respawn_lock = FileLock(str(_respawn_lock_path()))


class BridgeAutoRespawn:
    """Per-bridge tracker capping respawn attempts per ``tool_call_id``.

    A bridge instance keeps one of these for the lifetime of an MCP session.
    Each unique ``tool_call_id`` is allowed exactly ``MAX_RESPAWN_PER_CALL_ID``
    respawn attempt; subsequent attempts within ``_RESPAWN_TRACK_TTL_SEC``
    are rejected so a bug in the caller can't spawn-storm the daemon.
    Entries older than the TTL are discarded on read so the table doesn't
    grow without bound.
    """

    def __init__(self) -> None:
        self._respawned: dict[str, float] = {}

    def can_respawn(self, call_id: str) -> bool:
        ts = self._respawned.get(call_id)
        if ts is None:
            return True
        if time.time() - ts > _RESPAWN_TRACK_TTL_SEC:
            del self._respawned[call_id]
            return True
        return False

    def mark_respawned(self, call_id: str) -> None:
        self._respawned[call_id] = time.time()


def _spawn_daemon_detached(server_name: str) -> str:
    """Spawn ``uvx <server_name>`` detached from the current process group.

    Production wiring intentionally minimal: the daemon publishes its lock
    file as part of normal startup, so callers poll ``daemon_is_alive`` /
    ``daemon_relay_url`` to discover it. Tests monkeypatch this function so
    the test suite never spawns real subprocesses.
    """
    if sys.platform == "win32":
        # CREATE_NO_WINDOW (0x08000000) | CREATE_NEW_PROCESS_GROUP (0x200) —
        # match the flags ``_spawn_daemon`` uses in the run_smart_stdio_proxy
        # path so behaviour stays consistent for the user.
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) | 0x00000200
        subprocess.Popen(
            ["uvx", server_name],
            creationflags=creation_flags,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        subprocess.Popen(
            ["uvx", server_name],
            start_new_session=True,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    # Readiness is asserted by ``_wait_daemon_ready`` polling
    # ``daemon_is_alive`` against the lock file the spawned daemon writes.
    return ""


def _wait_daemon_ready(server_name: str, timeout: int = 60) -> bool:
    """Poll ``daemon_is_alive`` until alive or ``timeout`` seconds elapse."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if daemon_is_alive(server_name):
            return True
        time.sleep(0.5)
    return False


def daemon_respawn(server_name: str) -> str:
    """Respawn a dead daemon for ``server_name`` and return its relay URL.

    Serialized through ``_respawn_lock`` so that two bridges noticing the
    same dead daemon in the same instant don't spawn two daemons. The
    runner that wins the lock spawns; losers wait on the lock release and
    then read the relay URL the winner produced. If the lock can't be
    acquired within 10 seconds we assume a sibling is already in the
    middle of a spawn and just wait for the daemon to come up.
    """
    try:
        with _respawn_lock.acquire(timeout=10):
            # Double-check inside the lock: another process holding the
            # lock just before us may already have spawned a healthy daemon.
            if daemon_is_alive(server_name):
                return daemon_relay_url(server_name)
            _spawn_daemon_detached(server_name)
            if not _wait_daemon_ready(server_name, timeout=60):
                raise RuntimeError(f"daemon respawn timeout for {server_name}")
            return daemon_relay_url(server_name)
    except Timeout:
        # Sibling holds the lock — wait for the daemon to come up, then
        # surface the URL it published. If the sibling itself failed,
        # readiness times out and we propagate the failure.
        if not _wait_daemon_ready(server_name, timeout=60):
            raise RuntimeError(f"sibling respawn timeout for {server_name}")
        return daemon_relay_url(server_name)


def _read_lock_metadata(lock_path: Path) -> tuple[int, str] | None:
    """Read pid, port, and token from a lock file.

    Returns:
        (port, token) if readable and non-empty, else None.
    """
    try:
        content = lock_path.read_text(encoding="utf-8").strip()
        lines = content.split("\n")
        if len(lines) < 2:
            return None
        port = int(lines[1].strip())
        token = lines[2].strip() if len(lines) > 2 else ""
        return port, token
    except (OSError, ValueError):
        return None


def _find_newest_lock(server_name: str) -> Path | None:
    """Return the most recent lock file path for ``server_name``, or None.

    Used by fast-handshake to locate a capabilities cache even before the
    proxy has confirmed the daemon is HTTP-ready. Mtime ordering means a
    fresh daemon's lock wins over a stale residue.
    """
    locks_dir = Path.home() / ".config" / "mcp" / "locks"
    if not locks_dir.exists():
        return None
    candidates = sorted(
        locks_dir.glob(f"{server_name}-*.lock"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def get_active_daemon(server_name: str) -> tuple[int, str] | None:
    """Find the active daemon for server_name.

    Probes all lock files matching the server name. If a lock is held by
    another process, that daemon is alive. Reads the token from the lock file
    metadata so the proxy can authenticate.

    Returns:
        (port, token) if a live daemon is found, else None.
    """
    locks_dir = Path.home() / ".config" / "mcp" / "locks"
    if not locks_dir.exists():
        return None

    for lock_path in sorted(locks_dir.glob(f"{server_name}-*.lock"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            port_str = lock_path.stem.split("-")[-1]
            port = int(port_str)
        except ValueError:
            continue

        # Try acquiring the lock — if it fails, the daemon is ALIVE
        try:
            with LifecycleLock(server_name, port):
                # Successfully acquired → daemon is dead, stale lock cleaned up
                pass
        except RuntimeError:
            # Lock held by another process → daemon ALIVE
            metadata = _read_lock_metadata(lock_path)
            if metadata is None:
                return port, ""
            return metadata

    return None


def _spawn_daemon(daemon_cmd: list[str]) -> None:
    """Spawn a daemon in a detached background process.

    The daemon must run in HTTP mode -- it is the backend that the proxy
    bridges to. Without a clean env, the child inherits MCP_TRANSPORT=stdio
    from the parent proxy, re-enters this same code path, and fork-bombs
    itself spawning daemons recursively until the OS exhausts handles.
    Strip stdio-mode env vars so the daemon falls into the HTTP branch of
    its own ``main()``.
    """
    import os

    logger.debug(f"Spawning daemon: {daemon_cmd}")
    daemon_env = {k: v for k, v in os.environ.items() if k not in {"MCP_TRANSPORT", "TRANSPORT_MODE"}}
    if sys.platform == "win32":
        # CREATE_NO_WINDOW (0x08000000) | CREATE_NEW_PROCESS_GROUP (0x200)
        # We use CREATE_NO_WINDOW instead of DETACHED_PROCESS to prevent popping up terminals
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) | 0x00000200
        subprocess.Popen(
            daemon_cmd,
            env=daemon_env,
            creationflags=creation_flags,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=open(Path.home() / "daemon_stderr.log", "a"),
        )
    else:
        subprocess.Popen(
            daemon_cmd,
            env=daemon_env,
            start_new_session=True,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


async def _emit_list_changed_to_stdout() -> None:
    """Write a JSON-RPC ``notifications/tools/list_changed`` notification to stdout.

    The bridge's stdout is read by Claude Code as a JSON-RPC stream; emitting
    this notification causes Claude Code to immediately re-fetch ``tools/list``
    and show the full post-config tool surface without requiring a session restart.
    """
    payload = json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
    sys.stdout.buffer.write((payload + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()


async def _poll_tools_list_changed_sentinel(
    lock_path: Path,
    on_change,
) -> None:
    """Poll ``<lock>.tools-list-changed`` every 250ms; call ``on_change`` when mtime advances.

    D17.3: The daemon touches this sentinel file after a credential write
    (via ``_refresh_capabilities_cache_after_save``).  The bridge runs this
    coroutine as a background task so Claude Code receives
    ``notifications/tools/list_changed`` within ~250ms of the relay form submit.
    """
    import asyncio

    sentinel = lock_path.with_suffix(".tools-list-changed")
    last_mtime = sentinel.stat().st_mtime if sentinel.exists() else 0.0
    while True:
        await asyncio.sleep(0.25)
        if not sentinel.exists():
            continue
        try:
            current_mtime = sentinel.stat().st_mtime
        except OSError:
            continue
        if current_mtime > last_mtime:
            last_mtime = current_mtime
            try:
                await on_change()
            except Exception:  # noqa: BLE001
                pass


def _start_poller_thread(lock_path: Path) -> object:
    """Start the sentinel poller in a daemon thread; auto-stops on bridge exit.

    D17.3: ``run_smart_stdio_proxy`` is synchronous (httpx + threading), so
    the async ``_poll_tools_list_changed_sentinel`` coroutine must run in its
    own event loop on a dedicated daemon thread. Daemon threads die when the
    main process exits, so no explicit cancellation is needed — but we document
    it here so it is never mistaken for a resource leak.
    """
    import threading

    def _run() -> None:
        import asyncio as _asyncio

        try:
            _asyncio.run(_poll_tools_list_changed_sentinel(lock_path, _emit_list_changed_to_stdout))
        except Exception:  # noqa: BLE001
            pass

    t = threading.Thread(target=_run, daemon=True, name=f"sentinel-poller-{lock_path.stem}")
    t.start()
    return t


def run_smart_stdio_proxy(
    server_name: str,
    daemon_cmd: list[str],
    startup_timeout: float | None = None,
) -> int:
    """Entry point for the Smart Stdio Proxy.

    Workflow:
    1. Look for active daemon via lock files.
    2. If none found, spawn one and wait up to startup_timeout seconds.
    3. Forward stdin/stdout JSON-RPC frames to the daemon's /mcp endpoint.

    Args:
        server_name: Name of the MCP server (e.g. "wet-mcp").
        daemon_cmd: Command to spawn if daemon is not running.
        startup_timeout: Seconds to wait for daemon lock after spawn.
            Defaults to 60s, overridable via ``MCP_STDIO_STARTUP_TIMEOUT`` env
            var. Windows + cold Python imports + busy CI workers commonly take
            30-50s for the daemon to write its lock file, so the previous
            15s default produced spurious timeouts on slow hosts.

    Returns:
        Exit code (0 = success, 1 = daemon failed to start, 2 = HTTP error).
    """
    import warnings

    warnings.warn(
        "run_smart_stdio_proxy is deprecated as of mcp-core 1.12.0. "
        "Use FastMCP.run(transport='stdio') directly for stdio mode. "
        "See: https://github.com/n24q02m/mcp-core/blob/main/docs/migration-2026-04-30.md",
        DeprecationWarning,
        stacklevel=2,
    )

    import os
    import queue
    import threading

    import httpx

    if startup_timeout is None:
        env_value = os.environ.get("MCP_STDIO_STARTUP_TIMEOUT", "")
        try:
            startup_timeout = float(env_value) if env_value else 60.0
        except ValueError:
            startup_timeout = 60.0

    # 1. Find or spawn the daemon
    result = get_active_daemon(server_name)
    if result is None:
        sys.stderr.write(f"[stdio-proxy] No active daemon for {server_name!r}. Spawning...\n")
        _spawn_daemon(daemon_cmd)

        deadline = time.time() + startup_timeout
        while time.time() < deadline:
            result = get_active_daemon(server_name)
            if result is not None:
                break
            time.sleep(0.15)

        if result is None:
            sys.stderr.write(
                f"[stdio-proxy] Daemon for {server_name!r} did not start within {startup_timeout:.0f}s. Aborting.\n"
            )
            return 1

    port, token = result
    url = f"http://127.0.0.1:{port}/mcp"
    sys.stderr.write(f"[stdio-proxy] Connected to daemon at {url}\n")

    # 2. Build auth headers
    headers: dict[str, str] = {
        "Accept": "text/event-stream",
    }
    # Prefer env-override, fall back to lock-file token
    effective_token = "" or token
    if effective_token:
        headers["Authorization"] = f"Bearer {effective_token}"

    # Fast-handshake: a cache file written by a previous (or concurrent) daemon
    # run lets us answer `initialize` and `tools/list` from disk immediately,
    # before bridging to the live HTTP daemon. The user-visible win: tools
    # appear in Claude Code's /mcp panel ~1s after session start instead of
    # 30-60s while the daemon's Python imports finish. The bridge to the
    # daemon still runs for `tools/call` and any other non-cacheable method.
    #
    # Re-find the lock NOW that the daemon is guaranteed alive (whether it was
    # pre-existing or was just spawned above). Calling _find_newest_lock before
    # the spawn/wait loop returned None for new daemons, leaving the sentinel
    # poller (D17.3) unstarted for first-run users.
    cache_lock_path = _find_newest_lock(server_name)

    # D17.3: Start sentinel poller so Claude Code receives
    # ``notifications/tools/list_changed`` within ~250ms of a credential
    # save.  The poller runs in a dedicated daemon thread (this function is
    # synchronous); daemon threads die automatically when the bridge exits so
    # no explicit cancellation is needed.
    if cache_lock_path is not None:
        _start_poller_thread(cache_lock_path)

    # 3. Forward stdin <-> HTTP SSE <-> stdout
    line_queue: queue.Queue[bytes | None] = queue.Queue()

    def _stdin_reader() -> None:
        while True:
            try:
                line = sys.stdin.buffer.readline()
            except Exception:
                line = b""
            if not line:
                line_queue.put(None)
                return
            line_queue.put(line)

    reader_thread = threading.Thread(target=_stdin_reader, daemon=True)
    reader_thread.start()

    from urllib.parse import urljoin

    pending_first_line: bytes | None = None

    while True:
        candidate = line_queue.get()
        if candidate is None:
            return 0
        cached_response = None
        try:
            request = json.loads(candidate)
        except (ValueError, TypeError):
            request = None

        if request and isinstance(request, dict) and cache_lock_path is not None:
            method = request.get("method")
            if method == "initialize":
                cached_response = handle_initialize_from_cache(cache_lock_path, request)
            elif method == "tools/list":
                cached_response = handle_tools_list_from_cache(cache_lock_path, request)
            elif method == "notifications/initialized":
                # No response expected; swallow when serving from cache so
                # we don't spuriously bridge to the daemon for a fire-and-forget
                # notification.
                continue

        if cached_response is not None:
            sys.stdout.buffer.write((json.dumps(cached_response) + "\n").encode("utf-8"))
            sys.stdout.buffer.flush()
            continue

        # First non-cacheable line — fall through to the daemon bridge below
        # using this line as the SSE-stream-establishing POST body.
        pending_first_line = candidate
        break

    if pending_first_line is None:
        return 0
    first_line = pending_first_line

    with httpx.Client(timeout=httpx.Timeout(5.0, read=300.0)) as client:
        try:
            post_headers = headers.copy()
            post_headers["Content-Type"] = "application/json"
            post_headers["Accept"] = "application/json, text/event-stream"

            with client.stream("POST", url, headers=post_headers, content=first_line) as response:
                if response.status_code != 200:
                    body = b"".join(response.iter_bytes()).decode("utf-8", "replace")
                    sys.stderr.write(f"[stdio-proxy] Initial POST {url} returned {response.status_code}: {body}\n")
                    return 2
                event_iter = _iter_sse(response)

                endpoint_url = None
                for sse in event_iter:
                    if sse.event == "endpoint":
                        endpoint_url = urljoin(url, sse.data)
                        from urllib.parse import parse_qs, urlparse

                        parsed = urlparse(endpoint_url)
                        qs = parse_qs(parsed.query)
                        if "sessionId" in qs:
                            post_headers["MCP-Session-ID"] = qs["sessionId"][0]
                        break
                    if sse.event == "message" and sse.data:
                        # Stateless mode: server emits "message" directly
                        # (FastMCP streamable HTTP with no endpoint event).
                        endpoint_url = url
                        sys.stdout.buffer.write(sse.data.encode("utf-8") + b"\n")
                        sys.stdout.buffer.flush()
                        break

                if not endpoint_url:
                    sys.stderr.write(f"[stdio-proxy] Did not receive endpoint URL from SSE at {url}\n")
                    return 2

                def _stdout_writer() -> None:
                    try:
                        for sse in event_iter:
                            if sse.event == "message" and sse.data:
                                sys.stdout.buffer.write(sse.data.encode("utf-8") + b"\n")
                                sys.stdout.buffer.flush()
                    except Exception as e:
                        sys.stderr.write(f"[stdio-proxy] SSE error: {e}\n")
                        import os

                        os._exit(1)

                writer_thread = threading.Thread(target=_stdout_writer, daemon=True)
                writer_thread.start()

                while True:
                    line = line_queue.get()
                    if line is None:
                        return 0
                    try:
                        resp = client.post(endpoint_url, content=line, headers=post_headers)
                        resp.raise_for_status()
                    except httpx.ConnectError:
                        sys.stderr.write(f"[stdio-proxy] Daemon {server_name!r} died unexpectedly.\n")
                        return 2
                    except httpx.HTTPError as e:
                        sys.stderr.write(f"[stdio-proxy] HTTP error: {e}\n")
                        return 2
        except Exception as e:
            sys.stderr.write(f"[stdio-proxy] Connection failed: {e}\n")
            # For debugging, let's do a raw HTTP request to see the error body
            try:
                sys.stderr.write(f"[stdio-proxy] Debug first_line sent to server: {first_line!r}\n")
                debug_resp = client.post(url, headers=post_headers, content=first_line)
                sys.stderr.write(f"[stdio-proxy] Debug HTTP Response: {debug_resp.status_code} {debug_resp.text}\n")
            except Exception as e2:
                sys.stderr.write(f"[stdio-proxy] Debug HTTP request failed: {e2}\n")
            return 2
