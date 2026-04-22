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

import subprocess
import sys
import time
from pathlib import Path

from loguru import logger

from mcp_core.lifecycle.lock import LifecycleLock


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
    """Spawn a daemon in a detached background process."""
    logger.debug(f"Spawning daemon: {daemon_cmd}")
    if sys.platform == "win32":
        # CREATE_NO_WINDOW (0x08000000) | CREATE_NEW_PROCESS_GROUP (0x200)
        # We use CREATE_NO_WINDOW instead of DETACHED_PROCESS to prevent popping up terminals
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) | 0x00000200
        subprocess.Popen(
            daemon_cmd,
            creationflags=creation_flags,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        subprocess.Popen(
            daemon_cmd,
            start_new_session=True,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def run_smart_stdio_proxy(
    server_name: str,
    daemon_cmd: list[str],
    startup_timeout: float = 15.0,
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

    Returns:
        Exit code (0 = success, 1 = daemon failed to start, 2 = HTTP error).
    """
    import queue
    import threading

    import httpx

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
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    # Prefer env-override, fall back to lock-file token
    effective_token = "" or token
    if effective_token:
        headers["Authorization"] = f"Bearer {effective_token}"

    # 3. Forward stdin → HTTP POST → stdout
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

    with httpx.Client(timeout=30.0) as client:
        while True:
            line = line_queue.get()
            if line is None:
                return 0
            try:
                resp = client.post(url, content=line, headers=headers)
                sys.stdout.buffer.write(resp.content)
                if not resp.text.endswith("\n"):
                    sys.stdout.buffer.write(b"\n")
                sys.stdout.buffer.flush()
            except httpx.ConnectError:
                # Daemon died. Try to reconnect once by re-probing lock files.
                result = get_active_daemon(server_name)
                if result is None:
                    sys.stderr.write(f"[stdio-proxy] Daemon {server_name!r} died unexpectedly.\n")
                    return 2
                port, token = result
                url = f"http://127.0.0.1:{port}/mcp"
                if token:
                    headers["Authorization"] = f"Bearer {token}"
            except httpx.HTTPError as e:
                sys.stderr.write(f"[stdio-proxy] HTTP error: {e}\n")
                return 2
