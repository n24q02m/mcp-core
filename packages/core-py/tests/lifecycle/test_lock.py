"""Tests for cross-process lifecycle lock."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path

import pytest

from mcp_core.lifecycle.lock import LifecycleLock


@pytest.fixture
def lock_root(tmp_path: Path) -> Path:
    """Per-test lock directory so concurrent tests don't collide."""
    root = tmp_path / "locks"
    root.mkdir(parents=True, exist_ok=True)
    return root


@pytest.fixture
def unique_name() -> str:
    """Unique server name per test (belt-and-braces alongside lock_root)."""
    return f"test-srv-{uuid.uuid4().hex[:8]}"


class TestAcquireAndRelease:
    def test_acquires_and_releases(self, lock_root: Path, unique_name: str) -> None:
        lock = LifecycleLock(name=unique_name, port=9000, root=lock_root)
        lock_file = lock_root / f"{unique_name}-9000.lock"

        with lock:
            assert lock_file.exists(), "lock file must exist while held"

        # Scaffold unlinks on __exit__, so the file should be gone after release.
        assert not lock_file.exists(), "lock file must be removed after release"

    def test_acquires_multiple_times_sequentially(self, lock_root: Path, unique_name: str) -> None:
        """After release, a fresh LifecycleLock with same (name, port) can re-acquire."""
        lock1 = LifecycleLock(name=unique_name, port=9000, root=lock_root)
        with lock1:
            pass

        lock2 = LifecycleLock(name=unique_name, port=9000, root=lock_root)
        with lock2:
            pass  # should not raise

    def test_lock_stores_pid_and_port(self, lock_root: Path, unique_name: str) -> None:
        """While held, the lock file contains the current PID and port."""
        lock = LifecycleLock(name=unique_name, port=9000, root=lock_root)
        lock_file = lock_root / f"{unique_name}-9000.lock"

        with lock:
            content = lock_file.read_text(encoding="utf-8")
            lines = [line.strip() for line in content.splitlines() if line.strip()]
            assert lines[0] == str(os.getpid()), f"expected lock file to start with pid {os.getpid()}, got {lines!r}"
            assert lines[1] == "9000", f"expected lock file to contain port 9000, got {lines!r}"

    def test_path_property_exposes_lock_file_location(self, lock_root: Path, unique_name: str) -> None:
        lock = LifecycleLock(name=unique_name, port=9000, root=lock_root)
        assert lock.path == lock_root / f"{unique_name}-9000.lock"


class TestDifferentLocksDoNotConflict:
    def test_different_ports_do_not_conflict(self, lock_root: Path, unique_name: str) -> None:
        lock_a = LifecycleLock(name=unique_name, port=9000, root=lock_root)
        lock_b = LifecycleLock(name=unique_name, port=9001, root=lock_root)

        with lock_a, lock_b:
            assert (lock_root / f"{unique_name}-9000.lock").exists()
            assert (lock_root / f"{unique_name}-9001.lock").exists()

    def test_different_names_do_not_conflict(self, lock_root: Path) -> None:
        name_a = f"srv-a-{uuid.uuid4().hex[:6]}"
        name_b = f"srv-b-{uuid.uuid4().hex[:6]}"

        lock_a = LifecycleLock(name=name_a, port=9000, root=lock_root)
        lock_b = LifecycleLock(name=name_b, port=9000, root=lock_root)

        with lock_a, lock_b:
            assert (lock_root / f"{name_a}-9000.lock").exists()
            assert (lock_root / f"{name_b}-9000.lock").exists()


def _helper_script(lock_root: Path, name: str, port: int, ready_file: Path) -> str:
    """Python source for a subprocess that holds a lock until stdin closes."""
    # Inject the src path of the installed package by using the sys.path of the
    # parent process - simplest is to rely on the parent's environment, since
    # `uv run pytest` already has mcp_core importable.
    return textwrap.dedent(
        f"""
        import sys
        from pathlib import Path
        from mcp_core.lifecycle.lock import LifecycleLock

        lock = LifecycleLock(name={name!r}, port={port}, root=Path({str(lock_root)!r}))
        with lock:
            Path({str(ready_file)!r}).write_text("ready", encoding="utf-8")
            # Block on stdin so the parent test controls when we release the lock.
            sys.stdin.read()
        """
    ).strip()


class TestContention:
    """Verify that a second attempt to acquire the same lock fails."""

    def test_contention_raises_across_processes(self, tmp_path: Path, lock_root: Path, unique_name: str) -> None:
        ready_file = tmp_path / "ready.txt"
        script = _helper_script(lock_root, unique_name, 9000, ready_file)

        # Launch subprocess that acquires the lock and waits on stdin.
        proc = subprocess.Popen(
            [sys.executable, "-c", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            # Wait for helper to signal it has acquired the lock.
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                if ready_file.exists():
                    break
                if proc.poll() is not None:
                    stdout, stderr = proc.communicate(timeout=1.0)
                    pytest.fail(
                        "helper process exited before acquiring lock: "
                        f"rc={proc.returncode} stdout={stdout!r} stderr={stderr!r}"
                    )
                time.sleep(0.05)
            else:
                pytest.fail("helper did not acquire lock within 10s")

            # Now try to acquire in this process - must raise.
            contender = LifecycleLock(name=unique_name, port=9000, root=lock_root)
            with pytest.raises(RuntimeError, match="another process holds"):
                with contender:
                    pass
        finally:
            # Release the helper: closing stdin makes sys.stdin.read() return.
            if proc.stdin is not None:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
            try:
                proc.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5.0)

    def test_lock_available_after_holder_releases(self, tmp_path: Path, lock_root: Path, unique_name: str) -> None:
        ready_file = tmp_path / "ready.txt"
        script = _helper_script(lock_root, unique_name, 9000, ready_file)

        proc = subprocess.Popen(
            [sys.executable, "-c", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                if ready_file.exists():
                    break
                if proc.poll() is not None:
                    stdout, stderr = proc.communicate(timeout=1.0)
                    pytest.fail(
                        "helper process exited before acquiring lock: "
                        f"rc={proc.returncode} stdout={stdout!r} stderr={stderr!r}"
                    )
                time.sleep(0.05)
            else:
                pytest.fail("helper did not acquire lock within 10s")
        finally:
            if proc.stdin is not None:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
            try:
                proc.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5.0)

        # Helper has exited, lock should be free again.
        reacquired = LifecycleLock(name=unique_name, port=9000, root=lock_root)
        with reacquired:
            pass  # must not raise
