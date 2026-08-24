from __future__ import annotations

import subprocess
import sys


def test_mcp_sdk_fastmcp_constructs_without_runtime_warnings() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-Werror",
            "-c",
            "from mcp.server.fastmcp import FastMCP; FastMCP('warning-check')",
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
