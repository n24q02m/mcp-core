"""Tests for mcp_embedding_daemon.__main__."""

from __future__ import annotations

import sys
from unittest.mock import patch

from mcp_embedding_daemon.__main__ import main


def test_main_uvicorn_import_error() -> None:
    """Test that main() returns 1 when uvicorn is not installed."""
    # Setting sys.modules["uvicorn"] to None triggers ImportError in Python 3
    with patch.dict(sys.modules, {"uvicorn": None}):
        with patch("sys.stderr") as mock_stderr:
            with patch("sys.argv", ["mcp-embedding-daemon"]):
                # We must ensure uvicorn is not in sys.modules, which patch.dict handles.
                # But if it was already imported by this process, we might need to be careful.
                # However, main() does 'import uvicorn' locally.

                # We need to clear uvicorn from sys.modules if it's there,
                # but patch.dict(sys.modules, {"uvicorn": None}) is the standard way to simulate missing module.
                result = main()

                assert result == 1
                # Check that the error message was written to stderr
                called_text = "".join(call.args[0] for call in mock_stderr.write.call_args_list)
                assert "uvicorn is required to run mcp-embedding-daemon" in called_text


def test_main_success() -> None:
    """Test that main() returns 0 and calls uvicorn.run with correct arguments."""
    with patch("uvicorn.run") as mock_run:
        with patch("sys.argv", ["mcp-embedding-daemon", "--host", "0.0.0.0", "--port", "8888", "--log-level", "debug"]):
            result = main()

            assert result == 0
            mock_run.assert_called_once_with(
                "mcp_embedding_daemon.api:app",
                host="0.0.0.0",
                port=8888,
                log_level="debug",
            )


def test_main_default_args() -> None:
    """Test that main() uses default arguments when none are provided."""
    with patch("uvicorn.run") as mock_run:
        with patch("sys.argv", ["mcp-embedding-daemon"]):
            result = main()

            assert result == 0
            mock_run.assert_called_once_with(
                "mcp_embedding_daemon.api:app",
                host="127.0.0.1",
                port=9800,
                log_level="info",
            )
