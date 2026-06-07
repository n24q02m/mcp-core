"""Tests for cross-platform browser opening."""

import base64
from unittest.mock import MagicMock, mock_open, patch

import pytest

from mcp_core.relay.browser import _is_wsl, try_open_browser


@pytest.fixture(autouse=True)
def _clear_browser_dedupe():
    """Reset the in-memory dedupe cache so each test sees a fresh module state."""
    from mcp_core.relay import browser

    browser._recent_browser_opens.clear()
    yield
    browser._recent_browser_opens.clear()


class TestIsWsl:
    def test_detects_wsl_from_proc_version(self):
        content = "Linux version 5.15.90.1-microsoft-standard-WSL2"
        with patch("builtins.open", mock_open(read_data=content)):
            assert _is_wsl() is True

    def test_detects_microsoft_in_proc_version(self):
        content = "Linux version 5.4.0-Microsoft"
        with patch("builtins.open", mock_open(read_data=content)):
            assert _is_wsl() is True

    def test_returns_false_for_regular_linux(self):
        content = "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-051)"
        with patch("builtins.open", mock_open(read_data=content)):
            assert _is_wsl() is False

    def test_returns_false_when_file_not_found(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            assert _is_wsl() is False


class TestTryOpenBrowser:
    def test_rejects_malicious_urls(self):
        malicious_urls = [
            "https://example.com;rm -rf /",
            "https://example.com$(whoami)",
            "https://example.com`whoami`",
            "https://example.com|nc localhost 4444",
            "javascript:alert(1)",
            "file:///etc/passwd",
        ]
        for url in malicious_urls:
            assert try_open_browser(url) is False

    def test_accepts_valid_urls_with_ampersands(self):
        with patch("mcp_core.relay.browser.webbrowser") as mock_wb:
            mock_wb.open.return_value = True
            url = "https://example.com/auth?code=123&state=abc"
            assert try_open_browser(url) is True

    def test_accepts_urls_with_single_quotes(self):
        with patch("mcp_core.relay.browser.webbrowser") as mock_wb:
            mock_wb.open.return_value = True
            url = "https://example.com/auth?q='hello'"
            assert try_open_browser(url) is True

    def test_returns_true_on_success(self):
        with patch("mcp_core.relay.browser._is_wsl", return_value=False):
            with patch("mcp_core.relay.browser.webbrowser") as mock_wb:
                mock_wb.open.return_value = True
                result = try_open_browser("https://example.com")
                assert result is True
                mock_wb.open.assert_called_once_with("https://example.com")

    def test_returns_false_on_failure(self):
        with patch("mcp_core.relay.browser._is_wsl", return_value=False):
            with patch("mcp_core.relay.browser.webbrowser") as mock_wb:
                mock_wb.open.return_value = False
                result = try_open_browser("https://example.com")
                assert result is False

    def test_returns_false_on_exception(self):
        with patch("mcp_core.relay.browser._is_wsl", return_value=False):
            with patch("mcp_core.relay.browser.webbrowser") as mock_wb:
                mock_wb.open.side_effect = RuntimeError("no display")
                result = try_open_browser("https://example.com")
                assert result is False

    def test_tries_wsl_first_when_in_wsl(self):
        with patch("mcp_core.relay.browser._is_wsl", return_value=True):
            with patch("mcp_core.relay.browser._open_in_wsl", return_value=True) as mock_wsl:
                result = try_open_browser("https://example.com")
                assert result is True
                mock_wsl.assert_called_once_with("https://example.com")

    def test_falls_through_to_webbrowser_when_wsl_fails(self):
        with patch("mcp_core.relay.browser._is_wsl", return_value=True):
            with patch("mcp_core.relay.browser._open_in_wsl", return_value=False):
                with patch("mcp_core.relay.browser.webbrowser") as mock_wb:
                    mock_wb.open.return_value = True
                    result = try_open_browser("https://example.com")
                    assert result is True

    def test_never_raises(self):
        with patch("mcp_core.relay.browser._is_wsl", side_effect=Exception):
            # Even if _is_wsl raises unexpectedly, try_open_browser catches it
            result = try_open_browser("https://example.com")
            assert result is False


class TestOpenInWsl:
    def test_tries_wslview_first(self):
        with patch("mcp_core.relay.browser.subprocess") as mock_sp:
            mock_sp.run = MagicMock()
            mock_sp.SubprocessError = Exception
            from mcp_core.relay.browser import _open_in_wsl

            result = _open_in_wsl("https://example.com")
            # Should return True because mock_sp.run doesn't raise
            assert result is True
            mock_sp.run.assert_called_once()
            args = mock_sp.run.call_args
            assert args[0][0][0] == "wslview"

    def test_falls_back_to_powershell_exe(self):
        with patch("mcp_core.relay.browser.subprocess") as mock_sp:
            mock_sp.SubprocessError = Exception
            call_count = 0

            def side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise FileNotFoundError
                return MagicMock()

            mock_sp.run = MagicMock(side_effect=side_effect)
            from mcp_core.relay.browser import _open_in_wsl

            result = _open_in_wsl("https://example.com")
            assert result is True
            assert mock_sp.run.call_count == 2
            # Second call should be powershell
            args = mock_sp.run.call_args
            assert args[0][0][0] == "powershell.exe"
            # WSLENV should NOT be present now
            assert "env" not in args[1]

    def test_returns_false_when_all_methods_fail(self):
        with patch("mcp_core.relay.browser.subprocess") as mock_sp:
            mock_sp.SubprocessError = Exception
            mock_sp.run = MagicMock(side_effect=FileNotFoundError)
            from mcp_core.relay.browser import _open_in_wsl

            result = _open_in_wsl("https://example.com")
            assert result is False


class TestOpenInPowerShell:
    def test_uses_secure_command_and_noprofile(self):
        with patch("mcp_core.relay.browser.subprocess") as mock_sp:
            mock_sp.SubprocessError = Exception
            from mcp_core.relay.browser import _open_in_powershell

            url = "https://example.com"
            result = _open_in_powershell(url)

            assert result is True
            mock_sp.run.assert_called_once()
            args, kwargs = mock_sp.run.call_args

            cmd_list = args[0]
            assert cmd_list[0] == "powershell.exe"
            assert "-NoProfile" in cmd_list
            assert "-NonInteractive" in cmd_list
            assert "-Command" in cmd_list

            script = cmd_list[cmd_list.index("-Command") + 1]
            base64_url_arg = cmd_list[-1]

            base64_url = base64.b64encode(url.encode("utf-8")).decode("ascii")
            assert base64_url == base64_url_arg
            assert "$args[0]" in script
            assert "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[0]))" in script
            assert "Start-Process $url" in script

            # MCP_BROWSER_URL should NOT be in env if env is passed (kwargs might be empty or not contain it)
            if "env" in kwargs:
                assert "MCP_BROWSER_URL" not in kwargs["env"]
