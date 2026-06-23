"""Cross-platform browser opening with WSL detection."""

import base64
import logging
import re
import subprocess
import time
import webbrowser

logger = logging.getLogger(__name__)

# Dedupe repeated try_open_browser calls for the same URL. OAuth verification
# URLs are stable (e.g. https://microsoft.com/devicelogin,
# https://www.google.com/device) so a retry loop would otherwise spawn a new
# tab per attempt. Keep a 5-minute window per URL.
_BROWSER_OPEN_DEDUPE_WINDOW_S = 5 * 60
_recent_browser_opens: dict[str, float] = {}


def _is_wsl() -> bool:
    """Detect if running inside WSL."""
    try:
        with open("/proc/version", encoding="utf-8") as f:
            version = f.read().lower()
        return "microsoft" in version or "wsl" in version
    except OSError:
        return False


def _open_in_powershell(url: str) -> bool:
    """Open URL using powershell.exe -EncodedCommand."""
    try:
        base64_url = base64.b64encode(url.encode("utf-8")).decode("ascii")
        command = f"$url = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{base64_url}')); Start-Process $url"
        encoded_command = base64.b64encode(command.encode("utf-16le")).decode("ascii")
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-EncodedCommand", encoded_command],
            check=True,
            capture_output=True,
            timeout=10,
        )
        return True
    except (FileNotFoundError, subprocess.SubprocessError):
        return False


def _open_in_wsl(url: str) -> bool:
    """Open URL from inside WSL using wslview or powershell.exe."""
    # Try wslview first (from wslu package, commonly available)
    try:
        subprocess.run(
            ["wslview", url],
            check=True,
            capture_output=True,
            timeout=10,
        )
        return True
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    # Fallback to powershell.exe -EncodedCommand
    return _open_in_powershell(url)


def _print_failure_banner(url: str) -> None:
    """Print a terminal banner with the URL when auto-open fails."""
    import sys

    banner = f"""
[93m╔{"═" * 78}╗
║  [91mACTION REQUIRED: Browser auto-open failed.[93m {" " * 33}║
║  [97mPlease manually open this URL to continue setup:[93m {" " * 27}║
║  [36m{url:{74}s}[93m  ║
╚{"═" * 78}╝[0m
"""
    print(banner, file=sys.stderr)


def _open_browser_action(url: str) -> bool:
    """Execute the cross-platform browser opening logic. Never raises."""
    try:
        # 1. WSL detection
        if _is_wsl():
            logger.debug("WSL detected, using WSL-specific browser opening")
            if _open_in_wsl(url):
                return True
            logger.debug("WSL browser opening failed, falling through to webbrowser")

        # 2. Standard webbrowser
        result = webbrowser.open(url)
        if result:
            logger.debug("Opened browser via webbrowser.open()")
        else:
            logger.debug("webbrowser.open() returned False")
        return result
    except Exception as err:
        logger.debug("Failed to open browser: %s", err)
        return False


def try_open_browser(url: str) -> bool:
    """Try to open URL in default browser. Returns True if likely succeeded.

    Detection order:
    1. WSL: check /proc/version for Microsoft/WSL, use 'wslview' or 'powershell.exe'
    2. Standard: webbrowser.open()

    Never raises. Returns False on failure.

    Args:
        url: The URL to open.

    Returns:
        True if the browser was likely opened, False otherwise.
    """
    # Validate URL
    if not re.match(r"^https?://[a-zA-Z0-9-._~:/?#\[\]@!&'*+,;=%]+$", url, re.IGNORECASE):
        logger.debug("Invalid URL for browser open: %s", url)
        return False

    now = time.monotonic()
    last_opened = _recent_browser_opens.get(url)
    if last_opened is not None and now - last_opened < _BROWSER_OPEN_DEDUPE_WINDOW_S:
        logger.debug("Skipping duplicate browser open for %s", url)
        return True
    _recent_browser_opens[url] = now

    result = _open_browser_action(url)
    if not result:
        _print_failure_banner(url)

    return result
