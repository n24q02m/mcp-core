"""Cross-platform browser opening with WSL detection."""

import base64
import logging
import os
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


def _env_flag(name: str) -> bool:
    """Read an on/off environment flag: set, and not ``''`` / ``'false'`` / ``'0'``.

    One rule for all three guard variables. ``CI`` has to follow it because it is
    a variable we READ from someone else's environment, where ``CI=false`` is a
    real idiom for "do not apply CI behavior" (Create React App, Netlify) -- the
    ``ci-info`` package uses the same rule. Our own two then follow it as well,
    for two reasons: a plain truthy check makes ``MCP_NO_BROWSER=false`` SUPPRESS
    the browser, which is wrong under every reading of a negative variable name
    (writing ``=false`` means "no, don't no-browser" -- that person is asking for
    auto-open and would be blocked silently), and two rules inside one condition
    is a trap for whoever reads it next.
    """
    value = os.environ.get(name)
    return value is not None and value not in ("", "false", "0")


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
    """Open URL from inside WSL using powershell.exe or wslview."""
    # Try powershell.exe -EncodedCommand first (safer due to Base64 encoding)
    if _open_in_powershell(url):
        return True

    # Fallback to wslview (from wslu package, commonly available)
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
    # Env-guard: suppress auto-open in headless / CI / autonomous-test contexts so a
    # relay/clean-state server never hijacks the user's real browser with /authorize?nonce
    # or 127.0.0.1 tabs. Set MCP_NO_BROWSER=1 (or NO_BROWSER / CI) to disable.
    # All three go through the same rule -- see _env_flag for why.
    if _env_flag("MCP_NO_BROWSER") or _env_flag("NO_BROWSER") or _env_flag("CI"):
        logger.debug("Browser open suppressed by env guard (MCP_NO_BROWSER/NO_BROWSER/CI): %s", url)
        return False

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

    try:
        # 1. WSL detection
        if _is_wsl():
            logger.debug("WSL detected, using WSL-specific browser opening")
            result = _open_in_wsl(url)
            if result:
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
        result = False

    if not result:
        import sys

        banner = f"""
\x1b[93m╔{"═" * 78}╗
║  \x1b[91mACTION REQUIRED: Browser auto-open failed.\x1b[93m {" " * 33}║
║  \x1b[97mPlease manually open this URL to continue setup:\x1b[93m {" " * 27}║
║  \x1b[36m{url:{74}s}\x1b[93m  ║
╚{"═" * 78}╝\x1b[0m
"""
        print(banner, file=sys.stderr)

    return result
