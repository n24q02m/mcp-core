"""Cross-platform browser opening with WSL detection."""

import logging
import re
import subprocess
import webbrowser

logger = logging.getLogger(__name__)


def _is_wsl() -> bool:
    """Detect if running inside WSL."""
    try:
        with open("/proc/version", encoding="utf-8") as f:
            version = f.read().lower()
        return "microsoft" in version or "wsl" in version
    except OSError:
        return False


def _open_in_wsl(url: str) -> bool:
    """Open URL from inside WSL using wslview or cmd.exe."""
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

    # Fallback to Explorer.exe
    try:
        subprocess.run(
            ["explorer.exe", url],
            check=True,
            capture_output=True,
            timeout=10,
        )
        return True
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    return False


def _validate_url(url: str) -> bool:
    """Validate that URL is safe to open."""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return False
    # Filter out shell metacharacters that are not typically valid in URIs
    # and could be used for command injection. Note: & is valid in URLs.
    if re.search(r'[|<>"\'`\\]', url):
        return False
    return True

def try_open_browser(url: str) -> bool:
    """Try to open URL in default browser. Returns True if likely succeeded.

    Detection order:
    1. WSL: check /proc/version for Microsoft/WSL, use 'wslview' or 'cmd.exe /c start'
    2. Standard: webbrowser.open()

    Never raises. Returns False on failure.

    Args:
        url: The URL to open.

    Returns:
        True if the browser was likely opened, False otherwise.
    """
    if not _validate_url(url):
        logger.warning("Refused to open invalid or unsafe URL: %s", url)
        return False

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
