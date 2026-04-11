"""Machine ID and username detection (cross-platform)."""

import getpass
import os
import platform
import re
import socket
import subprocess
import uuid


def get_machine_id() -> str:
    """Get a stable machine identifier.

    Platform-specific:
    - Linux: /etc/machine-id
    - macOS: IOPlatformUUID via ioreg
    - Windows: MachineGuid from registry

    Falls back to hostname + first MAC address.

    Returns:
        Machine identifier string.
    """
    system = platform.system()
    try:
        if system == "Linux":
            with open("/etc/machine-id") as f:
                return f.read().strip()

        if system == "Darwin":
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            match = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', result.stdout)
            if match:
                return match.group(1)

        if system == "Windows":
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    r"HKLM\SOFTWARE\Microsoft\Cryptography",
                    "/v",
                    "MachineGuid",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            match = re.search(r"MachineGuid\s+REG_SZ\s+(\S+)", result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass

    # Fallback: hostname + first MAC address
    mac = _get_first_mac()
    return f"{socket.gethostname()}-{mac}"


def _get_first_mac() -> str:
    """Get first non-loopback MAC address, or 'unknown'."""
    try:
        mac_int = uuid.getnode()
        # uuid.getnode() returns a random MAC if it can't find one,
        # indicated by the multicast bit being set
        if (mac_int >> 40) & 1:
            return "unknown"
        mac_str = ":".join(
            f"{(mac_int >> (8 * i)) & 0xFF:02x}" for i in range(5, -1, -1)
        )
        if mac_str == "00:00:00:00:00:00":
            return "unknown"
        return mac_str
    except Exception:
        return "unknown"


def get_username() -> str:
    """Get current OS username.

    Returns:
        Username string.
    """
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
