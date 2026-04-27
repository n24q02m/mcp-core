"""Allocate ephemeral ports for local Docker compose test runs.

Asks the kernel for a free port via ``socket.bind(0)``. Race-prone but
acceptable for serial driver runs where a port is allocated and immediately
bound by Docker.
"""

from __future__ import annotations

import socket


def allocate_port() -> int:
    """Return a port number unused at the moment of the call."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
