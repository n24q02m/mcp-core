class _SetupStatusManager:
    """Manages in-memory setup status for background tasks.

    Status values: "idle", "complete", or "error:<message>".
    The "error:<message>" format allows the frontend to detect failure
    and surface the message to the user.
    """

    def __init__(self) -> None:
        self._status: dict[str, str] = {"gdrive": "idle"}

    def mark_complete(self, key: str = "gdrive") -> None:
        """Mark a background setup step as complete."""
        self._status[key] = "complete"

    def mark_failed(self, key: str = "gdrive", error: str = "unknown error") -> None:
        """Mark a background setup step as failed with sanitization.

        Collapses whitespace and strips redundant "error:" prefixes to avoid
        double-prefixing in the status string.
        """
        # Sanitize: collapse whitespace so the error string is single-line
        # (the frontend inlines it).
        message = " ".join(str(error).split()) or "unknown error"

        # Strip redundant "error:" prefix if present in the message
        if message.lower().startswith("error:"):
            message = message[6:].lstrip() or "unknown error"

        self._status[key] = f"error:{message}"

    def reset_all(self) -> None:
        """Reset all status keys to "idle"."""
        for key in list(self._status.keys()):
            self._status[key] = "idle"

    def get_status(self) -> dict[str, str]:
        """Return a copy of the current status dictionary."""
        return self._status.copy()
