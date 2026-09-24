from __future__ import annotations

from mcp_core.crypto.timing import timing_safe_equal


def test_timing_safe_equal_accepts_matching_bytes_and_strings() -> None:
    assert timing_safe_equal(b"secret", b"secret") is True
    assert timing_safe_equal("secret", "secret") is True
    assert timing_safe_equal("secret", b"secret") is True


def test_timing_safe_equal_rejects_value_or_length_mismatches() -> None:
    assert timing_safe_equal(b"secret", b"secrex") is False
    assert timing_safe_equal(b"secret", b"secret-longer") is False
    assert timing_safe_equal("secret", "secret-longer") is False
