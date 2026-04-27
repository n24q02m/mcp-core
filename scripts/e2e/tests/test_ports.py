"""Tests for ports.allocate_port."""

from e2e.ports import allocate_port


def test_allocate_returns_port_in_valid_range() -> None:
    p = allocate_port()
    assert 1024 <= p <= 65535


def test_allocate_unique_consecutive_calls() -> None:
    a, b = allocate_port(), allocate_port()
    assert a != b


def test_allocate_returns_int() -> None:
    p = allocate_port()
    assert isinstance(p, int)
