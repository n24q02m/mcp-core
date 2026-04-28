"""Tests for the ``_setup_complete`` metadata flag plumbing.

The flag distinguishes "user has explicitly submitted the relay form" from
"config.enc has values written by a peer-share path or a partial bootstrap".
``runLocalServer`` reads it via ``is_schema_complete`` to decide whether to
auto-open the browser on startup.
"""

import pytest

from mcp_core.storage.config_file import (
    SETUP_COMPLETE_KEY,
    clear_key_cache_for_testing,
    mark_setup_complete,
    read_config,
    set_config_path,
    write_config,
)


@pytest.fixture
def isolated_config(tmp_path):
    """Point config_file at a tmp path so tests don't touch the real config.enc."""
    config_path = tmp_path / "config.enc"
    set_config_path(str(config_path))
    clear_key_cache_for_testing()
    yield config_path
    set_config_path(None)
    clear_key_cache_for_testing()


def test_setup_complete_key_constant_value(isolated_config):
    assert SETUP_COMPLETE_KEY == "_setup_complete"


def test_mark_setup_complete_sets_flag_without_losing_other_keys(isolated_config):
    write_config("demo", {"API_KEY": "k"})
    mark_setup_complete("demo")
    saved = read_config("demo")
    assert saved is not None
    assert saved[SETUP_COMPLETE_KEY] == "true"
    assert saved["API_KEY"] == "k"


def test_mark_setup_complete_works_when_no_prior_config(isolated_config):
    """First-time setup: no config exists yet. mark_setup_complete should
    create an entry with just the flag — useful for all-optional schemas."""
    mark_setup_complete("demo")
    saved = read_config("demo")
    assert saved is not None
    assert saved == {SETUP_COMPLETE_KEY: "true"}


def test_write_config_does_not_auto_carry_forward_flag(isolated_config):
    """write_config replaces the whole entry. Flag carry-forward is the
    caller's responsibility — by design."""
    write_config("demo", {"API_KEY": "k1", SETUP_COMPLETE_KEY: "true"})
    write_config("demo", {"API_KEY": "k2"})
    saved = read_config("demo")
    assert saved is not None
    assert saved["API_KEY"] == "k2"
    assert SETUP_COMPLETE_KEY not in saved


def test_mark_setup_complete_idempotent(isolated_config):
    """Calling twice produces the same end state."""
    write_config("demo", {"API_KEY": "k"})
    mark_setup_complete("demo")
    mark_setup_complete("demo")
    saved = read_config("demo")
    assert saved == {"API_KEY": "k", SETUP_COMPLETE_KEY: "true"}


def test_mark_setup_complete_does_not_pollute_other_servers(isolated_config):
    write_config("server-a", {"A": "1"})
    write_config("server-b", {"B": "2"})
    mark_setup_complete("server-a")
    a = read_config("server-a")
    b = read_config("server-b")
    assert a == {"A": "1", SETUP_COMPLETE_KEY: "true"}
    assert b == {"B": "2"}
    assert SETUP_COMPLETE_KEY not in b
