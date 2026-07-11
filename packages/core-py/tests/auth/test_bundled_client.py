"""Tests for the bundled-client BYO resolution chain."""

from __future__ import annotations

import pytest

from mcp_core.auth.bundled_client import (
    BundledClientSpec,
    resolve_bundled_client,
    token_client_mismatch,
)

SPEC = BundledClientSpec(
    provider="google-drive",
    env_id="GOOGLE_DRIVE_CLIENT_ID",
    env_secret="GOOGLE_DRIVE_CLIENT_SECRET",
    bundled_id="bundled-id.apps.googleusercontent.com",
    bundled_secret="GOCSPX-bundled",
    use_bundled_env="USE_BUNDLED_GOOGLE_CLIENT",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (SPEC.env_id, SPEC.env_secret, SPEC.use_bundled_env):
        monkeypatch.delenv(var, raising=False)


def test_bundled_default_when_nothing_set():
    r = resolve_bundled_client(SPEC)
    assert (r.client_id, r.client_secret, r.source) == (SPEC.bundled_id, SPEC.bundled_secret, "bundled")


def test_env_pair_beats_bundled(monkeypatch):
    monkeypatch.setenv(SPEC.env_id, "my-id")
    monkeypatch.setenv(SPEC.env_secret, "my-secret")
    r = resolve_bundled_client(SPEC)
    assert (r.client_id, r.client_secret, r.source) == ("my-id", "my-secret", "env")


def test_cli_pair_beats_env(monkeypatch):
    monkeypatch.setenv(SPEC.env_id, "env-id")
    monkeypatch.setenv(SPEC.env_secret, "env-secret")
    r = resolve_bundled_client(SPEC, cli_id="cli-id", cli_secret="cli-secret")
    assert (r.client_id, r.source) == ("cli-id", "cli")


@pytest.mark.parametrize("kwargs", [{"cli_id": "only-id"}, {"cli_secret": "only-secret"}])
def test_cli_half_pair_raises(kwargs):
    with pytest.raises(ValueError, match="together"):
        resolve_bundled_client(SPEC, **kwargs)


def test_cli_half_pair_raises_even_with_valid_env(monkeypatch):
    monkeypatch.setenv(SPEC.env_id, "env-id")
    monkeypatch.setenv(SPEC.env_secret, "env-secret")
    with pytest.raises(ValueError, match="together"):
        resolve_bundled_client(SPEC, cli_id="only-id")


def test_env_half_pair_raises(monkeypatch):
    monkeypatch.setenv(SPEC.env_id, "only-id")
    with pytest.raises(ValueError, match="together"):
        resolve_bundled_client(SPEC)


def test_public_client_id_alone_ok(monkeypatch):
    spec = BundledClientSpec(
        provider="outlook",
        env_id="OUTLOOK_CLIENT_ID",
        env_secret="OUTLOOK_CLIENT_SECRET",
        bundled_id="ms-public-client",
        bundled_secret="",
        use_bundled_env="USE_BUNDLED_OUTLOOK_CLIENT",
        requires_secret=False,
    )
    monkeypatch.delenv("OUTLOOK_CLIENT_ID", raising=False)
    monkeypatch.delenv("OUTLOOK_CLIENT_SECRET", raising=False)
    monkeypatch.setenv("OUTLOOK_CLIENT_ID", "my-public-id")
    r = resolve_bundled_client(spec)
    assert (r.client_id, r.client_secret, r.source) == ("my-public-id", "", "env")


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "False", " FALSE "])
def test_kill_switch_disables_bundled(monkeypatch, value):
    monkeypatch.setenv(SPEC.use_bundled_env, value)
    with pytest.raises(RuntimeError, match="disables the bundled client"):
        resolve_bundled_client(SPEC)


def test_kill_switch_with_env_override_still_works(monkeypatch):
    monkeypatch.setenv(SPEC.use_bundled_env, "false")
    monkeypatch.setenv(SPEC.env_id, "my-id")
    monkeypatch.setenv(SPEC.env_secret, "my-secret")
    assert resolve_bundled_client(SPEC).source == "env"


def test_token_mismatch_matrix():
    assert token_client_mismatch(None, "eff-id") is False
    assert token_client_mismatch({"client_id": "eff-id"}, "eff-id") is False
    assert token_client_mismatch({"client_id": "other"}, "eff-id") is True
    assert token_client_mismatch({}, "eff-id") is True  # token không ghi client_id -> ép re-auth sạch
