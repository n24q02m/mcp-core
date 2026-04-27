"""Unit tests for the Task 22 driver-hardening invariants in oauth_client.

These tests pin the public contract — flow-keyed timeouts, health probe
behavior, polling progress emission — so future refactors can't silently
regress what the matrix run depends on.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from e2e import oauth_client

# ----- FLOW_TIMEOUTS lookup -----


def test_flow_timeouts_dict_matches_upstream_lifetimes():
    assert oauth_client.FLOW_TIMEOUTS["device-code"] == 900.0
    assert oauth_client.FLOW_TIMEOUTS["oauth-redirect"] == 300.0
    assert oauth_client.FLOW_TIMEOUTS["browser-form"] == 600.0


def test_get_flow_timeout_known_flows():
    assert oauth_client.get_flow_timeout("device-code") == 900.0
    assert oauth_client.get_flow_timeout("oauth-redirect") == 300.0
    assert oauth_client.get_flow_timeout("browser-form") == 600.0


def test_get_flow_timeout_unknown_or_none_uses_fallback():
    assert oauth_client.get_flow_timeout(None) == oauth_client._FALLBACK_FLOW_TIMEOUT
    assert (
        oauth_client.get_flow_timeout("made-up-flow")
        == oauth_client._FALLBACK_FLOW_TIMEOUT
    )


# ----- _health_probe -----


class _FakeAsyncClient:
    """Minimal stand-in for httpx.AsyncClient yielding scripted GET results."""

    def __init__(self, responses: dict[str, httpx.Response | Exception]):
        self.responses = responses
        self.calls: list[str] = []

    async def get(self, url: str, timeout: float = 5.0) -> httpx.Response:
        self.calls.append(url)
        result = self.responses.get(url)
        if isinstance(result, Exception):
            raise result
        if result is None:
            return httpx.Response(404)
        return result


@pytest.mark.asyncio
async def test_health_probe_succeeds_when_both_endpoints_200():
    base = "http://127.0.0.1:9999"
    fake = _FakeAsyncClient(
        {
            f"{base}/setup-status": httpx.Response(200, json={"gdrive": "idle"}),
            f"{base}/.well-known/oauth-authorization-server": httpx.Response(
                200, json={"issuer": base}
            ),
        }
    )
    await oauth_client._health_probe(fake, base)  # type: ignore[arg-type]
    assert fake.calls == [
        f"{base}/setup-status",
        f"{base}/.well-known/oauth-authorization-server",
    ]


@pytest.mark.asyncio
async def test_health_probe_fails_on_non_200():
    base = "http://127.0.0.1:9999"
    fake = _FakeAsyncClient(
        {
            f"{base}/setup-status": httpx.Response(503, text="busy"),
        }
    )
    with pytest.raises(RuntimeError, match="Health probe FAIL"):
        await oauth_client._health_probe(fake, base)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_health_probe_fails_on_http_error():
    base = "http://127.0.0.1:9999"
    fake = _FakeAsyncClient(
        {
            f"{base}/setup-status": httpx.ConnectError("refused"),
        }
    )
    with pytest.raises(RuntimeError, match="Health probe FAIL"):
        await oauth_client._health_probe(fake, base)  # type: ignore[arg-type]


# ----- _poll_until_complete progress logging -----


class _PollResponses:
    """Iterates a list of (status_code, body) tuples on each .get() call."""

    def __init__(self, sequence: list[tuple[int, dict[str, Any]]]):
        self._iter = iter(sequence)
        self.calls = 0

    async def get(self, url: str, timeout: float = 5.0) -> httpx.Response:
        self.calls += 1
        try:
            status, body = next(self._iter)
        except StopIteration:
            status, body = 200, {"gdrive": "idle"}
        return httpx.Response(status, json=body)


@pytest.mark.asyncio
async def test_poll_until_complete_returns_on_complete_value():
    fake = _PollResponses(
        [
            (200, {"gdrive": "idle"}),
            (200, {"gdrive": "complete"}),
        ]
    )
    await oauth_client._poll_until_complete(fake, "http://x/setup-status", timeout=10.0)  # type: ignore[arg-type]
    assert fake.calls == 2


@pytest.mark.asyncio
async def test_poll_until_complete_raises_on_error_value():
    fake = _PollResponses(
        [
            (200, {"gdrive": "error: invalid token"}),
        ]
    )
    with pytest.raises(RuntimeError, match="Setup failed"):
        await oauth_client._poll_until_complete(
            fake, "http://x/setup-status", timeout=10.0
        )  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_poll_until_complete_emits_progress_to_stderr(capsys, monkeypatch):
    # Force the progress interval down so the test doesn't have to wait 30s.
    monkeypatch.setattr(oauth_client, "_PROGRESS_LOG_INTERVAL", 0.0)
    fake = _PollResponses(
        [
            (200, {"gdrive": "idle"}),
            (200, {"gdrive": "complete"}),
        ]
    )

    # Patch asyncio.sleep so the test runs near-instantly.
    real_sleep = asyncio.sleep

    async def fast_sleep(_seconds):
        await real_sleep(0)

    monkeypatch.setattr(oauth_client.asyncio, "sleep", fast_sleep)

    await oauth_client._poll_until_complete(fake, "http://x/setup-status", timeout=10.0)  # type: ignore[arg-type]
    captured = capsys.readouterr()
    assert "[poll]" in captured.err
    assert "elapsed=" in captured.err
    assert "remaining=" in captured.err
    assert "status=" in captured.err


@pytest.mark.asyncio
async def test_poll_until_complete_timeout_raises(monkeypatch):
    # Sequence longer than timeout permits — every poll says idle.
    fake = _PollResponses([(200, {"gdrive": "idle"})] * 100)

    async def fast_sleep(_seconds):
        # Each "sleep" advances the clock so the deadline is hit quickly.
        pass

    monkeypatch.setattr(oauth_client.asyncio, "sleep", fast_sleep)
    # Keep timeout very short; the loop body advances time via real time.time().
    with pytest.raises(TimeoutError):
        await oauth_client._poll_until_complete(
            fake, "http://x/setup-status", timeout=0.05
        )  # type: ignore[arg-type]


# ----- _live_progress_logger cancellation behavior -----


@pytest.mark.asyncio
async def test_live_progress_logger_emits_and_cancels_cleanly(monkeypatch):
    """Task prints progress at interval, terminates cleanly on cancel.

    Uses monkeypatch instead of capsys because the logger captures the
    sys.stderr reference at print() time inside an async task, and pytest's
    capsys swaps sys.stderr per-test in a way that the already-scheduled
    task may miss. Monkeypatching directly to a StringIO sidesteps that.
    """
    import io
    import time

    buf = io.StringIO()
    monkeypatch.setattr(oauth_client.sys, "stderr", buf)

    # Function uses ``time.time()`` (wall-clock) internally — the deadline
    # MUST be from the same clock or the first iteration sees ``now >= deadline``
    # and returns immediately without printing.
    deadline = time.time() + 60.0
    task = asyncio.create_task(
        oauth_client._live_progress_logger(deadline, "test", interval=0.05)
    )
    # Yield long enough for at least 2 ticks to print.
    await asyncio.sleep(0.25)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert task.done()
    err = buf.getvalue()
    assert "[gate] test" in err, f"expected progress lines, got: {err!r}"
    assert "elapsed=" in err
    assert "remaining=" in err


# ---------------------------------------------------------------------------
# Phase C3.5: ``acquire_jwt_via_browser_form`` builds prefill query string
# from creds so the user lands on a form with skret-derived fields already
# filled (e.g. TELEGRAM_PHONE) and only types what skret cannot supply
# (OTP, 2FA password).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_browser_form_announces_url_with_prefill_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Driver must append ``&prefill_<KEY>=<VALUE>`` for each cred key.

    The user opens the URL, sees TELEGRAM_PHONE pre-filled, clicks Connect,
    and only types OTP / 2FA in the chained step UI. URL-encoding ensures
    a phone like ``+84...`` survives the query without ``+`` decoding to
    space.
    """
    captured_url: list[str] = []

    def announce(url: str) -> None:
        captured_url.append(url)

    async def fake_register(_client: object, _base: str) -> str:
        return "local-browser"

    async def fake_health(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(oauth_client, "_register_client", fake_register)
    monkeypatch.setattr(oauth_client, "_health_probe", fake_health)

    # Use a short timeout to avoid hanging the test suite. We never satisfy
    # ``code_future`` so this raises TimeoutError after the announce — but
    # the URL is captured before then.
    with pytest.raises(TimeoutError):
        await oauth_client.acquire_jwt_via_browser_form(
            "http://127.0.0.1:0",
            announce,
            timeout=0.1,
            creds={
                "TELEGRAM_PHONE": "+84123456789",
                "MCP_DCR_SERVER_SECRET": "should-be-excluded",
            },
            allowed_prefill_keys=["TELEGRAM_PHONE", "MCP_DCR_SERVER_SECRET"],
        )

    assert len(captured_url) == 1
    url = captured_url[0]
    # Phone is URL-encoded so + survives unmangled.
    assert "prefill_TELEGRAM_PHONE=%2B84123456789" in url
    # Server secret never leaks into the user-visible URL.
    assert "MCP_DCR_SERVER_SECRET" not in url


@pytest.mark.asyncio
async def test_browser_form_omits_empty_prefill_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty creds values must not produce ``prefill_KEY=`` (empty value)."""
    captured_url: list[str] = []

    def announce(url: str) -> None:
        captured_url.append(url)

    async def fake_register(_client: object, _base: str) -> str:
        return "local-browser"

    async def fake_health(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(oauth_client, "_register_client", fake_register)
    monkeypatch.setattr(oauth_client, "_health_probe", fake_health)

    with pytest.raises(TimeoutError):
        await oauth_client.acquire_jwt_via_browser_form(
            "http://127.0.0.1:0",
            announce,
            timeout=0.1,
            creds={"TELEGRAM_PHONE": "", "TELEGRAM_BOT_TOKEN": "abc"},
            allowed_prefill_keys=["TELEGRAM_PHONE", "TELEGRAM_BOT_TOKEN"],
        )

    url = captured_url[0]
    assert "prefill_TELEGRAM_PHONE=" not in url
    assert "prefill_TELEGRAM_BOT_TOKEN=abc" in url


@pytest.mark.asyncio
async def test_browser_form_filters_unrelated_skret_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SECURITY: keys NOT in ``allowed_prefill_keys`` MUST NOT leak into URL.

    The skret namespace often co-locates deploy-time secrets (CI tokens,
    Docker Hub PATs, SMTP passwords) alongside the runtime form fields.
    Iterating ``creds.items()`` without a whitelist would propagate every
    one of those into the announced URL → browser history → access logs
    → screenshots. ``allowed_prefill_keys`` (driven by matrix.yaml's
    ``skret_keys``) hard-restricts which keys are eligible.
    """
    captured_url: list[str] = []

    def announce(url: str) -> None:
        captured_url.append(url)

    async def fake_register(_client: object, _base: str) -> str:
        return "local-browser"

    async def fake_health(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(oauth_client, "_register_client", fake_register)
    monkeypatch.setattr(oauth_client, "_health_probe", fake_health)

    with pytest.raises(TimeoutError):
        await oauth_client.acquire_jwt_via_browser_form(
            "http://127.0.0.1:0",
            announce,
            timeout=0.1,
            creds={
                "TELEGRAM_PHONE": "+84123",
                "TELEGRAM_BOT_TOKEN": "secret-bot-token",
                "DOCKERHUB_TOKEN": "dckr_pat_should_not_leak",
                "CI_APP_KEY": "-----BEGIN RSA PRIVATE KEY-----\nfoo\n-----END",
                "SMTP_CREDENTIAL": "user@gmail.com:appsecret",
            },
            allowed_prefill_keys=["TELEGRAM_PHONE"],
        )

    url = captured_url[0]
    assert "prefill_TELEGRAM_PHONE=%2B84123" in url
    assert "DOCKERHUB_TOKEN" not in url
    assert "dckr_pat_should_not_leak" not in url
    assert "CI_APP_KEY" not in url
    assert "RSA%20PRIVATE%20KEY" not in url
    assert "SMTP_CREDENTIAL" not in url
    assert "appsecret" not in url
    assert "TELEGRAM_BOT_TOKEN" not in url


@pytest.mark.asyncio
async def test_browser_form_no_allowed_keys_means_no_prefill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``allowed_prefill_keys=None`` with ``creds=...`` produces empty prefill.

    Defensive default: if a caller forgets to pass the whitelist, fall
    back to suppressing all prefill rather than leaking the entire
    namespace. The ``creds`` parameter then becomes a no-op for the URL
    construction (it is still kept on the call signature for symmetry
    and future use).
    """
    captured_url: list[str] = []

    def announce(url: str) -> None:
        captured_url.append(url)

    async def fake_register(_client: object, _base: str) -> str:
        return "local-browser"

    async def fake_health(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(oauth_client, "_register_client", fake_register)
    monkeypatch.setattr(oauth_client, "_health_probe", fake_health)

    with pytest.raises(TimeoutError):
        await oauth_client.acquire_jwt_via_browser_form(
            "http://127.0.0.1:0",
            announce,
            timeout=0.1,
            creds={"TELEGRAM_PHONE": "+84", "DOCKERHUB_TOKEN": "secret"},
            # allowed_prefill_keys omitted (defaults to None)
        )

    url = captured_url[0]
    assert "prefill_" not in url
    assert "+84" not in url
    assert "secret" not in url


@pytest.mark.asyncio
async def test_browser_form_no_creds_no_prefill_qs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without ``creds=...`` the URL has no ``prefill_*`` query suffix."""
    captured_url: list[str] = []

    def announce(url: str) -> None:
        captured_url.append(url)

    async def fake_register(_client: object, _base: str) -> str:
        return "local-browser"

    async def fake_health(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(oauth_client, "_register_client", fake_register)
    monkeypatch.setattr(oauth_client, "_health_probe", fake_health)

    with pytest.raises(TimeoutError):
        await oauth_client.acquire_jwt_via_browser_form(
            "http://127.0.0.1:0",
            announce,
            timeout=0.1,
        )

    url = captured_url[0]
    assert "prefill_" not in url
