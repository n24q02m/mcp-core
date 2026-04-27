"""Unit tests for Task 22 driver hardening — checklist banner + diagnostics.

Stays at the helper-function level so we don't spin Docker just to verify
output text. Integration coverage of the full T2 path lives in `make e2e-*`.
"""

from __future__ import annotations

from pathlib import Path

from e2e import driver


def test_checklist_banner_lists_all_t2_interaction_providers(capsys):
    driver._print_t2_interaction_checklist()
    err = capsys.readouterr().err
    assert "Microsoft (Outlook)" in err
    assert "Google Drive (wet/mnemo)" in err
    assert "Telegram (telegram-user)" in err
    # Notion-oauth is intentionally documented as RECLASSIFIED so users
    # don't keep asking why the checklist doesn't list a Notion gate.
    assert "Notion (notion-oauth): RECLASSIFIED" in err


def test_capture_diagnostics_writes_file_with_logs_and_status(tmp_path, monkeypatch):
    monkeypatch.setattr(driver, "DIAG_DIR", tmp_path)

    captured_compose_calls = []

    class _CompletedProcess:
        def __init__(self, stdout: str = "", stderr: str = ""):
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, **kwargs):
        captured_compose_calls.append(cmd)
        return _CompletedProcess(stdout="compose log line\n", stderr="")

    monkeypatch.setattr(driver.subprocess, "run", fake_run)

    class _FakeResp:
        status_code = 200
        text = '{"gdrive": "idle"}'

    def fake_get(url, timeout=2.0):
        return _FakeResp()

    monkeypatch.setattr(driver.httpx, "get", fake_get)

    diag_file = driver._capture_diagnostics(
        "email-outlook-test", Path("/fake/compose.yml"), "http://127.0.0.1:9999"
    )
    assert diag_file.exists()
    body = diag_file.read_text(encoding="utf-8")
    assert "container logs" in body
    assert "compose log line" in body
    assert "last setup-status" in body
    assert "gdrive" in body
    # Compose `logs` was the call we made.
    assert captured_compose_calls and "logs" in captured_compose_calls[0]


def test_capture_diagnostics_handles_compose_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(driver, "DIAG_DIR", tmp_path)

    def fake_run(cmd, **kwargs):
        raise OSError("docker not on PATH")

    monkeypatch.setattr(driver.subprocess, "run", fake_run)

    class _FakeResp:
        status_code = 200
        text = '{"gdrive": "idle"}'

    monkeypatch.setattr(driver.httpx, "get", lambda url, timeout=2.0: _FakeResp())

    diag_file = driver._capture_diagnostics(
        "test-cfg", Path("/fake/compose.yml"), "http://127.0.0.1:9999"
    )
    body = diag_file.read_text(encoding="utf-8")
    assert "container logs FAILED" in body
    assert "docker not on PATH" in body
    # setup-status capture still works
    assert "last setup-status" in body


def test_capture_diagnostics_handles_setup_status_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(driver, "DIAG_DIR", tmp_path)

    class _CompletedProcess:
        stdout = "ok\n"
        stderr = ""

    monkeypatch.setattr(driver.subprocess, "run", lambda *a, **kw: _CompletedProcess())

    def fake_get(url, timeout=2.0):
        raise driver.httpx.ConnectError("refused")

    monkeypatch.setattr(driver.httpx, "get", fake_get)

    diag_file = driver._capture_diagnostics(
        "test-cfg", Path("/fake/compose.yml"), "http://127.0.0.1:9999"
    )
    body = diag_file.read_text(encoding="utf-8")
    assert "container logs" in body
    assert "setup-status FAILED" in body
    assert "refused" in body
