import subprocess
import sys


def test_help_runs():
    result = subprocess.run(
        [sys.executable, "-m", "mcp_core.scripts.clean_state", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Clear MCP server credentials" in result.stdout
    assert "--keep-data" in result.stdout
    assert "--server" in result.stdout
    assert "--dry-run" in result.stdout


def test_dry_run_lists_paths(tmp_path, monkeypatch):
    # Set up fake state
    config_dir = tmp_path / ".config" / "mcp"
    config_dir.mkdir(parents=True)
    (config_dir / "config.enc").write_text("encrypted")
    (config_dir / "locks").mkdir()
    (config_dir / "locks" / "wet-mcp-1234.lock").write_text("lock")
    (config_dir / "cache").mkdir()
    (config_dir / "cache" / "wet-mcp-1234-2.28-1.11.tools.json").write_text("{}")

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows

    result = subprocess.run(
        [sys.executable, "-m", "mcp_core.scripts.clean_state", "--dry-run"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "config.enc" in result.stdout
    assert "wet-mcp-1234.lock" in result.stdout
    assert "tools.json" in result.stdout
    # Files NOT removed
    assert (config_dir / "config.enc").exists()


def test_actual_clean(tmp_path, monkeypatch):
    config_dir = tmp_path / ".config" / "mcp"
    config_dir.mkdir(parents=True)
    (config_dir / "config.enc").write_text("encrypted")

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    result = subprocess.run(
        [sys.executable, "-m", "mcp_core.scripts.clean_state"],
        capture_output=True,
        text=True,
        input="y\n",
    )

    assert result.returncode == 0
    assert not (config_dir / "config.enc").exists()


def test_keep_data_default(tmp_path, monkeypatch):
    """Default --keep-data ON: app data dirs preserved."""
    home = tmp_path
    (home / ".wet-mcp" / "data").mkdir(parents=True)
    (home / ".wet-mcp" / "data" / "search.sqlite").write_text("data")
    (home / ".wet-mcp" / "tokens").mkdir(parents=True)
    (home / ".wet-mcp" / "tokens" / "google_drive.json").write_text("{}")

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    result = subprocess.run(
        [sys.executable, "-m", "mcp_core.scripts.clean_state"],
        capture_output=True,
        text=True,
        input="y\n",
    )

    assert result.returncode == 0
    # Tokens cleared, data preserved
    assert not (home / ".wet-mcp" / "tokens" / "google_drive.json").exists()
    assert (home / ".wet-mcp" / "data" / "search.sqlite").exists()


def test_no_keep_data_wipes_app_data(tmp_path, monkeypatch):
    home = tmp_path
    (home / ".wet-mcp" / "data").mkdir(parents=True)
    (home / ".wet-mcp" / "data" / "search.sqlite").write_text("data")

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    result = subprocess.run(
        [sys.executable, "-m", "mcp_core.scripts.clean_state", "--no-keep-data"],
        capture_output=True,
        text=True,
        input="y\n",
    )

    assert result.returncode == 0
    assert not (home / ".wet-mcp" / "data" / "search.sqlite").exists()
