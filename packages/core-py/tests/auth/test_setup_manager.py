from mcp_core.auth.local_oauth_app import _SetupStatusManager

def test_setup_status_manager_initial_state():
    manager = _SetupStatusManager()
    assert manager.get_status() == {"gdrive": "idle"}

def test_setup_status_manager_mark_complete():
    manager = _SetupStatusManager()
    manager.mark_complete("gdrive")
    assert manager.get_status() == {"gdrive": "complete"}

def test_setup_status_manager_mark_failed_sanitization():
    manager = _SetupStatusManager()
    # Test whitespace collapsing
    manager.mark_failed("gdrive", "  some   error  message  ")
    assert manager.get_status() == {"gdrive": "error:some error message"}

def test_setup_status_manager_mark_failed_redundant_prefix():
    manager = _SetupStatusManager()
    # Test stripping "error:" prefix
    manager.mark_failed("gdrive", "error: already prefixed")
    assert manager.get_status() == {"gdrive": "error:already prefixed"}

    manager.mark_failed("gdrive", "Error: mixed case prefix")
    assert manager.get_status() == {"gdrive": "error:mixed case prefix"}

def test_setup_status_manager_reset_all():
    manager = _SetupStatusManager()
    manager.mark_complete("gdrive")
    manager.mark_failed("other", "failed")
    assert manager.get_status() == {"gdrive": "complete", "other": "error:failed"}

    manager.reset_all()
    assert manager.get_status() == {"gdrive": "idle", "other": "idle"}

def test_setup_status_manager_get_status_copy():
    manager = _SetupStatusManager()
    status = manager.get_status()
    status["gdrive"] = "modified"
    assert manager.get_status()["gdrive"] == "idle"
