from mcp_core.auth.local_oauth_app import _SetupStatusManager


def test_setup_manager_initial_state():
    manager = _SetupStatusManager()
    assert manager.get_all() == {"gdrive": "idle"}


def test_setup_manager_mark_complete():
    manager = _SetupStatusManager()
    manager.mark_complete("gdrive")
    assert manager.get_all() == {"gdrive": "complete"}


def test_setup_manager_mark_failed_sanitization():
    manager = _SetupStatusManager()
    # Test whitespace collapsing
    manager.mark_failed("gdrive", "  error  message  \n  with  newlines  ")
    assert manager.get_all()["gdrive"] == "error:error message with newlines"


def test_setup_manager_mark_failed_redundant_prefix():
    manager = _SetupStatusManager()
    # Test stripping redundant "error:" prefix
    manager.mark_failed("gdrive", "error: already has prefix")
    assert manager.get_all()["gdrive"] == "error:already has prefix"

    # Test stripping multiple redundant prefixes
    manager.mark_failed("gdrive", "ERROR: error: multiple prefixes")
    assert manager.get_all()["gdrive"] == "error:multiple prefixes"


def test_setup_manager_reset_all():
    manager = _SetupStatusManager()
    manager.mark_complete("gdrive")
    manager.mark_failed("other", "some error")
    manager.reset_all()
    assert manager.get_all() == {"gdrive": "idle", "other": "idle"}


def test_setup_manager_mark_failed_empty_error():
    manager = _SetupStatusManager()
    manager.mark_failed("gdrive", "")
    assert manager.get_all()["gdrive"] == "error:unknown error"

    manager.mark_failed("gdrive", "error:   ")
    assert manager.get_all()["gdrive"] == "error:unknown error"
