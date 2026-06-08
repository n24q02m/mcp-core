import pytest
from mcp_core.storage.per_plugin_store import _cred_path


def test_path_traversal_plugin_name(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    # This should probably raise ValueError or similar
    with pytest.raises(ValueError, match="Invalid plugin name"):
        _cred_path("../evil", None)


def test_path_traversal_sub(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    with pytest.raises(ValueError, match="Invalid sub identifier"):
        _cred_path("plugin", "../../evil")
