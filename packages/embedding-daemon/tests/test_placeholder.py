from mcp_embedding_daemon import __version__


def test_version_exposed() -> None:
    assert isinstance(__version__, str)
    assert len(__version__) > 0
