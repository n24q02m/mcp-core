"""Error path khi litellm chưa cài — chạy ở CI leg no-extra."""

import importlib.util

import pytest


@pytest.mark.skipif(
    importlib.util.find_spec("litellm") is not None,
    reason="litellm installed — covered by extras leg",
)
def test_helpful_error_without_extra():
    from mcp_core.llm.catalog import _get_litellm

    with pytest.raises(RuntimeError, match=r"n24q02m-mcp-core\[llm\]"):
        _get_litellm()
