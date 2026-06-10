import sys
from mcp_core.relay.tool_helpers import _build_open_relay_handler


def test_open_relay_handler_docstring():
    """Verify docstring replacement in _build_open_relay_handler."""
    server_name = "test-custom-server"
    handler = _build_open_relay_handler(server_name, "http://localhost")

    if sys.flags.optimize >= 2:
        # Under -OO, docstrings are removed and __doc__ is None
        assert handler.__doc__ is None
    else:
        # Under normal conditions (or -O), docstrings exist
        assert handler.__doc__ is not None
        assert server_name in handler.__doc__
        assert "{server_name}" not in handler.__doc__
