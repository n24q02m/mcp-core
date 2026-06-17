from pathlib import Path
from mcp_core.transport.cache import cache_filename


def test_cache_traversal_sanitization():
    malicious_name = "../../etc/passwd"
    filename = cache_filename(malicious_name, 80, "1.0", "1.0")

    # It should no longer be a traversal path
    assert "/" not in filename
    assert "\\" not in filename
    assert filename == "______etc_passwd-80-1.0-1.0.tools.json"

    cache_dir = Path("/tmp/mcp-cache")
    full_path = cache_dir / filename

    # The resulting path MUST be under cache_dir
    assert full_path.parent == cache_dir


def test_dangerous_chars_sanitization():
    malicious_name = "server:name*with?chars"
    filename = cache_filename(malicious_name, 80, "1.0", "1.0")
    assert filename == "server_name_with_chars-80-1.0-1.0.tools.json"


def test_version_sanitization():
    filename = cache_filename("server", 80, "1.0/../2.0", "v1.0")
    assert filename == "server-80-1.0____2.0-v1.0.tools.json"
