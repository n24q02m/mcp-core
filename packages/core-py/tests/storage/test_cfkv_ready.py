"""CfKvBackend.ready() — readiness probe gating the first credential PUT (E.1)."""

import json

from mcp_core.storage.backends import CfKvBackend


class _Http:
    """Fake http seam: GET <base>/__ready -> {ready: bool}; ready after N polls."""

    def __init__(self, ready_after: int = 0) -> None:
        self.ready_after = ready_after
        self.get_calls = 0

    def request(self, method, url, data=None, headers=None):
        assert method == "GET" and url.endswith("/__ready"), (method, url)
        self.get_calls += 1
        ready = self.get_calls > self.ready_after
        return (200, json.dumps({"ready": ready}).encode())


class _FlakyHttp(_Http):
    """First poll raises a transport error, then behaves like _Http."""

    def request(self, method, url, data=None, headers=None):
        self.get_calls += 1
        if self.get_calls == 1:
            raise ConnectionError("connection refused (interception not wired yet)")
        return (200, json.dumps({"ready": True}).encode())


def test_ready_immediately_true():
    http = _Http(ready_after=0)
    assert CfKvBackend("http://kv.internal", http=http).ready(retries=3, delay=0) is True
    assert http.get_calls == 1


def test_ready_after_two_polls():
    http = _Http(ready_after=2)
    assert CfKvBackend("http://kv.internal", http=http).ready(retries=5, delay=0) is True
    assert http.get_calls == 3


def test_ready_gives_up_returns_false():
    http = _Http(ready_after=99)
    assert CfKvBackend("http://kv.internal", http=http).ready(retries=3, delay=0) is False
    assert http.get_calls == 3


def test_ready_tolerates_transport_error_during_poll():
    http = _FlakyHttp()
    assert CfKvBackend("http://kv.internal", http=http).ready(retries=3, delay=0) is True
    assert http.get_calls == 2
