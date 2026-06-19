import pytest
from mcp_core.llm.key_rotation import is_rotatable_error, rotate_keys, split_keys


def test_split_keys_csv_strip_skip_empty():
    assert split_keys("k1, k2 ,, k3 ") == ["k1", "k2", "k3"]
    assert split_keys("solo") == ["solo"]
    assert split_keys("") == []
    assert split_keys(None) == []


class _HTTPErr(Exception):
    def __init__(self, status_code):
        self.status_code = status_code


def test_is_rotatable_error_429_401_403_only():
    assert is_rotatable_error(_HTTPErr(429))
    assert is_rotatable_error(_HTTPErr(401))
    assert is_rotatable_error(_HTTPErr(403))
    assert not is_rotatable_error(_HTTPErr(500))
    assert not is_rotatable_error(_HTTPErr(404))
    assert not is_rotatable_error(ValueError("boom"))


@pytest.mark.asyncio
async def test_rotate_keys_advances_on_429_then_succeeds():
    seen = []

    async def call(key):
        seen.append(key)
        if key == "bad":
            raise _HTTPErr(429)
        return f"ok:{key}"

    assert await rotate_keys(["bad", "good"], call) == "ok:good"
    assert seen == ["bad", "good"]


@pytest.mark.asyncio
async def test_rotate_keys_reraises_non_rotatable_immediately():
    seen = []

    async def call(key):
        seen.append(key)
        raise ValueError("config error")

    with pytest.raises(ValueError):
        await rotate_keys(["k1", "k2"], call)
    assert seen == ["k1"]  # did NOT advance


@pytest.mark.asyncio
async def test_rotate_keys_all_429_raises_last():
    async def call(key):
        raise _HTTPErr(429)

    with pytest.raises(_HTTPErr):
        await rotate_keys(["k1", "k2"], call)


@pytest.mark.asyncio
async def test_rotate_keys_single_key_no_wrapper():
    async def call(key):
        return f"ok:{key}"

    assert await rotate_keys(["solo"], call) == "ok:solo"
