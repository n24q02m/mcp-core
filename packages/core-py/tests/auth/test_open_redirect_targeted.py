import pytest
from mcp_core.auth import relay_login


@pytest.fixture(autouse=True)
def reset_state():
    relay_login._sessions.clear()
    relay_login._fails.clear()
    relay_login.configure_relay_login("password123")


@pytest.mark.parametrize(
    "payload",
    [
        "//google.com",
        "/\\google.com",
        "\\google.com",
        "/ google.com",
        "/\tgoogle.com",
        "/\rgoogle.com",
        "/\ngoogle.com",
        "http://google.com",
        "https://google.com",
        "javascript:alert(1)",
        "//\\google.com",
        "///google.com",
        " \t/google.com",
    ],
)
async def test_login_post_handler_blocks_open_redirect(payload):
    form = {"password": "password123", "next": payload}
    response = await relay_login.login_post_handler(form, "1.2.3.4")
    assert response.status_code == 302
    assert response.headers["location"] == "/authorize"


@pytest.mark.parametrize(
    "payload",
    [
        "//google.com",
        "/\\google.com",
        "\\google.com",
        "/ google.com",
        "/\tgoogle.com",
        "/\rgoogle.com",
        "/\ngoogle.com",
        "http://google.com",
        "https://google.com",
        "javascript:alert(1)",
        "//\\google.com",
        "///google.com",
        " \t/google.com",
    ],
)
async def test_login_get_handler_sanitizes_next(payload):
    response = await relay_login.login_get_handler(next=payload)
    assert 'name="next" value="/authorize"' in response.body.decode()
