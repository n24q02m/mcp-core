import re

path = 'scripts/e2e/oauth_client.py'
content = open(path).read()

# 1. Update imports
content = content.replace(
    'from urllib.parse import parse_qs, urlparse',
    'from urllib.parse import parse_qs, urljoin, urlparse'
)

# 2. Add validation to satisfy Semgrep
validation = '    if not base_url.startswith(("http://", "https://")): raise ValueError("invalid base_url")'

content = content.replace(
    'async def _health_probe(client: httpx.AsyncClient, base_url: str) -> None:',
    f'async def _health_probe(client: httpx.AsyncClient, base_url: str) -> None:\n{validation}'
)
content = content.replace(
    'async def _register_client(client: httpx.AsyncClient, base_url: str) -> str:',
    f'async def _register_client(client: httpx.AsyncClient, base_url: str) -> str:\n{validation}'
)

# For entry points, we'll be more surgical
content = re.sub(
    r'(async def acquire_jwt\(.*?base_url: str.*?-> str:)',
    rf'\1\n{validation}',
    content, flags=re.DOTALL
)
content = re.sub(
    r'(async def acquire_jwt_via_browser_form\(.*?base_url: str.*?-> str:)',
    rf'\1\n{validation}',
    content, flags=re.DOTALL
)
content = re.sub(
    r'(async def acquire_jwt_via_upstream_consent\(.*?base_url: str.*?-> str:)',
    rf'\1\n{validation}',
    content, flags=re.DOTALL
)

# 3. Move health probes to fail fast
content = content.replace(
    '            client_id = await _register_client(client, base_url)\n            # Probe BEFORE printing the URL; user clicking a link to a dead\n            # server is the worst failure mode (silent, looks like driver bug).\n            await _health_probe(client, base_url)',
    '            # Probe BEFORE printing the URL; user clicking a link to a dead\n            # server is the worst failure mode (silent, looks like driver bug).\n            await _health_probe(client, base_url)\n            client_id = await _register_client(client, base_url)'
)
content = content.replace(
    '            client_id = await _register_client(client, base_url)\n            await _health_probe(client, base_url)',
    '            await _health_probe(client, base_url)\n            client_id = await _register_client(client, base_url)'
)
content = re.sub(
    r'(\s+)client_id = await _register_client\(client, base_url\)',
    r'\1# Confirm target alive BEFORE registration\n\1await _health_probe(client, base_url)\n\1client_id = await _register_client(client, base_url)',
    content, count=1
)

# 4. Use urljoin for URLs
content = content.replace('f"{base_url}/setup-status"', 'urljoin(base_url, "/setup-status")')
content = content.replace('f"{base_url}/.well-known/oauth-authorization-server"', 'urljoin(base_url, "/.well-known/oauth-authorization-server")')
content = content.replace('f"{base_url}/register"', 'urljoin(base_url, "/register")')
content = content.replace('f"{base_url}/authorize"', 'urljoin(base_url, "/authorize")')
content = content.replace('f"{base_url}/authorize/prefill"', 'urljoin(base_url, "/authorize/prefill")')
content = content.replace('f"{base_url}/token"', 'urljoin(base_url, "/token")')
content = content.replace('f"{base_url}{action}"', 'urljoin(base_url, action)')

# 5. Remove redundant probe
redundant = r'\n\s+# Verify server alive \+ OAuth metadata reachable BEFORE prompting\n\s+# the user\. A dead container with cached auth code = user clicks\n\s+# link, sees error, doesn\'t realize the test framework is at fault\.\n\s+await _health_probe\(client, base_url\)'
content = re.sub(redundant, '', content)

open(path, 'w').write(content)
