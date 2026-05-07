import re

path = 'scripts/e2e/oauth_client.py'
content = open(path).read()

# 1. Imports
content = content.replace(
    'from urllib.parse import parse_qs, urlparse',
    'from urllib.parse import parse_qs, urljoin, urlparse'
)

# 2. _health_probe
content = content.replace(
    '    for url in (\n        f"{base_url}/setup-status",\n        f"{base_url}/.well-known/oauth-authorization-server",\n    ):',
    '    for url in (\n        urljoin(base_url, "/setup-status"),\n        urljoin(base_url, "/.well-known/oauth-authorization-server"),\n    ):'
)

# 3. acquire_jwt_via_browser_form
content = re.sub(
    r'(\s+)client_id = await _register_client\(client, base_url\)\n\s+(# Probe BEFORE printing the URL; user clicking a link to a dead\n\s+# server is the worst failure mode \(silent, looks like driver bug\)\.\n\s+await _health_probe\(client, base_url\))',
    r'\1# Probe BEFORE printing the URL; user clicking a link to a dead\n\1# server is the worst failure mode (silent, looks like driver bug).\n\1await _health_probe(client, base_url)\n\1client_id = await _register_client(client, base_url)',
    content, flags=re.DOTALL
)
content = content.replace('f"{base_url}/authorize/prefill"', 'urljoin(base_url, "/authorize/prefill")')
content = content.replace('f"{base_url}/authorize?"', 'urljoin(base_url, "/authorize") + "?"')

# 4. acquire_jwt_via_upstream_consent
content = re.sub(
    r'(\s+)client_id = await _register_client\(client, base_url\)\n\s+(await _health_probe\(client, base_url\))',
    r'\1\2\n\1client_id = await _register_client(client, base_url)',
    content
)
content = content.replace('await client.get(f"{base_url}/authorize"', 'await client.get(urljoin(base_url, "/authorize")')

# 5. acquire_jwt
content = re.sub(
    r'(\s+)client_id = await _register_client\(client, base_url\)',
    r'\1await _health_probe(client, base_url)\n\1client_id = await _register_client(client, base_url)',
    content, count=1
)
content = content.replace('await client.get(f"{base_url}/authorize"', 'await client.get(urljoin(base_url, "/authorize")')
redundant = r'\n\s+# Verify server alive \+ OAuth metadata reachable BEFORE prompting\n\s+# the user\. A dead container with cached auth code = user clicks\n\s+# link, sees error, doesn\'t realize the test framework is at fault\.\n\s+await _health_probe\(client, base_url\)'
content = re.sub(redundant, '', content)

# 6. _register_client
content = content.replace('f"{base_url}/register"', 'urljoin(base_url, "/register")')

# 7. Other remaining uses
content = re.sub(r'f"\{base_url\}(/[^"]+)"', r'urljoin(base_url, "\1")', content)

open(path, 'w').write(content)
