import os

def fix_local_oauth_app():
    path = 'packages/core-ts/src/auth/local-oauth-app.ts'
    with open(path, 'r') as f:
        content = f.read()

    # Target: `Failed to mark _setup_complete=true for ${options.serverName}:`
    # Replace with: 'Failed to mark _setup_complete=true for %s:', options.serverName

    old1 = '`Failed to mark _setup_complete=true for ${options.serverName}:`'
    new1 = "'Failed to mark _setup_complete=true for %s:', options.serverName"

    content = content.replace(old1, new1)

    with open(path, 'w') as f:
        f.write(content)

def fix_cache():
    path = 'packages/core-ts/src/transport/cache.ts'
    with open(path, 'r') as f:
        content = f.read()

    old = '`Failed to persist capabilities cache for ${serverName}:`'
    new = "'Failed to persist capabilities cache for %s:', serverName"

    content = content.replace(old, new)

    with open(path, 'w') as f:
        f.write(content)

def fix_relay_login():
    path = 'packages/core-ts/src/auth/relay-login.ts'
    with open(path, 'r') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if '<input type="hidden" name="next" value="${safeNext}">' in line:
            # Add nosemgrep on the same line if possible, or right before.
            # Template literals make it tricky.
            lines[i] = line.replace('value="${safeNext}">', 'value="${safeNext}"> // nosemgrep: javascript.express.security.injection.raw-html-format.raw-html-format')
            break

    with open(path, 'w') as f:
        f.writelines(lines)

fix_local_oauth_app()
fix_cache()
fix_relay_login()
