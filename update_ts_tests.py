import sys

path = 'packages/core-ts/tests/transport/local-server.test.ts'
with open(path, 'r') as f:
    lines = f.readlines()

# Add vi.mock for tryOpenBrowser
# Need to find imports to add vi and the mock
import_end_idx = -1
for i, line in enumerate(lines):
    if line.startswith('import') or line.startswith('} from'):
        import_end_idx = i

mock_code = """
vi.mock('../../src/relay/browser.js', () => ({
  tryOpenBrowser: vi.fn().mockResolvedValue(undefined)
}))
"""

# Update imports to include vi
for i, line in enumerate(lines):
    if 'from \'vitest\'' in line:
        if 'vi' not in line:
            lines[i] = line.replace('it }', 'it, vi }')
        break

lines.insert(import_end_idx + 1, mock_code)

with open(path, 'w') as f:
    f.writelines(lines)
