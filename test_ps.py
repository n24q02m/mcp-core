import subprocess
import base64

def test_ps(url):
    command = "Start-Process $args[0]"
    encoded_command = base64.b64encode(command.encode("utf-16le")).decode("ascii")
    print(f"Running with URL: {url}")
    try:
        # Note: this might not work on Linux unless powershell (pwsh) is installed,
        # but the code is intended for WSL/Windows where powershell.exe is available.
        # In this environment, we might not have powershell.exe in the path or it might not run.
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-EncodedCommand", encoded_command, url],
            capture_output=True, text=True, timeout=5
        )
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
    except Exception as e:
        print(f"Error: {e}")

test_ps("https://example.com")
