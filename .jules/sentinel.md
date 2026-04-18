
## 2025-04-15 - Remove command-line token argument for security policy compliance
**Vulnerability:** The `mcp-stdio-proxy` CLI accepted an authentication token via the `--token` flag. Passing sensitive secrets as command-line arguments leaks them to the system's process list (e.g., via `ps` or `top`), shell history files, and potentially logging systems, exposing the application to unauthorized access.
**Learning:** This repo has a strict security policy stating that sensitive tokens like `MCP_CORE_SERVER_TOKEN` must never be passed via command-line arguments. This policy is explicitly recorded in memory to ensure environmental configurations do not compromise credentials at runtime.
**Prevention:** Remove CLI arguments that accept secrets (like `--token`). Force the application to source such sensitive data exclusively from environment variables (e.g., `os.environ.get("MCP_CORE_SERVER_TOKEN")`) which are typically isolated to the process context and not globally exposed.
