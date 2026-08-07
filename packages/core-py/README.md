# n24q02m-mcp-core

Unified MCP Streamable HTTP 2025-11-25 transport, OAuth 2.1 Authorization
Server, lifecycle management, install automation, and the LLM passthrough used
across the n24q02m MCP ecosystem.

> Part of the [`mcp-core`](https://github.com/n24q02m/mcp-core) monorepo. See
> the [root README](https://github.com/n24q02m/mcp-core#readme) for the full
> module reference, quick-start, and provider key configuration; the published
> PyPI page mirrors that README.

## Install

```bash
pip install n24q02m-mcp-core

# with the optional LLM passthrough (litellm)
pip install 'n24q02m-mcp-core[llm]'
```

## LLM gateway default

Calls made through `mcp_core.llm` are routed to the base URL in
`MCP_LLM_GATEWAY_BASE` whenever that variable is set and the caller passed no
`api_base` of its own — one OpenAI-compatible endpoint in front of the
providers, configured once instead of at every call site (the value is
SSRF-vetted exactly like a caller-supplied `api_base`). A caller that does pass
`api_base` always wins, so a per-task or self-hosted endpoint still overrides
the gateway. With `MCP_LLM_GATEWAY_BASE` unset the behaviour is exactly what it
was before: no base is added to the request and each provider is reached
directly.

## License

Apache-2.0
