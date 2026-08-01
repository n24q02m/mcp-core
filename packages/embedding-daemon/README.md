# mcp-embedding-daemon

FastAPI HTTP server scaffold for the shared ONNX / GGUF embedding backend used
by the n24q02m Python MCP servers (wet, mnemo, code-review-graph).

> Part of the [`mcp-core`](https://github.com/n24q02m/mcp-core) monorepo. See
> the [root README](https://github.com/n24q02m/mcp-core#readme) for the full
> package overview; the published PyPI page mirrors that README.

## Install

```bash
pip install mcp-embedding-daemon
```

## Status

`v0.1.0` alpha. `GET /health` works; the embedding backends are not wired up
yet, so the inference endpoints return `501 Not Implemented` with a pointer to
the roadmap:

- `GET /health` — returns `{status, version}`
- `POST /embed` — `501` until the ONNX backend (qwen3-embed) is wired in
- `POST /rerank` — `501` until the ONNX backend is wired in

## Run

```bash
mcp-embedding-daemon --host 127.0.0.1 --port 9800
```

## License

Apache-2.0
