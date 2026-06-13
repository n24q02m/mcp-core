"""Vertex AI Express generateContent adapter (spec: vertex-express-passthrough).

litellm's ``vertex_ai/`` provider requires a Service Account / ADC and ignores
the Vertex Express API key (open upstream bug BerriAI/litellm#21036). This
module provides a thin, httpx-only branch — selected by the ``vertex_express/``
model prefix in ``dispatch.acompletion`` / ``dispatch.completion`` — that calls
the Express ``generateContent`` REST endpoint directly and translates Google's
response into a litellm-ChatCompletion-shaped object exposing
``.choices[0].message.content`` and ``.usage``.

Endpoint shape verified against google-genai 2.8.0's own request builder
(genai.Client(vertexai=True, api_key=...)):
    POST https://aiplatform.googleapis.com/v1beta1/publishers/google/models/{model}:generateContent
    header: x-goog-api-key: <api_key>
NOT the ``?key=`` query param, and ``v1beta1`` (not ``v1``).

Scope: chat completion ONLY. Vertex Express has no Imagen (:predict) or Veo
(:predictLongRunning) REST surface — image/video generation stays native in
imagine-mcp via the google-genai SDK. No google-genai dependency is added to
mcp-core; this is a pure httpx passthrough.
"""

from __future__ import annotations

from dataclasses import dataclass, field

VERTEX_EXPRESS_PREFIX = "vertex_express"


@dataclass
class ExpressMessage:
    role: str
    content: str | None


@dataclass
class ExpressChoice:
    message: ExpressMessage
    finish_reason: str | None
    index: int = 0


@dataclass
class ExpressUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class ExpressResponse:
    """litellm-ChatCompletion-shaped: callers read .choices[0].message.content."""

    choices: list[ExpressChoice] = field(default_factory=list)
    usage: ExpressUsage = field(default_factory=ExpressUsage)
    model: str = ""


def is_express_model(model: str) -> bool:
    """True when ``model`` carries the ``vertex_express/`` provider prefix."""
    return model.strip().startswith(f"{VERTEX_EXPRESS_PREFIX}/")


def strip_express_prefix(model: str) -> str:
    """Drop the leading ``vertex_express/`` segment, keep the rest verbatim."""
    return model.strip().split("/", 1)[1]
