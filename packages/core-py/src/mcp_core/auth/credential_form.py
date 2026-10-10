"""Credential form HTML renderer.

Renders a dark-themed HTML form from a RelayConfigSchema dict.
Used as the OAuth authorization page presented to the user during relay config.

Relay config field schema
-------------------------
Each ``RelayConfigField`` dict supports keys:
  name (str, required): config.enc key
  label (str, required): UI label
  required (bool, required): server gate
  secret (bool, optional, default False): True = never re-render value to HTML
  oauth_field (bool, optional, default False): True = managed by OAuth flow,
    render as Re-authorize button instead of input
  type (str, optional, default "text"): UI input type ("text", "password", "url", "email")
  description (str, optional): help text
  default (any, optional): default value if user submits empty
  pattern (str, optional): client-side regex validation
"""

import html
import json
from typing import Any, TypedDict


class RelayConfigField(TypedDict, total=False):
    """Relay config field schema (see module docstring for full spec)."""

    name: str
    label: str
    required: bool
    secret: bool
    oauth_field: bool
    type: str
    description: str
    default: Any
    pattern: str


def _escape(value: Any) -> str:
    """Escape a value for safe HTML insertion."""
    return html.escape(str(value), quote=True)


# Interactive model-chain widget script. Built as a PLAIN (non-f) string so the
# many JS braces need no escaping; ``__PROVIDER_KEY_JSON__`` is substituted at
# render time with ``json.dumps(PROVIDER_KEY_ENV)`` (the canonical provider->env
# map). The widget renders draggable chips, a suggested-model dropdown, keeps the
# hidden ``.field-input`` CSV synced (so the existing submit handler works
# unchanged), and toggles ``[data-provider-key]`` credential fields based on the
# providers of the chosen models (derive-keys).
_MODEL_CHAIN_SCRIPT = """
    <script>
    (function () {
        var PROVIDER_KEY = JSON.parse('__PROVIDER_KEY_JSON__');
        function providerOf(model) {
            model = (model || "").trim();
            var i = model.indexOf("/");
            return i === -1 ? "openai" : model.slice(0, i);
        }
        function looksLikeModel(m) {
            // Loose shape gate: "provider/model" or a bare model id. Lets any
            // litellm-supported (or registry-missing) model through the relay
            // form via free text, instead of caging the user to suggestions.
            return /^[\\w.-]+(\\/[\\w.:-]+)?$/.test((m || "").trim());
        }
        function keyEnvFor(model, w) {
            // search-chain widgets carry an explicit backend -> ENV-var map
            // (named backends, no model-prefix inference). A backend absent
            // from the map (e.g. searxng) needs no credential -> returns null.
            var explicit = w && w.getAttribute("data-provider-keys");
            if (explicit) {
                var map = JSON.parse(explicit);
                return Object.prototype.hasOwnProperty.call(map, model) ? map[model] : null;
            }
            var p = providerOf(model);
            return PROVIDER_KEY[p] || (p.toUpperCase() + "_API_KEY");
        }

        var widgets = document.querySelectorAll(".model-chain");

        // The credential env-vars this page actually has input fields for (every
        // declared [data-provider-key] group, visible or hidden). Used to filter
        // the dropdown so it only OFFERS models we can authenticate.
        var availableKeys = {};
        document.querySelectorAll("[data-provider-key]").forEach(function (g) {
            availableKeys[g.getAttribute("data-provider-key")] = true;
        });

        function getChips(w) {
            var hidden = document.getElementById("field-" + w.getAttribute("data-key"));
            return hidden.value ? hidden.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean) : [];
        }
        function deriveKeys() {
            var needed = {};
            widgets.forEach(function (w) {
                getChips(w).forEach(function (m) {
                    var k = keyEnvFor(m, w);
                    if (k) needed[k] = true;
                });
            });
            document.querySelectorAll("[data-provider-key]").forEach(function (grp) {
                var k = grp.getAttribute("data-provider-key");
                grp.style.display = needed[k] ? "" : "none";
                if (!needed[k]) {
                    var inp = grp.querySelector("input");
                    if (inp) inp.value = "";
                }
            });
        }
        function updateBadge(w, models) {
            var badge = document.getElementById("mc-badge-" + w.getAttribute("data-key"));
            if (models.length > 0) { badge.textContent = ""; return; }
            var noun = w.getAttribute("data-noun") || "models";
            var localLabel = w.getAttribute("data-local-label") || "local ONNX";
            badge.textContent = (w.getAttribute("data-has-local") === "true")
                ? ("No " + noun + " -> " + localLabel + " (no key needed)")
                : ("No " + noun + " -> this feature is disabled");
        }
        function setChips(w, models) {
            var hidden = document.getElementById("field-" + w.getAttribute("data-key"));
            hidden.value = models.join(",");
            renderChips(w, models);
            updateBadge(w, models);
            deriveKeys();
        }
        function attachDrag(w, chip) {
            chip.addEventListener("dragstart", function (e) {
                chip.classList.add("dragging");
                e.dataTransfer.setData("text/plain", chip.dataset.model);
            });
            chip.addEventListener("dragend", function () { chip.classList.remove("dragging"); });
            chip.addEventListener("dragover", function (e) { e.preventDefault(); });
            chip.addEventListener("drop", function (e) {
                e.preventDefault();
                var dragged = e.dataTransfer.getData("text/plain");
                var target = chip.dataset.model;
                if (dragged === target) return;
                var models = getChips(w).filter(function (x) { return x !== dragged; });
                var ti = models.indexOf(target);
                models.splice(ti, 0, dragged);
                setChips(w, models);
            });
        }
        function renderChips(w, models) {
            var box = document.getElementById("mc-chips-" + w.getAttribute("data-key"));
            while (box.firstChild) box.removeChild(box.firstChild);
            models.forEach(function (m, idx) {
                var chip = document.createElement("span");
                chip.className = "mc-chip";
                chip.setAttribute("draggable", "true");
                chip.setAttribute("title", "Drag to reorder");
                chip.dataset.model = m;
                var ord = document.createElement("span");
                ord.className = "mc-order";
                ord.textContent = (idx + 1) + ".";
                chip.appendChild(ord);
                var name = document.createElement("span");
                name.textContent = m;
                chip.appendChild(name);
                var rm = document.createElement("button");
                rm.type = "button";
                rm.setAttribute("aria-label", "Remove " + m);
                rm.setAttribute("title", "Remove " + m);
                rm.textContent = "x";
                rm.addEventListener("click", function () {
                    setChips(w, getChips(w).filter(function (x) { return x !== m; }));
                });
                chip.appendChild(rm);
                attachDrag(w, chip);
                box.appendChild(chip);
            });
        }
        function buildDropdown(w, filter) {
            var dd = document.getElementById("mc-dropdown-" + w.getAttribute("data-key"));
            while (dd.firstChild) dd.removeChild(dd.firstChild);
            var suggested = JSON.parse(w.getAttribute("data-suggested") || "[]");
            var catalog = JSON.parse(w.getAttribute("data-catalog") || "[]");
            // Only OFFER catalog models this page can authenticate: a credential
            // field must exist for the model's provider (or the model needs no
            // key). Without this, picking a model whose <PROVIDER>_API_KEY the
            // server never declared (vertex_ai/*, bedrock/*, azure/*, ...) reveals
            // no credential box — the silent-trap bug. Author-curated `suggested`
            // are exempt (chosen to match declared fields); free-text Enter still
            // accepts any model (open passthrough for power users).
            catalog = catalog.filter(function (m) {
                var k = keyEnvFor(m, w);
                return !k || availableKeys[k];
            });
            var seen = {}, options = [];
            suggested.concat(catalog).forEach(function (m) {
                if (m && !seen[m]) { seen[m] = true; options.push(m); }
            });
            var f = (filter || "").toLowerCase();
            if (f) options = options.filter(function (m) { return m.toLowerCase().indexOf(f) !== -1; });
            var current = getChips(w);
            options.slice(0, 50).forEach(function (m) {
                var lbl = document.createElement("label");
                var cb = document.createElement("input");
                cb.type = "checkbox";
                cb.checked = current.indexOf(m) !== -1;
                cb.addEventListener("change", function () {
                    var models = getChips(w);
                    if (cb.checked) { if (models.indexOf(m) === -1) models.push(m); }
                    else { models = models.filter(function (x) { return x !== m; }); }
                    setChips(w, models);
                });
                lbl.appendChild(cb);
                var span = document.createElement("span");
                span.textContent = m;
                lbl.appendChild(span);
                dd.appendChild(lbl);
            });
            dd.hidden = false;
        }
        widgets.forEach(function (w) {
            var input = w.querySelector(".mc-typeahead");
            var dd = document.getElementById("mc-dropdown-" + w.getAttribute("data-key"));
            setChips(w, getChips(w));
            input.addEventListener("focus", function () { buildDropdown(w, input.value.trim()); });
            input.addEventListener("input", function () { buildDropdown(w, input.value.trim()); });
            input.addEventListener("keydown", function (e) {
                if (e.key === "Enter" && input.value.trim()) {
                    e.preventDefault();
                    var m = input.value.trim();
                    // Accept any shape-valid provider/model (open passthrough),
                    // not only curated suggestions -- searchable combobox, not
                    // a fixed whitelist.
                    if (!looksLikeModel(m)) { return; }
                    var models = getChips(w);
                    if (models.indexOf(m) === -1) models.push(m);
                    setChips(w, models);
                    // Keep the typed keyword so the user can keep adding matches
                    // from the same search; re-filter the dropdown with it.
                    buildDropdown(w, input.value.trim());
                }
            });
            document.addEventListener("click", function (e) {
                if (!w.contains(e.target)) dd.hidden = true;
            });
        });
        deriveKeys();
    })();
    </script>"""


# Shared CSS for every relay/auth HTML page rendered by core-py.
#
# Kept verbatim with ``packages/core-ts/src/auth/credential-form.ts``'s
# ``FORM_SHELL_CSS`` constant so the credential form, the ``/login`` password
# gate, and any future relay page have identical visual styling regardless of
# which language renders them. Extending this string requires updating the TS
# parity copy in the same commit.
_FORM_SHELL_CSS = """        *, *::before, *::after {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: #0f0f0f;
            color: #e8e8e8;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            font-size: 15px;
            line-height: 1.6;
            min-height: 100vh;
            display: flex;
            align-items: flex-start;
            justify-content: center;
            padding: 2rem 1rem;
        }

        .container {
            width: 100%;
            max-width: 480px;
        }

        .card {
            background-color: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 1.25rem;
        }

        .server-header {
            margin-bottom: 1.5rem;
        }

        .server-name {
            font-size: 1.375rem;
            font-weight: 600;
            color: #ffffff;
            margin-bottom: 0.375rem;
        }

        .server-id {
            font-size: 0.8125rem;
            color: #9ca3af;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            margin-bottom: 0.5rem;
        }

        .server-description {
            font-size: 0.9rem;
            color: #9ca3af;
            margin-top: 0.5rem;
        }

        .form-title {
            display: block;
            font-size: 0.875rem;
            font-weight: 500;
            color: #aaa;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 1.25rem;
        }

        .field-group {
            margin-bottom: 1.25rem;
        }

        .field-label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            font-weight: 500;
            color: #ccc;
            margin-bottom: 0.375rem;
        }

        .required-badge {
            font-size: 0.6875rem;
            font-weight: 500;
            color: #f87171;
            background-color: rgba(248, 113, 113, 0.1);
            border: 1px solid rgba(248, 113, 113, 0.25);
            border-radius: 4px;
            padding: 0.1rem 0.4rem;
        }

        .optional-badge {
            font-size: 0.6875rem;
            font-weight: 400;
            color: #9ca3af;
            background-color: rgba(255, 255, 255, 0.04);
            border: 1px solid #333;
            border-radius: 4px;
            padding: 0.1rem 0.4rem;
        }

        .field-input {
            width: 100%;
            background-color: #111;
            border: 1px solid #2e2e2e;
            border-radius: 8px;
            color: #e8e8e8;
            font-size: 0.9375rem;
            padding: 0.625rem 0.875rem;
            transition: border-color 0.15s ease, box-shadow 0.15s ease;
            outline: none;
        }

        .field-input:focus {
            border-color: #4a6fa5;
            box-shadow: 0 0 0 3px rgba(74, 111, 165, 0.2);
        }

        .field-input::placeholder {
            color: #9ca3af;
        }

        .field-input[aria-invalid="true"] {
            border-color: #f87171;
        }

        .field-input[aria-invalid="true"]:focus {
            box-shadow: 0 0 0 3px rgba(248, 113, 113, 0.2);
        }

        .field-input:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            background-color: #0f0f0f;
        }

        .model-chain { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; position: relative; padding: 8px; border: 1px solid #2a2a3a; border-radius: 8px; background: #14141f; transition: border-color 0.15s ease, box-shadow 0.15s ease; }
        .model-chain:focus-within { border-color: #4a6fa5; box-shadow: 0 0 0 3px rgba(74, 111, 165, 0.2); }
        .mc-chips { display: flex; flex-wrap: wrap; gap: 6px; width: 100%; }
        .mc-chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 8px; background: #23233a; border: 1px solid #34344a; border-radius: 6px; font-size: 13px; cursor: grab; }
        .mc-chip.dragging { opacity: 0.4; }
        .mc-chip .mc-order { color: #8a8aa5; font-variant-numeric: tabular-nums; }
        .mc-chip button { background: none; border: none; color: #b56; cursor: pointer; font-size: 14px; line-height: 1; padding: 0; }
        .mc-chip button:hover, .mc-chip button:focus-visible { color: #ff6b6b; outline: 2px solid #ff6b6b; outline-offset: 2px; border-radius: 2px; }
        .mc-typeahead { flex: 1; min-width: 140px; background: transparent; border: none; color: inherit; outline: none; font-size: 14px; padding: 4px; }
        .mc-dropdown { position: absolute; top: 100%; left: 0; right: 0; z-index: 10; background: #1b1b2a; border: 1px solid #2a2a3a; border-radius: 8px; margin-top: 4px; max-height: 220px; overflow-y: auto; }
        .mc-dropdown label { display: flex; align-items: center; gap: 8px; padding: 6px 10px; cursor: pointer; font-size: 13px; }
        .mc-dropdown label:hover, .mc-dropdown label:focus-within { background: #23233a; }
        .mc-badge { font-size: 12px; color: #8a8aa5; width: 100%; }

        .help-text {
            font-size: 0.8125rem;
            color: #9ca3af;
            margin-top: 0.375rem;
        }

        .help-text a {
            color: #6c9bd2;
            text-decoration: none;
        }

        .help-text a:hover {
            text-decoration: underline;
        }

        .help-text a:focus-visible {
            outline: 2px solid #4a6fa5;
            outline-offset: 2px;
            border-radius: 2px;
        }

        .submit-btn {
            width: 100%;
            background-color: #4a6fa5;
            border: none;
            border-radius: 8px;
            color: #fff;
            cursor: pointer;
            font-size: 0.9375rem;
            font-weight: 500;
            padding: 0.75rem 1.5rem;
            transition: background-color 0.15s ease, opacity 0.15s ease;
            margin-top: 0.5rem;
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 0.5rem;
        }

        .submit-btn:hover {
            background-color: #5a7fb5;
        }

        .submit-btn:focus-visible {
            outline: 2px solid #6c9bd2;
            outline-offset: 2px;
        }

        .submit-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .submit-btn[aria-busy="true"] {
            cursor: wait;
        }

        .submit-btn[aria-busy="true"]::before {
            content: "";
            width: 1rem;
            height: 1rem;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
            to {
                transform: rotate(360deg);
            }
        }

        .status-box {
            display: none;
            border-radius: 8px;
            font-size: 0.875rem;
            margin-top: 1rem;
            padding: 0.75rem 1rem;
        }

        .status-box.success {
            background-color: rgba(52, 199, 89, 0.1);
            border: 1px solid rgba(52, 199, 89, 0.3);
            color: #34c759;
        }

        .status-box.error {
            background-color: rgba(248, 113, 113, 0.1);
            border: 1px solid rgba(248, 113, 113, 0.3);
            color: #f87171;
        }

        .status-box.info {
            background-color: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            color: #e8e8e8;
        }

        .status-box a {
            color: #60a5fa;
            font-weight: 500;
            text-decoration: none;
        }

        .status-box a:hover {
            text-decoration: underline;
        }

        .status-box a:focus-visible {
            outline: 2px solid #60a5fa;
            outline-offset: 2px;
            border-radius: 2px;
        }

        .capabilities-section {
            margin-top: 0;
        }

        .capabilities-title {
            font-size: 0.875rem;
            font-weight: 500;
            color: #aaa;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.875rem;
        }

        .capabilities-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 0.625rem;
        }

        .capability-item {
            background-color: #111;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            padding: 0.75rem 1rem;
        }

        .capability-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.5rem;
            margin-bottom: 0.25rem;
        }

        .capability-label {
            font-size: 0.875rem;
            font-weight: 500;
            color: #ccc;
        }

        .capability-priority {
            font-size: 0.6875rem;
            font-weight: 500;
            border-radius: 4px;
            padding: 0.1rem 0.4rem;
            text-transform: capitalize;
        }

        .priority-high {
            color: #f87171;
            background-color: rgba(248, 113, 113, 0.1);
            border: 1px solid rgba(248, 113, 113, 0.25);
        }

        .priority-medium {
            color: #fbbf24;
            background-color: rgba(251, 191, 36, 0.1);
            border: 1px solid rgba(251, 191, 36, 0.25);
        }

        .priority-low {
            color: #6ee7b7;
            background-color: rgba(110, 231, 183, 0.1);
            border: 1px solid rgba(110, 231, 183, 0.25);
        }

        .capability-desc {
            font-size: 0.8125rem;
            color: #9ca3af;
        }

        :root {
            color-scheme: light dark;
        }

        @media (prefers-color-scheme: light) {
            body {
                background-color: #f4f5f7;
                color: #1f2937;
            }
            .card {
                background-color: #ffffff;
                border-color: #e5e7eb;
            }
            .server-name {
                color: #111827;
            }
            .server-id,
            .server-description,
            .help-text,
            .mc-badge,
            .form-title,
            .capabilities-title,
            .capability-desc {
                color: #6b7280;
            }
            .field-label,
            .capability-label {
                color: #374151;
            }
            .field-input {
                background-color: #ffffff;
                border-color: #d1d5db;
                color: #1f2937;
            }
            .field-input::placeholder {
                color: #9ca3af;
            }
            .field-input:disabled {
                background-color: #f3f4f6;
            }
            .optional-badge {
                color: #6b7280;
                background-color: #f3f4f6;
                border-color: #d1d5db;
            }
            .capability-item {
                background-color: #f9fafb;
                border-color: #e5e7eb;
            }
            .model-chain {
                background: #f9fafb;
                border-color: #d1d5db;
            }
            .mc-chip {
                background: #eef1f6;
                border-color: #d1d5db;
            }
            .mc-dropdown {
                background: #ffffff;
                border-color: #d1d5db;
            }
            .mc-dropdown label:hover,
            .mc-dropdown label:focus-within {
                background: #eef1f6;
            }
        }
"""


def render_form_shell(title: str, body_html: str) -> str:
    """Wrap ``body_html`` in the shared dark-theme HTML shell.

    The shell provides ``<!DOCTYPE html>``, ``<head>`` (charset, viewport, a
    Content-Security-Policy meta, escaped ``<title>``, embedded
    ``_FORM_SHELL_CSS``) and a ``<body>`` whose only child is ``body_html``.
    ``body_html`` is inserted verbatim, so callers MUST pre-escape any untrusted
    values they interpolate.

    The CSP (``default-src 'none'; style-src 'unsafe-inline'; script-src
    'unsafe-inline'; connect-src 'self'``) permits the page's own inline
    ``<style>``/``<script>`` (the form is self-contained by design) and its
    same-origin ``fetch`` submits, while blocking any external resource load.

    ``title`` is HTML-escaped before being placed in ``<title>``.

    Used by ``render_credential_form`` (relay credential form) and by
    ``relay_login.login_get_handler`` (the ``/login`` password gate) so both
    pages share identical typography, palette, card layout, and input
    styling. Parity with TS ``renderFormShell`` in
    ``packages/core-ts/src/auth/credential-form.ts``.
    """
    safe_title = _escape(title)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'" />
    <title>{safe_title}</title>
    <style>
{_FORM_SHELL_CSS}    </style>
</head>
<body>
{body_html}
</body>
</html>"""


# Map a model-chain ``task`` to the litellm catalog ``mode``(s) used to back
# the searchable dropdown. search-chain tasks (named backends, no litellm
# models) are absent -> empty catalog. ``generate`` covers litellm's image +
# video generation modes (imagine's GENERATE_MODELS chain) — ``image_edit`` is
# included to match the dispatch capability check in ``mcp_core.llm.dispatch``.
_TASK_CATALOG_MODES: dict[str, tuple[str, ...]] = {
    "embedding": ("embedding",),
    "rerank": ("rerank",),
    "chat": ("chat",),
    "summary": ("chat",),
    "understand": ("chat",),
    "generate": ("image_generation", "video_generation", "image_edit"),
}

# Cap the catalog at the FULL litellm registry (a few thousand models) so the
# dropdown is genuinely searchable across the whole provider/model space, not a
# 100-entry alphabetical slice that hid most models (e.g. ``deepseek``). The
# largest mode (chat, ~2.2k models) serializes to ~105 KB as the rendered
# ``data-catalog`` attribute — a bounded, reasonable page-weight ceiling.
_CATALOG_LIMIT = 5000

# Providers whose bare-named litellm ids must be prefixed so the widget derives
# the right ``<PROVIDER>_API_KEY`` (a bare name infers ``openai``). Mirrors
# ``mcp_core.llm.providers.PROVIDER_KEY_ENV``.
_NORMALIZE_PREFIXES = frozenset({"cohere", "jina_ai", "openai", "gemini", "xai", "anthropic", "vertex_express"})


def _normalize_litellm_id(model: str, provider: str, *, chat: bool = False) -> str | None:
    """Prefix a bare curated-provider model id so prefix-inference derives the
    correct key; leave already-prefixed and non-curated ids untouched.

    Vertex is special: litellm surfaces ``vertex_ai/*`` but this stack can only
    authenticate Vertex via the ``vertex_express`` httpx adapter (Gemini
    chat/vision, key ``GOOGLE_VERTEX_EXPRESS_API_KEY``); litellm's ``vertex_ai/``
    still demands a Service Account / ADC (BerriAI/litellm#21036, open). So a
    chat-catalog ``vertex_ai/gemini-*`` is remapped to the working
    ``vertex_express/`` id, and every other ``vertex_ai/*`` is DROPPED
    (returns ``None``) — offering it would derive a ``VERTEX_AI_API_KEY`` field
    no server declares, reproducing the silent no-credential-box trap.
    """
    if model.startswith("vertex_ai/"):
        rest = model.split("/", 1)[1]
        if chat and rest.startswith("gemini"):
            return f"vertex_express/{rest}"
        return None
    if "/" in model:
        return model
    if provider in _NORMALIZE_PREFIXES:
        return f"{provider}/{model}"
    return model


def _catalog_models_for_task(task: str, limit: int = _CATALOG_LIMIT) -> list[str]:
    """Best-effort model-id list for a model-chain ``task``'s catalog mode.

    Merges live special-provider models (``provider_catalog_models`` — e.g. Jina,
    keyless) first, then the litellm registry with bare curated names normalized
    to ``provider/model``. Deduped, order-preserving. Returns ``[]`` gracefully
    when neither source yields models (no ``[llm]`` extra, unknown task), so the
    form renders for every server (including non-LLM ones).
    """
    modes = _TASK_CATALOG_MODES.get(task)
    if not modes:
        return []
    # Vertex express is chat/vision only; remap vertex_ai/gemini-* -> vertex_express
    # for chat-family tasks and drop other vertex_ai/* (see _normalize_litellm_id).
    is_chat = modes == ("chat",)
    out: list[str] = []
    seen: set[str] = set()

    def _add(model_id: str) -> None:
        if model_id and model_id not in seen:
            seen.add(model_id)
            out.append(model_id)

    try:
        from mcp_core.llm.provider_catalog import provider_catalog_models

        for m in provider_catalog_models(task):
            _add(m)
    except Exception:
        pass

    try:
        from mcp_core.llm.catalog import list_models

        for m in list_models(modes=modes, configured_only=False, limit=limit):
            if isinstance(m, dict) and m.get("model"):
                norm = _normalize_litellm_id(str(m["model"]), str(m.get("provider", "")), chat=is_chat)
                if norm is not None:
                    _add(norm)
    except Exception:
        pass

    return out


def _render_field(field: dict[str, Any], value: str = "") -> str:
    """Render a single ConfigField as an HTML input block.

    ``value`` is the prefill string from the GET ``?prefill_<KEY>=<VALUE>``
    query param. When non-empty it lands as an HTML-escaped ``value`` attr
    so the user sees the field already filled and only has to click Connect.
    """
    key = _escape(field.get("key", ""))
    label = _escape(field.get("label", ""))
    field_type = _escape(field.get("type", "text"))
    placeholder = _escape(field.get("placeholder", ""))
    help_text = _escape(field.get("helpText", ""))
    help_url = _escape(field.get("helpUrl", ""))
    required = field.get("required", False)

    required_attr = " required" if required else ""
    required_badge = (
        '<span class="required-badge" aria-hidden="true">Required</span>'
        if required
        else '<span class="optional-badge" aria-hidden="true">Optional</span>'
    )

    value_attr = f' value="{_escape(value)}"' if value else ""
    # ``validation`` (a regex string) renders as the input's ``pattern`` attr so
    # the browser applies it natively. Escaped so it cannot break out of the
    # attribute. Parity with core-ts ``renderField`` (#656).
    pattern_attr = f' pattern="{_escape(field["validation"])}"' if field.get("validation") else ""

    help_html = ""
    aria_describedby = ""
    if help_text:
        aria_describedby = f' aria-describedby="help-{key}"'
        if help_url:
            help_html = f'<p class="help-text" id="help-{key}"><a href="{help_url}" target="_blank" rel="noopener noreferrer">{help_text}</a></p>'
        else:
            help_html = f'<p class="help-text" id="help-{key}">{help_text}</p>'

    # --- model-chain widget: chip combobox + drag-reorder; the JS keeps a
    # hidden ``.field-input`` synced with the CSV so the existing submit
    # handler picks it up unchanged.
    if field_type in ("model-chain", "search-chain"):
        task = _escape(field.get("task", ""))
        has_local = "true" if field.get("hasLocal", False) else "false"
        suggested = field.get("suggestedModels", [])
        suggested_json = _escape(json.dumps(suggested))
        # Back the dropdown with the real litellm catalog so the widget is a
        # searchable combobox, not a curated cage. Only for model-chain
        # (prefix-inferred litellm models); search-chain (named backends) and
        # any litellm-unavailable case fall back to an empty catalog.
        catalog_models = _catalog_models_for_task(field.get("task", "")) if field_type == "model-chain" else []
        catalog_json = _escape(json.dumps(catalog_models))
        # search-chain uses explicit named backends (no model-prefix inference):
        # ``providerKeys`` (backend -> ENV var) drives derive-keys, and
        # ``noun``/``localLabel`` customize the empty-chain badge. Absent for a
        # model-chain field -> the widget falls back to prefix inference + the
        # default "models"/"local ONNX" badge, so model-chain output is byte-for-
        # byte unchanged.
        provider_keys = field.get("providerKeys")
        provider_keys_attr = f' data-provider-keys="{_escape(json.dumps(provider_keys))}"' if provider_keys else ""
        noun_attr = f' data-noun="{_escape(field["noun"])}"' if field.get("noun") else ""
        local_label_attr = f' data-local-label="{_escape(field["localLabel"])}"' if field.get("localLabel") else ""
        return f"""
        <div class="field-group">
            <label class="field-label" for="mc-input-{key}">
                {label}
                <span class="optional-badge" aria-hidden="true">Optional</span>
            </label>
            <div class="model-chain" id="mc-{key}"
                 data-model-chain="{task}"
                 data-key="{key}"
                 data-has-local="{has_local}"
                 data-suggested="{suggested_json}" data-catalog="{catalog_json}"{provider_keys_attr}{noun_attr}{local_label_attr}>
                <div class="mc-chips" id="mc-chips-{key}" role="list"></div>
                <input id="mc-input-{key}" class="mc-typeahead" type="text"
                       placeholder="{placeholder or "add model…"}"
                       autocomplete="off" autocorrect="off"
                       autocapitalize="off" spellcheck="false" />
                <div class="mc-dropdown" id="mc-dropdown-{key}" hidden></div>
                <span class="mc-badge" id="mc-badge-{key}"></span>
            </div>
            <input type="hidden" name="{key}" class="field-input"
                   id="field-{key}"{value_attr} />
            {help_html}
        </div>"""

    # --- derived credential field: rendered but hidden until a model-chain
    # chip references its provider (derive-keys JS toggles display).
    if field.get("derived", False):
        return f"""
        <div class="field-group" data-provider-key="{key}" style="display:none">
            <label for="field-{key}" class="field-label">
                {label}
                <span class="optional-badge" aria-hidden="true">Optional</span>
            </label>
            <input
                id="field-{key}"
                name="{key}"
                type="{field_type}"
                placeholder="{placeholder}"
                class="field-input"
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck="false"{value_attr}{aria_describedby}
            />
            {help_html}
        </div>"""

    return f"""
        <div class="field-group">
            <label for="field-{key}" class="field-label">
                {label}
                {required_badge}
            </label>
            <input
                id="field-{key}"
                name="{key}"
                type="{field_type}"
                placeholder="{placeholder}"
                class="field-input"
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck="false"{value_attr}{pattern_attr}{required_attr}{aria_describedby}
            />
            {help_html}
        </div>"""


def _render_capability(cap: dict[str, Any]) -> str:
    """Render a single CapabilityInfo item."""
    label = _escape(cap.get("label", ""))
    priority = _escape(cap.get("priority", ""))
    description = _escape(cap.get("description", ""))

    priority_class = f"priority-{priority}" if priority else "priority-medium"

    return f"""
            <li class="capability-item">
                <div class="capability-header">
                    <span class="capability-label">{label}</span>
                    <span class="capability-priority {priority_class}">{priority}</span>
                </div>
                {f'<p class="capability-desc">{description}</p>' if description else ""}
            </li>"""


# ===========================================================================
# Schema-level tabs + dynamic card group (W4.1)
# ---------------------------------------------------------------------------
# Two OPT-IN capabilities that let servers declare richer credential UIs
# through the schema alone (no forked renderer):
#   * ``tabs``      -> mutually-exclusive credential modes (e.g. telegram
#                      bot-token vs phone/OTP), only the active tab submits.
#   * ``cardGroup`` -> a repeatable field group with Add/Remove (e.g. email
#                      multi-account), submitted as a JSON array.
# A schema that declares NEITHER key renders through the unchanged flat-field
# path in ``render_credential_form`` below, byte-for-byte identical to before,
# so every existing server (wet, mnemo, crg, notion, ...) is unaffected. The
# feature CSS ships as a ``<style>`` block inside the body — only when the
# feature is used — so the shared ``_FORM_SHELL_CSS`` (and the flat form) stay
# untouched. Kept in parity with core-ts ``credential-form.ts``.
# ===========================================================================

# Tab CSS (scoped ``.tabs``/``.tab``/``.tab-panel``); emitted in-body only for
# tabbed forms. Palette mirrors the shared shell so tabs blend into the card.
_TABS_CSS = """    <style>
        .tabs {
            display: flex;
            gap: 0;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid #2a2a2a;
        }
        .tab {
            flex: 1;
            padding: 0.75rem 1rem;
            background: transparent;
            border: none;
            color: #9ca3af;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
            border-bottom: 2px solid transparent;
            transition: color 0.15s ease, border-color 0.15s ease;
            font-family: inherit;
        }
        .tab:not(:disabled):hover {
            color: #ccc;
        }
        .tab:focus-visible {
            outline: 2px solid #4a6fa5;
            outline-offset: -2px;
            border-radius: 4px;
        }
        .tab.active {
            color: #fff;
            border-bottom-color: #4a6fa5;
        }
        .tab:disabled {
            cursor: not-allowed;
            opacity: 0.5;
        }
        .tab-panel {
            display: none;
        }
        .tab-panel.active {
            display: block;
        }
        @media (prefers-color-scheme: light) {
            .tabs {
                border-bottom-color: #e5e7eb;
            }
            .tab {
                color: #6b7280;
            }
            .tab:not(:disabled):hover {
                color: #374151;
            }
            .tab.active {
                color: #111827;
            }
        }
    </style>
"""

# Card-group CSS (scoped ``.card-group-*``); emitted in-body only for card
# forms. ``.card-group-item`` avoids the shell's ``.card`` name deliberately.
_CARD_GROUP_CSS = """    <style>
        .card-group-item {
            border: 1px solid #2a2a2a;
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 0.875rem;
            background-color: #121212;
        }
        .card-group-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }
        .card-group-title {
            font-size: 0.95rem;
            font-weight: 600;
            color: #ddd;
            max-width: 300px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .card-group-remove {
            background: transparent;
            color: #f87171;
            border: 1px solid rgba(248, 113, 113, 0.3);
            border-radius: 6px;
            padding: 0.25rem 0.6rem;
            cursor: pointer;
            font-size: 0.75rem;
            font-family: inherit;
        }
        .card-group-remove:hover:not(:disabled) {
            background-color: rgba(248, 113, 113, 0.08);
        }
        .card-group-remove:focus-visible {
            outline: 2px solid #f87171;
            outline-offset: 2px;
        }
        .card-group-add {
            width: 100%;
            background-color: transparent;
            color: #6c9bd2;
            border: 1px dashed #3a5a8a;
            border-radius: 8px;
            padding: 0.625rem 1rem;
            cursor: pointer;
            font-size: 0.875rem;
            margin-bottom: 1rem;
            font-family: inherit;
            transition: background-color 0.15s ease, border-color 0.15s ease;
        }
        .card-group-add:hover:not(:disabled) {
            background-color: rgba(108, 155, 210, 0.08);
            border-color: #4a6fa5;
        }
        .card-group-add:focus-visible {
            outline: 2px solid #6c9bd2;
            outline-offset: 2px;
        }
        .card-group-add:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            border-color: #2a3a4a;
        }
        @media (prefers-color-scheme: light) {
            .card-group-item {
                background-color: #f9fafb;
                border-color: #e5e7eb;
            }
            .card-group-title {
                color: #374151;
            }
        }
    </style>
"""

# Multi-step (OTP / 2FA) step-input UI, shared by tab forms. Written as a plain
# (non-f) string so JS braces need no escaping. Mirrors the flat form's
# ``showStepInput``/``submitStep`` semantics (same ``/otp`` POST, same
# redirect-follow on completion) so a tabbed server's phone->OTP->2FA chain
# behaves identically to the default form.
_STEP_UI_JS = """
            function showStepInput(ns) {
                if (form && form.style.display !== "none") { form.style.display = "none"; }
                var tabsEl = document.querySelector(".tabs");
                if (tabsEl) { tabsEl.style.display = "none"; }
                var container = document.getElementById("step-container");
                var promptEl, inputEl, buttonEl, errorEl;
                if (container) {
                    promptEl = document.getElementById("step-prompt");
                    inputEl = document.getElementById("step-input");
                    buttonEl = document.getElementById("step-submit");
                    errorEl = document.getElementById("step-error");
                    errorEl.style.display = "none"; errorEl.textContent = "";
                    inputEl.value = ""; inputEl.disabled = false;
                    buttonEl.disabled = false; buttonEl.removeAttribute("aria-busy"); buttonEl.textContent = "Verify";
                } else {
                    var card = form.parentNode;
                    container = document.createElement("div"); container.id = "step-container";
                    promptEl = document.createElement("label"); promptEl.id = "step-prompt";
                    promptEl.setAttribute("for", "step-input"); promptEl.className = "form-title";
                    container.appendChild(promptEl);
                    var fieldGroup = document.createElement("div"); fieldGroup.className = "field-group";
                    inputEl = document.createElement("input"); inputEl.id = "step-input"; inputEl.className = "field-input";
                    inputEl.setAttribute("autocomplete", "off"); inputEl.setAttribute("autocorrect", "off");
                    inputEl.setAttribute("autocapitalize", "off"); inputEl.setAttribute("spellcheck", "false");
                    fieldGroup.appendChild(inputEl); container.appendChild(fieldGroup);
                    buttonEl = document.createElement("button"); buttonEl.type = "button"; buttonEl.id = "step-submit";
                    buttonEl.className = "submit-btn"; buttonEl.textContent = "Verify"; container.appendChild(buttonEl);
                    errorEl = document.createElement("div"); errorEl.id = "step-error"; errorEl.className = "status-box error";
                    errorEl.setAttribute("role", "alert"); errorEl.setAttribute("aria-live", "polite"); errorEl.setAttribute("aria-atomic", "true"); errorEl.style.display = "none"; container.appendChild(errorEl);
                    card.appendChild(container);
                    buttonEl.addEventListener("click", function () { submitStep(); });
                    inputEl.addEventListener("keydown", function (evt) { if (evt.key === "Enter") { evt.preventDefault(); submitStep(); } });
                    inputEl.addEventListener("input", function () { inputEl.removeAttribute("aria-invalid"); inputEl.removeAttribute("aria-errormessage"); errorEl.style.display = "none"; });
                }
                promptEl.textContent = ns.text || "";
                inputEl.setAttribute("type", ns.input_type || "text");
                inputEl.setAttribute("placeholder", ns.placeholder || "");
                inputEl.dataset.field = ns.field || "value";
                inputEl.focus();
            }
            function submitStep() {
                var inputEl = document.getElementById("step-input");
                var buttonEl = document.getElementById("step-submit");
                var errorEl = document.getElementById("step-error");
                var fieldName = inputEl.dataset.field || "value";
                var value = inputEl.value;
                inputEl.removeAttribute("aria-invalid");
                if (value.trim() === "") {
                    errorEl.textContent = "Please enter a value."; errorEl.style.display = "block";
                    inputEl.setAttribute("aria-invalid", "true"); inputEl.setAttribute("aria-errormessage", "step-error");
                    inputEl.focus(); return;
                }
                errorEl.style.display = "none"; errorEl.textContent = "";
                buttonEl.disabled = true; buttonEl.textContent = "Verifying..."; buttonEl.setAttribute("aria-busy", "true");
                inputEl.disabled = true;
                var body = {}; body[fieldName] = value;
                fetch(otpUrl(), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
                    .then(function (response) { return response.json().then(function (data) {
                        if (data.ok) {
                            if (data.next_step && (data.next_step.type === "otp_required" || data.next_step.type === "password_required")) {
                                showStepInput(data.next_step);
                            } else if (typeof data.redirect_url === "string" && data.redirect_url.length > 0) {
                                var c = document.getElementById("step-container"); while (c.firstChild) { c.removeChild(c.firstChild); }
                                var done = document.createElement("div"); done.className = "status-box success"; done.style.display = "block";
                                done.setAttribute("role", "alert"); done.setAttribute("aria-live", "polite"); done.setAttribute("aria-atomic", "true"); done.textContent = "Setup complete! Redirecting..."; c.appendChild(done);
                                window.location.replace(data.redirect_url);
                            } else {
                                var c2 = document.getElementById("step-container"); while (c2.firstChild) { c2.removeChild(c2.firstChild); }
                                var done2 = document.createElement("div"); done2.className = "status-box success"; done2.style.display = "block";
                                done2.setAttribute("role", "alert"); done2.setAttribute("aria-live", "polite"); done2.setAttribute("aria-atomic", "true"); done2.textContent = "Setup complete! You can close this tab."; c2.appendChild(done2);
                            }
                        } else {
                            errorEl.textContent = data.error || data.error_description || "Verification failed."; errorEl.style.display = "block";
                            inputEl.disabled = false; inputEl.setAttribute("aria-invalid", "true"); inputEl.setAttribute("aria-errormessage", "step-error");
                            buttonEl.disabled = false; buttonEl.textContent = "Verify"; buttonEl.removeAttribute("aria-busy"); inputEl.focus();
                        }
                    }); })
                    .catch(function (err) {
                        errorEl.textContent = "Network error: " + err.message; errorEl.style.display = "block";
                        inputEl.disabled = false; inputEl.setAttribute("aria-invalid", "true"); inputEl.setAttribute("aria-errormessage", "step-error");
                        buttonEl.disabled = false; buttonEl.textContent = "Verify"; buttonEl.removeAttribute("aria-busy"); inputEl.focus();
                    });
            }
"""


def _resolve_active_tab(tabs: list[dict[str, Any]], initial_tab: str | None) -> str:
    """Return the id of the tab that should render active on load.

    Defaults to the first tab. ``initial_tab`` (a server-computed hint, e.g.
    telegram opening the phone tab when only a phone was prefilled) wins when
    it names a real tab; an unknown hint falls back to the first tab.
    """
    ids = [str(t.get("id", "")) for t in tabs]
    if initial_tab is not None and initial_tab in ids:
        return initial_tab
    return ids[0] if ids else ""


def _render_tabbed_credential_form(
    schema: dict[str, Any],
    *,
    submit_url: str,
    page_title: str | None,
    prefill: dict[str, str] | None,
    include_username_field: bool,
    initial_tab: str | None,
) -> str:
    """Render a credential form whose fields are split across mutually-exclusive tabs.

    Only the active tab's fields are collected on submit, so a schema can offer
    several credential modes (each a tab) without the inactive mode's fields
    leaking into the POST. Multi-step (OTP / 2FA) chaining works exactly as the
    flat form. See ``_TABS_CSS`` / ``_STEP_UI_JS``.
    """
    display_name = _escape(schema.get("displayName", schema.get("server", "Configuration")))
    server = _escape(schema.get("server", ""))
    description = _escape(schema.get("description", ""))
    title = page_title if page_title is not None else schema.get("displayName", schema.get("server", "Configuration"))
    submit_url_escaped = _escape(submit_url)
    prefill = prefill or {}

    tabs: list[dict[str, Any]] = schema.get("tabs", [])
    active_id = _resolve_active_tab(tabs, initial_tab)

    tab_buttons = []
    tab_panels = []
    for tab in tabs:
        tid = _escape(tab.get("id", ""))
        label = _escape(tab.get("label", ""))
        is_active = tab.get("id", "") == active_id
        active_cls = " active" if is_active else ""
        aria_selected = "true" if is_active else "false"
        tabindex = "0" if is_active else "-1"
        tab_buttons.append(
            f'<button type="button" id="tab-{tid}" class="tab{active_cls}" data-tab="{tid}"'
            f' role="tab" aria-selected="{aria_selected}" tabindex="{tabindex}"'
            f' aria-controls="panel-{tid}">{label}</button>'
        )
        panel_fields = "".join([_render_field(f, prefill.get(f.get("key", ""), "")) for f in tab.get("fields", [])])
        tab_panels.append(
            f'<div id="panel-{tid}" class="tab-panel{active_cls}" data-panel="{tid}"'
            f' role="tabpanel" aria-labelledby="tab-{tid}">{panel_fields}\n                </div>'
        )

    tabs_html = "\n                ".join(tab_buttons)
    panels_html = "\n                ".join(tab_panels)

    username_html = _username_field_html() if include_username_field else ""

    capability_info: list[dict[str, Any]] = schema.get("capabilityInfo", [])
    capabilities_html = ""
    if capability_info:
        items_html = "".join([_render_capability(c) for c in capability_info])
        capabilities_html = f"""
        <section class="capabilities-section" aria-labelledby="capabilities-title">
            <h2 class="capabilities-title" id="capabilities-title">Capabilities Requested</h2>
            <ul class="capabilities-list">{items_html}
            </ul>
        </section>"""

    description_html = f'<p class="server-description" id="server-desc">{description}</p>' if description else ""
    form_aria = ' aria-describedby="server-desc"' if description else ""

    script = _TABS_SCRIPT.replace("__SUBMIT_URL__", submit_url_escaped).replace("__INITIAL_TAB__", active_id)

    body_html = f"""{_TABS_CSS}    <div class="container">
        <div class="card">
            <div class="server-header">
                <h1 class="server-name">{display_name}</h1>
                <div class="server-id">{server}</div>
                {description_html}
            </div>

            <div class="tabs" role="tablist" aria-label="Credential mode">
                {tabs_html}
            </div>

            <form id="credential-form"{form_aria} novalidate>
                {username_html}{panels_html}

                <button type="submit" class="submit-btn" id="submit-btn">Connect</button>

                <div class="status-box" id="status-box" role="alert" aria-live="polite" aria-atomic="true"></div>
            </form>
        </div>
        {capabilities_html}
    </div>
{script}"""

    return render_form_shell(title, body_html)


# Tab form behaviour: tab switching (click + ARIA-tablist arrow keys), then a
# submit that collects ONLY the active panel's fields. ``__SUBMIT_URL__`` and
# ``__INITIAL_TAB__`` are substituted at render time; ``_STEP_UI_JS`` is spliced
# in for OTP/2FA support.
_TABS_SCRIPT = (
    """    <script>
        (function () {
            var form = document.getElementById("credential-form");
            var submitBtn = document.getElementById("submit-btn");
            var statusBox = document.getElementById("status-box");
            var submitUrl = "__SUBMIT_URL__";
            var activeTab = "__INITIAL_TAB__";
            var tabs = document.querySelectorAll(".tab");
            var tabsArray = Array.prototype.slice.call(tabs);
            var pendingRedirectUrl = null;

            function showStatus(type, message) {
                statusBox.className = "status-box " + type;
                statusBox.textContent = message;
                statusBox.style.display = "block";
            }
            function otpUrl() {
                return submitUrl.replace(/\\/authorize.*/, "/otp");
            }
"""
    + _STEP_UI_JS
    + """
            tabs.forEach(function (tab, index) {
                tab.addEventListener("click", function () {
                    if (tab.disabled) { return; }
                    activeTab = tab.dataset.tab;
                    tabs.forEach(function (t) {
                        t.classList.remove("active");
                        t.setAttribute("aria-selected", "false");
                        t.setAttribute("tabindex", "-1");
                    });
                    tab.classList.add("active");
                    tab.setAttribute("aria-selected", "true");
                    tab.setAttribute("tabindex", "0");
                    document.querySelectorAll(".tab-panel").forEach(function (p) { p.classList.remove("active"); });
                    var panel = document.querySelector('.tab-panel[data-panel="' + activeTab + '"]');
                    if (panel) { panel.classList.add("active"); }
                    statusBox.style.display = "none";
                    statusBox.textContent = "";
                    form.querySelectorAll(".field-input").forEach(function (i) { i.removeAttribute("aria-invalid"); });
                });
                tab.addEventListener("keydown", function (e) {
                    var targetIndex = -1;
                    if (e.key === "ArrowRight") { targetIndex = index + 1; if (targetIndex >= tabsArray.length) { targetIndex = 0; } }
                    else if (e.key === "ArrowLeft") { targetIndex = index - 1; if (targetIndex < 0) { targetIndex = tabsArray.length - 1; } }
                    if (targetIndex !== -1) { e.preventDefault(); tabsArray[targetIndex].focus(); tabsArray[targetIndex].click(); }
                });
            });

            form.addEventListener("input", function (event) {
                if (event.target.classList.contains("field-input")) {
                    event.target.removeAttribute("aria-invalid");
                    event.target.removeAttribute("aria-errormessage");
                    statusBox.style.display = "none";
                }
            });

            form.addEventListener("submit", function (event) {
                event.preventDefault();
                var activePanel = document.querySelector(".tab-panel.active");
                var inputs = activePanel ? activePanel.querySelectorAll(".field-input") : [];
                var payload = {};
                var valid = true;
                var firstInvalid = null;
                inputs.forEach(function (input) {
                    if (input.hasAttribute("required") && input.value.trim() === "") {
                        valid = false;
                        input.setAttribute("aria-invalid", "true");
                        input.setAttribute("aria-errormessage", "status-box");
                        if (!firstInvalid) { firstInvalid = input; }
                    } else {
                        input.removeAttribute("aria-invalid");
                        input.removeAttribute("aria-errormessage");
                        payload[input.name] = input.value;
                    }
                });
                if (!valid) {
                    showStatus("error", "Please fill in all required fields.");
                    if (firstInvalid) { firstInvalid.focus(); }
                    return;
                }
                submitBtn.disabled = true;
                submitBtn.textContent = "Connecting...";
                submitBtn.setAttribute("aria-busy", "true");
                statusBox.style.display = "none";
                tabs.forEach(function (t) { t.disabled = true; });
                function reenable() {
                    submitBtn.disabled = false;
                    submitBtn.textContent = "Connect";
                    submitBtn.removeAttribute("aria-busy");
                    form.querySelectorAll(".field-input").forEach(function (i) { i.disabled = false; });
                    tabs.forEach(function (t) { t.disabled = false; });
                }
                function lockConnected() {
                    form.querySelectorAll(".field-input").forEach(function (i) { i.disabled = true; });
                    submitBtn.disabled = true;
                    submitBtn.removeAttribute("aria-busy");
                    submitBtn.textContent = "Connected";
                }
                fetch(submitUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
                    .then(function (response) { return response.json().then(function (data) {
                        if (data.ok) {
                            if (typeof data.redirect_url === "string" && data.redirect_url.length > 0) { pendingRedirectUrl = data.redirect_url; }
                            if (data.next_step && (data.next_step.type === "otp_required" || data.next_step.type === "password_required")) {
                                statusBox.style.display = "none";
                                showStepInput(data.next_step);
                            } else if (data.next_step && data.next_step.type === "info") {
                                lockConnected();
                                showStatus("success", data.next_step.message || "Setup saved. Additional steps may be required.");
                            } else if (pendingRedirectUrl) {
                                lockConnected();
                                showStatus("success", "Credentials saved. Redirecting...");
                                window.location.replace(pendingRedirectUrl);
                            } else {
                                lockConnected();
                                showStatus("success", data.message || "Connected successfully. You can close this window.");
                            }
                        } else {
                            showStatus("error", data.error || data.error_description || "Request failed.");
                            reenable();
                        }
                    }); })
                    .catch(function (err) {
                        showStatus("error", "Network error: " + err.message);
                        reenable();
                    });
            });
        })();
    </script>"""
)


def _username_field_html() -> str:
    """Optional workspace-username field shared by the flat + feature forms.

    Carries the ``.field-input`` class so the form's collector picks it up into
    the POST as ``__sub_username`` (the local OAuth AS pops it to derive a
    STABLE sub). Optional, so it never blocks submit.
    """
    return (
        '<div class="field-group">'
        '<label for="field-__sub_username" class="field-label">Workspace / username'
        ' <span class="optional-badge" aria-hidden="true">Optional</span></label>'
        '<input id="field-__sub_username" type="text" name="__sub_username"'
        ' class="field-input" placeholder="e.g. alice" aria-describedby="help-__sub_username"'
        ' autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" />'
        '<p class="help-text" id="help-__sub_username">Leave blank for a one-off session. Set the same value on'
        " every device to keep your saved data (one shared bucket per username).</p>"
        "</div>"
    )


def _render_card_group_credential_form(
    schema: dict[str, Any],
    *,
    submit_url: str,
    page_title: str | None,
    prefill: dict[str, str] | None,
    include_username_field: bool,
) -> str:
    """Render a credential form built around one repeatable card group.

    The group's fields are cloned per card (Add/Remove) and submitted as a JSON
    array under the group ``key`` (e.g. ``{"accounts": [{"email": "...", ...}]}``).
    An Outlook-style device-code follow-up is supported via the response handler.
    See ``_CARD_GROUP_CSS`` / ``_CARD_GROUP_SCRIPT``.
    """
    display_name = _escape(schema.get("displayName", schema.get("server", "Configuration")))
    server = _escape(schema.get("server", ""))
    description = _escape(schema.get("description", ""))
    title = page_title if page_title is not None else schema.get("displayName", schema.get("server", "Configuration"))
    submit_url_escaped = _escape(submit_url)

    group: dict[str, Any] = schema.get("cardGroup", {})
    group_key = str(group.get("key", "items"))
    item_label = str(group.get("itemLabel", "Item"))
    add_label = _escape(group.get("addButtonLabel", "+ Add"))
    min_items = int(group.get("minItems", 1))
    title_field = str(group.get("titleField", ""))
    group_heading = _escape(group.get("heading", item_label + "s"))
    fields = group.get("fields", [])

    # Field spec drives the client-side card builder. Compact separators match
    # JS ``JSON.stringify`` byte-for-byte (core-ts parity); ``<`` is escaped to
    # ``<`` so the JSON cannot terminate the surrounding <script> early.
    fields_json = json.dumps(fields, separators=(",", ":")).replace("<", "\\u003c")

    username_html = _username_field_html() if include_username_field else ""

    capability_info: list[dict[str, Any]] = schema.get("capabilityInfo", [])
    capabilities_html = ""
    if capability_info:
        items_html = "".join([_render_capability(c) for c in capability_info])
        capabilities_html = f"""
        <section class="capabilities-section" aria-labelledby="capabilities-title">
            <h2 class="capabilities-title" id="capabilities-title">Capabilities Requested</h2>
            <ul class="capabilities-list">{items_html}
            </ul>
        </section>"""

    description_html = f'<p class="server-description" id="server-desc">{description}</p>' if description else ""

    # ``__CARD_FIELDS__`` (the only placeholder carrying user-controlled JSON) is
    # substituted LAST so a crafted field value cannot be mistaken for another
    # placeholder token.
    script = (
        _CARD_GROUP_SCRIPT.replace("__SUBMIT_URL__", submit_url_escaped)
        .replace("__GROUP_KEY__", _js_string(group_key))
        .replace("__TITLE_FIELD__", _js_string(title_field))
        .replace("__ITEM_LABEL__", _js_string(item_label))
        .replace("__MIN_ITEMS__", str(min_items))
        .replace("__CARD_FIELDS__", fields_json)
    )

    body_html = f"""{_CARD_GROUP_CSS}    <div class="container">
        <div class="card">
            <div class="server-header">
                <h1 class="server-name">{display_name}</h1>
                <div class="server-id">{server}</div>
                {description_html}
            </div>

            <h2 class="form-title" id="form-title">{group_heading}</h2>

            <form id="credential-form" aria-labelledby="form-title" novalidate>
                <fieldset id="form-fieldset" style="border: none; padding: 0; margin: 0;">
                    {username_html}<div id="card-group-container"></div>

                    <button type="button" class="card-group-add" id="card-group-add">{add_label}</button>

                    <button type="submit" class="submit-btn" id="submit-btn">Connect</button>
                </fieldset>

                <div class="status-box" id="status-box" role="alert" aria-live="polite" aria-atomic="true"></div>
            </form>
        </div>
        {capabilities_html}
    </div>
{script}"""

    return render_form_shell(title, body_html)


def _js_string(value: str) -> str:
    """Escape a Python string for safe embedding inside a double-quoted JS literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("<", "\\u003c")


# Card-group behaviour: a JS builder that clones the declared fields per card,
# Add/Remove with focus management, and a submit that serialises every card into
# a JSON array under ``__GROUP_KEY__``. All DOM is built with
# createElement/textContent/setAttribute (no innerHTML with user values).
# Placeholders substituted at render: ``__SUBMIT_URL__`` (HTML-escaped),
# ``__CARD_FIELDS__`` (JSON), ``__GROUP_KEY__``/``__TITLE_FIELD__``/``__ITEM_LABEL__``
# (JS string literals), ``__MIN_ITEMS__`` (int).
_CARD_GROUP_SCRIPT = """    <script>
        (function () {
            var submitUrl = "__SUBMIT_URL__";
            var CARD_FIELDS = __CARD_FIELDS__;
            var GROUP_KEY = "__GROUP_KEY__";
            var TITLE_FIELD = "__TITLE_FIELD__";
            var ITEM_LABEL = "__ITEM_LABEL__";
            var MIN_ITEMS = __MIN_ITEMS__;

            var container = document.getElementById("card-group-container");
            var addBtn = document.getElementById("card-group-add");
            var form = document.getElementById("credential-form");
            var submitBtn = document.getElementById("submit-btn");
            var statusBox = document.getElementById("status-box");
            var formFieldset = document.getElementById("form-fieldset");
            var uid = 0;
            var pendingRedirectUrl = null;

            function showStatus(type, message) {
                statusBox.className = "status-box " + type;
                statusBox.textContent = message;
                statusBox.style.display = "block";
            }
            function safeRedirect(url) {
                try {
                    var parsed = new URL(url, window.location.origin);
                    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
                        window.location.replace(parsed.href);
                        return true;
                    }
                } catch (e) { /* fail safe */ }
                return false;
            }

            function buildField(spec, cardUid) {
                var group = document.createElement("div");
                group.className = "field-group";
                var fid = "field-" + GROUP_KEY + "-" + spec.key + "-" + cardUid;

                var label = document.createElement("label");
                label.className = "field-label";
                label.setAttribute("for", fid);
                label.textContent = spec.label || "";
                var badge = document.createElement("span");
                badge.setAttribute("aria-hidden", "true");
                if (spec.required) { badge.className = "required-badge"; badge.textContent = "Required"; }
                else { badge.className = "optional-badge"; badge.textContent = "Optional"; }
                label.appendChild(document.createTextNode(" "));
                label.appendChild(badge);
                group.appendChild(label);

                var input = document.createElement("input");
                input.id = fid;
                input.className = "field-input";
                input.setAttribute("type", spec.type || "text");
                input.setAttribute("name", GROUP_KEY + "[" + cardUid + "]." + spec.key);
                input.dataset.field = spec.key;
                input.setAttribute("autocomplete", "off");
                input.setAttribute("autocorrect", "off");
                input.setAttribute("autocapitalize", "off");
                input.setAttribute("spellcheck", "false");
                if (spec.placeholder) { input.setAttribute("placeholder", spec.placeholder); }
                if (spec.required) { input.setAttribute("required", "required"); }
                group.appendChild(input);

                if (spec.helpText) {
                    var help = document.createElement("p");
                    help.className = "help-text";
                    help.id = "help-" + GROUP_KEY + "-" + spec.key + "-" + cardUid;
                    if (spec.helpUrl) {
                        var a = document.createElement("a");
                        a.setAttribute("href", spec.helpUrl);
                        a.setAttribute("target", "_blank");
                        a.setAttribute("rel", "noopener noreferrer");
                        a.textContent = spec.helpText;
                        help.appendChild(a);
                    } else {
                        help.textContent = spec.helpText;
                    }
                    input.setAttribute("aria-describedby", help.id);
                    group.appendChild(help);
                }

                input.addEventListener("input", function () {
                    if (input.hasAttribute("aria-invalid")) { input.removeAttribute("aria-invalid"); }
                });
                return input;
            }

            function updateTitles() {
                var cards = container.querySelectorAll(".card-group-item");
                for (var i = 0; i < cards.length; i++) {
                    var titleEl = cards[i].querySelector(".card-group-title");
                    var titleInput = TITLE_FIELD ? cards[i].querySelector('input[data-field="' + TITLE_FIELD + '"]') : null;
                    var titleVal = titleInput && titleInput.value ? titleInput.value.trim() : "";
                    var titleStr = titleVal ? titleVal : (ITEM_LABEL + " " + (i + 1));
                    if (titleEl) { titleEl.textContent = titleStr; titleEl.title = titleStr; }
                    var removeBtn = cards[i].querySelector(".card-group-remove");
                    if (removeBtn) {
                        removeBtn.style.display = cards.length > MIN_ITEMS ? "" : "none";
                        removeBtn.setAttribute("aria-label", "Remove " + titleStr);
                    }
                }
            }

            function createCard() {
                var cardUid = uid++;
                var card = document.createElement("div");
                card.className = "card-group-item";
                card.dataset.uid = String(cardUid);
                card.setAttribute("role", "group");
                var titleId = "card-group-title-" + cardUid;
                card.setAttribute("aria-labelledby", titleId);

                var header = document.createElement("div");
                header.className = "card-group-header";
                var title = document.createElement("h3");
                title.id = titleId;
                title.className = "card-group-title";
                title.textContent = ITEM_LABEL;
                header.appendChild(title);

                var removeBtn = document.createElement("button");
                removeBtn.type = "button";
                removeBtn.className = "card-group-remove";
                removeBtn.textContent = "Remove";
                removeBtn.addEventListener("click", function () {
                    var inputs = card.querySelectorAll("input");
                    var hasData = false;
                    for (var i = 0; i < inputs.length; i++) { if (inputs[i].value.trim() !== "") { hasData = true; break; } }
                    if (hasData && !window.confirm("This " + ITEM_LABEL.toLowerCase() + " has unsaved data. Remove it?")) { return; }
                    var prev = card.previousElementSibling;
                    var next = card.nextElementSibling;
                    var focusTarget = (prev && prev.classList && prev.classList.contains("card-group-item")) ? prev :
                                      (next && next.classList && next.classList.contains("card-group-item")) ? next : null;
                    card.remove();
                    updateTitles();
                    if (focusTarget) {
                        var fi = focusTarget.querySelector("input");
                        if (fi) { fi.focus(); return; }
                    }
                    if (addBtn) { addBtn.focus(); }
                });
                header.appendChild(removeBtn);
                card.appendChild(header);

                for (var f = 0; f < CARD_FIELDS.length; f++) {
                    var input = buildField(CARD_FIELDS[f], cardUid);
                    card.appendChild(input.parentNode);
                    if (CARD_FIELDS[f].key === TITLE_FIELD) {
                        input.addEventListener("input", updateTitles);
                    }
                }
                return card;
            }

            function collectCards() {
                var cards = container.querySelectorAll(".card-group-item");
                var arr = [];
                for (var i = 0; i < cards.length; i++) {
                    var inputs = cards[i].querySelectorAll(".field-input");
                    var obj = {};
                    var hasAny = false;
                    for (var j = 0; j < inputs.length; j++) {
                        obj[inputs[j].dataset.field] = inputs[j].value;
                        if (inputs[j].value.trim() !== "") { hasAny = true; }
                    }
                    if (hasAny) { arr.push(obj); }
                }
                return arr;
            }

            function renderOAuthDeviceCode(nextStep) {
                statusBox.className = "status-box info";
                statusBox.style.display = "block";
                while (statusBox.firstChild) { statusBox.removeChild(statusBox.firstChild); }
                var strong = document.createElement("strong");
                strong.textContent = "Finish sign-in";
                statusBox.appendChild(strong);
                statusBox.appendChild(document.createElement("br"));
                statusBox.appendChild(document.createElement("br"));
                statusBox.appendChild(document.createTextNode("Visit:"));
                statusBox.appendChild(document.createElement("br"));
                var link = document.createElement("a");
                link.setAttribute("href", nextStep.verification_url);
                link.setAttribute("target", "_blank");
                link.setAttribute("rel", "noopener noreferrer");
                link.textContent = nextStep.verification_url;
                statusBox.appendChild(link);
                statusBox.appendChild(document.createElement("br"));
                statusBox.appendChild(document.createElement("br"));
                statusBox.appendChild(document.createTextNode("Enter code: "));
                var codeEl = document.createElement("strong");
                codeEl.style.fontSize = "1.2em";
                codeEl.style.letterSpacing = "0.1em";
                codeEl.style.userSelect = "all";
                codeEl.style.cursor = "copy";
                codeEl.title = "Click to select";
                codeEl.textContent = nextStep.user_code;
                statusBox.appendChild(codeEl);
                statusBox.appendChild(document.createElement("br"));
                statusBox.appendChild(document.createElement("br"));
                var waiting = document.createElement("span");
                waiting.id = "device-waiting";
                waiting.setAttribute("role", "alert");
                waiting.setAttribute("aria-live", "polite");
                waiting.setAttribute("aria-atomic", "true");
                waiting.style.color = "#9ca3af";
                waiting.textContent = "Waiting for authorization...";
                statusBox.appendChild(waiting);
                var statusUrl = submitUrl.replace(/\\/authorize.*/, "/setup-status");
                var pollId = setInterval(function () {
                    fetch(statusUrl)
                        .then(function (r) { return r.json(); })
                        .then(function (s) {
                            if (s && s.outlook === "complete") {
                                clearInterval(pollId);
                                statusBox.className = "status-box success";
                                while (statusBox.firstChild) { statusBox.removeChild(statusBox.firstChild); }
                                var done = document.createElement("strong");
                                done.textContent = "Setup complete!";
                                statusBox.appendChild(done);
                                submitBtn.textContent = "Connected";
                                if (typeof pendingRedirectUrl === "string" && pendingRedirectUrl.length > 0) {
                                    statusBox.appendChild(document.createElement("br"));
                                    statusBox.appendChild(document.createTextNode("Redirecting..."));
                                    safeRedirect(pendingRedirectUrl);
                                } else {
                                    statusBox.appendChild(document.createElement("br"));
                                    statusBox.appendChild(document.createTextNode("You can close this tab."));
                                }
                            } else if (s && typeof s.outlook === "string" && s.outlook.indexOf("error:") === 0) {
                                clearInterval(pollId);
                                var w = document.getElementById("device-waiting");
                                if (w) { w.style.color = "#ff453a"; w.textContent = "Authorization failed: " + s.outlook.slice(6) + ". Please retry setup."; }
                            }
                        })
                        .catch(function () {});
                }, 3000);
            }

            container.appendChild(createCard());
            for (var s = 1; s < MIN_ITEMS; s++) { container.appendChild(createCard()); }
            updateTitles();

            addBtn.addEventListener("click", function () {
                var newCard = createCard();
                container.appendChild(newCard);
                updateTitles();
                var fi = newCard.querySelector("input");
                if (fi) { fi.focus(); }
            });

            form.addEventListener("submit", function (evt) {
                evt.preventDefault();
                statusBox.style.display = "none";
                if (!form.checkValidity()) {
                    showStatus("error", "Please fill in all required fields.");
                    var firstInvalid = form.querySelector(":invalid");
                    if (firstInvalid) {
                        firstInvalid.setAttribute("aria-invalid", "true");
                        firstInvalid.setAttribute("aria-errormessage", "status-box");
                        firstInvalid.focus();
                    }
                    return;
                }
                var items = collectCards();
                if (items.length === 0) {
                    showStatus("error", "Please add at least one " + ITEM_LABEL.toLowerCase() + ".");
                    return;
                }
                var payload = {};
                payload[GROUP_KEY] = items;

                formFieldset.disabled = true;
                submitBtn.setAttribute("aria-busy", "true");
                submitBtn.textContent = "Connecting...";

                fetch(submitUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
                    .then(function (resp) { return resp.json().then(function (data) {
                        if (!data.ok) {
                            showStatus("error", data.error || data.error_description || "Request failed.");
                            formFieldset.disabled = false;
                            submitBtn.removeAttribute("aria-busy");
                            submitBtn.textContent = "Connect";
                            submitBtn.focus();
                            return;
                        }
                        if (typeof data.redirect_url === "string" && data.redirect_url.length > 0) { pendingRedirectUrl = data.redirect_url; }
                        if (data.next_step && data.next_step.type === "oauth_device_code") {
                            submitBtn.textContent = "Awaiting authorization...";
                            submitBtn.removeAttribute("aria-busy");
                            renderOAuthDeviceCode(data.next_step);
                            return;
                        }
                        if (pendingRedirectUrl) {
                            showStatus("success", "Credentials saved. Redirecting...");
                            submitBtn.textContent = "Connected";
                            submitBtn.removeAttribute("aria-busy");
                            if (!safeRedirect(pendingRedirectUrl)) {
                                showStatus("error", "Setup complete, but refused to redirect to unsafe URL.");
                            }
                            return;
                        }
                        showStatus("success", data.message || "Setup complete! You can close this tab.");
                        submitBtn.textContent = "Connected";
                        submitBtn.removeAttribute("aria-busy");
                    }); })
                    .catch(function (err) {
                        showStatus("error", "Network error: " + err.message);
                        formFieldset.disabled = false;
                        submitBtn.removeAttribute("aria-busy");
                        submitBtn.textContent = "Connect";
                        submitBtn.focus();
                    });
            });
        })();
    </script>"""


def render_credential_form(
    schema: dict[str, Any],
    *,
    submit_url: str,
    page_title: str | None = None,
    prefill: dict[str, str] | None = None,
    include_username_field: bool = False,
    initial_tab: str | None = None,
) -> str:
    """Render a dark-themed HTML credential form from a RelayConfigSchema dict.

    Args:
        schema: RelayConfigSchema dict with server metadata and field definitions.
        submit_url: URL the form POSTs to as JSON via fetch().
        page_title: Optional browser tab title. Defaults to displayName.
        prefill: Optional ``{KEY: VALUE}`` mapping for input ``value=`` attrs.
            Driver populates this from skret via ``?prefill_<KEY>=<VALUE>``
            query params on the GET so users only type what skret can't
            supply (OTP, 2FA password). Non-matching keys are ignored.

        initial_tab: Optional id of the tab to render active for a ``tabs``
            schema (defaults to the first tab). Ignored for non-tabbed schemas.

    Returns:
        Complete HTML document string, XSS-safe with all dynamic content escaped.
    """
    # Schema-level capabilities (opt-in): dispatch to the dedicated renderer.
    # A schema declaring neither key falls through to the unchanged flat form.
    if schema.get("tabs"):
        return _render_tabbed_credential_form(
            schema,
            submit_url=submit_url,
            page_title=page_title,
            prefill=prefill,
            include_username_field=include_username_field,
            initial_tab=initial_tab,
        )
    if schema.get("cardGroup"):
        return _render_card_group_credential_form(
            schema,
            submit_url=submit_url,
            page_title=page_title,
            prefill=prefill,
            include_username_field=include_username_field,
        )

    display_name = _escape(schema.get("displayName", schema.get("server", "Configuration")))
    server = _escape(schema.get("server", ""))
    description = _escape(schema.get("description", ""))
    title = page_title if page_title is not None else schema.get("displayName", schema.get("server", "Configuration"))
    submit_url_escaped = _escape(submit_url)

    fields: list[dict[str, Any]] = schema.get("fields", [])
    capability_info: list[dict[str, Any]] = schema.get("capabilityInfo", [])

    prefill = prefill or {}
    fields_html = "".join([_render_field(f, prefill.get(f.get("key", ""), "")) for f in fields])

    # Optional workspace-username field (opt-in via include_username_field).
    # Shared with the tabbed + card-group forms: this used to be an inline copy
    # of the same markup, and the copy is what drifted -- it kept its help text
    # unlinked long after the helper had gained aria-describedby.
    username_html = _username_field_html() if include_username_field else ""

    capabilities_html = ""
    if capability_info:
        items_html = "".join([_render_capability(c) for c in capability_info])
        capabilities_html = f"""
        <section class="capabilities-section" aria-labelledby="capabilities-title">
            <h2 class="capabilities-title" id="capabilities-title">Capabilities Requested</h2>
            <ul class="capabilities-list">{items_html}
            </ul>
        </section>"""

    description_html = f'<p class="server-description" id="server-desc">{description}</p>' if description else ""
    form_aria = ' aria-describedby="server-desc"' if description else ""

    body_html = f"""    <div class="container">
        <div class="card">
            <div class="server-header">
                <h1 class="server-name">{display_name}</h1>
                <div class="server-id">{server}</div>
                {description_html}
            </div>

            <p class="form-title" id="form-title">Enter your credentials</p>

            <form id="credential-form" aria-labelledby="form-title"{form_aria} novalidate>
                {username_html}{fields_html}

                <button type="submit" class="submit-btn" id="submit-btn">
                    Connect
                </button>

                <div class="status-box" id="status-box" role="alert" aria-live="polite" aria-atomic="true"></div>
            </form>
        </div>
        {capabilities_html}
    </div>

    <script>
        (function () {{
            var form = document.getElementById("credential-form");
            var submitBtn = document.getElementById("submit-btn");
            var statusBox = document.getElementById("status-box");
            var submitUrl = "{submit_url_escaped}";

            function showStatus(type, message) {{
                statusBox.className = "status-box " + type;
                statusBox.textContent = message;
                statusBox.style.display = "block";
            }}

            // Derive /otp endpoint URL from submitUrl (replaces /authorize... with /otp).
            function otpUrl() {{
                return submitUrl.replace(/\\/authorize.*/, "/otp");
            }}

            // Render (or update in-place) a step-input UI for otp_required / password_required.
            // ns: next_step object with {{ text, field, input_type, placeholder }}.
            // All textual content from ns is inserted via textContent (never innerHTML).
            function showStepInput(ns) {{
                // Hide the original credential form after first transition.
                if (form && form.style.display !== "none") {{
                    form.style.display = "none";
                }}

                // If a step container already exists, update it in-place (chained next_step).
                var container = document.getElementById("step-container");
                var promptEl, inputEl, buttonEl, errorEl;
                if (container) {{
                    promptEl = document.getElementById("step-prompt");
                    inputEl = document.getElementById("step-input");
                    buttonEl = document.getElementById("step-submit");
                    errorEl = document.getElementById("step-error");
                    errorEl.style.display = "none";
                    errorEl.textContent = "";
                    inputEl.value = "";
                    inputEl.disabled = false;
                    buttonEl.disabled = false;
                    buttonEl.removeAttribute("aria-busy");
                    buttonEl.textContent = "Verify";
                }} else {{
                    // Build a fresh step-input container inside the card.
                    var card = form.parentNode;
                    container = document.createElement("div");
                    container.id = "step-container";

                    promptEl = document.createElement("label");
                    promptEl.id = "step-prompt";
                    promptEl.setAttribute("for", "step-input");
                    promptEl.className = "form-title";
                    container.appendChild(promptEl);

                    var fieldGroup = document.createElement("div");
                    fieldGroup.className = "field-group";
                    inputEl = document.createElement("input");
                    inputEl.id = "step-input";
                    inputEl.className = "field-input";
                    inputEl.setAttribute("autocomplete", "off");
                    inputEl.setAttribute("autocorrect", "off");
                    inputEl.setAttribute("autocapitalize", "off");
                    inputEl.setAttribute("spellcheck", "false");
                    fieldGroup.appendChild(inputEl);
                    container.appendChild(fieldGroup);

                    buttonEl = document.createElement("button");
                    buttonEl.type = "button";
                    buttonEl.id = "step-submit";
                    buttonEl.className = "submit-btn";
                    buttonEl.textContent = "Verify";
                    container.appendChild(buttonEl);

                    errorEl = document.createElement("div");
                    errorEl.id = "step-error";
                    errorEl.className = "status-box error";
                    errorEl.setAttribute("role", "alert");
                    errorEl.setAttribute("aria-live", "polite");
                    errorEl.setAttribute("aria-atomic", "true");
                    errorEl.style.display = "none";
                    container.appendChild(errorEl);

                    card.appendChild(container);

                    // Submit handlers (attached once, read current field name from dataset).
                    buttonEl.addEventListener("click", function () {{
                        submitStep();
                    }});
                    inputEl.addEventListener("keydown", function (evt) {{
                        if (evt.key === "Enter") {{
                            evt.preventDefault();
                            submitStep();
                        }}
                    }});
                    inputEl.addEventListener("input", function() {{
                        inputEl.removeAttribute("aria-invalid");
                        inputEl.removeAttribute("aria-errormessage");
                        errorEl.style.display = "none";
                    }});
                }}

                // Populate prompt + input attributes via safe DOM APIs.
                promptEl.textContent = ns.text || "";
                inputEl.setAttribute("type", ns.input_type || "text");
                inputEl.setAttribute("placeholder", ns.placeholder || "");
                // Stash field name so submitStep can read it at click time.
                inputEl.dataset.field = ns.field || "value";
                inputEl.focus();
            }}

            function submitStep() {{
                var inputEl = document.getElementById("step-input");
                var buttonEl = document.getElementById("step-submit");
                var errorEl = document.getElementById("step-error");
                var fieldName = inputEl.dataset.field || "value";
                var value = inputEl.value;

                inputEl.removeAttribute("aria-invalid");

                if (value.trim() === "") {{
                    errorEl.textContent = "Please enter a value.";
                    errorEl.style.display = "block";
                    inputEl.setAttribute("aria-invalid", "true");
                    inputEl.setAttribute("aria-errormessage", "step-error");
                    inputEl.focus();
                    return;
                }}
                errorEl.style.display = "none";
                errorEl.textContent = "";
                buttonEl.disabled = true;
                buttonEl.textContent = "Verifying...";
                buttonEl.setAttribute("aria-busy", "true");
                inputEl.disabled = true;
                inputEl.removeAttribute("aria-invalid");

                var body = {{}};
                body[fieldName] = value;

                fetch(otpUrl(), {{
                    method: "POST",
                    headers: {{ "Content-Type": "application/json" }},
                    body: JSON.stringify(body),
                }})
                    .then(function (response) {{
                        return response.json().then(function (data) {{
                            if (data.ok) {{
                                if (data.next_step && (data.next_step.type === "otp_required" || data.next_step.type === "password_required")) {{
                                    // Chain: update in place with new prompt/field/type.
                                    showStepInput(data.next_step);
                                }} else if (typeof data.redirect_url === "string" && data.redirect_url.length > 0) {{
                                    // Multi-step auth finished: follow the OAuth redirect so
                                    // the originating client callback server receives the
                                    // code. Without this the external client hangs forever.
                                    var container = document.getElementById("step-container");
                                    while (container.firstChild) {{
                                        container.removeChild(container.firstChild);
                                    }}
                                    var done = document.createElement("div");
                                    done.className = "status-box success";
                                    done.style.display = "block";
                                    done.setAttribute("role", "alert");
                                    done.setAttribute("aria-live", "polite");
                                    done.setAttribute("aria-atomic", "true");
                                    done.textContent = "Setup complete! Redirecting...";
                                    container.appendChild(done);
                                    window.location.replace(data.redirect_url);
                                }} else {{
                                    // Completed.
                                    var container = document.getElementById("step-container");
                                    while (container.firstChild) {{
                                        container.removeChild(container.firstChild);
                                    }}
                                    var done = document.createElement("div");
                                    done.className = "status-box success";
                                    done.style.display = "block";
                                    done.setAttribute("role", "alert");
                                    done.setAttribute("aria-live", "polite");
                                    done.setAttribute("aria-atomic", "true");
                                    done.textContent = "Setup complete! You can close this tab.";
                                    container.appendChild(done);
                                }}
                            }} else {{
                                // Error: show message, re-enable input + button for retry, keep value.
                                errorEl.textContent = data.error || data.error_description || "Verification failed.";
                                errorEl.style.display = "block";
                                inputEl.disabled = false;
                                inputEl.setAttribute("aria-invalid", "true");
                                inputEl.setAttribute("aria-errormessage", "step-error");
                                buttonEl.disabled = false;
                                buttonEl.textContent = "Verify";
                                buttonEl.removeAttribute("aria-busy");
                                inputEl.focus();
                            }}
                        }});
                    }})
                    .catch(function (err) {{
                        errorEl.textContent = "Network error: " + err.message;
                        errorEl.style.display = "block";
                        inputEl.disabled = false;
                        inputEl.setAttribute("aria-invalid", "true");
                        inputEl.setAttribute("aria-errormessage", "step-error");
                        buttonEl.disabled = false;
                        buttonEl.textContent = "Verify";
                        buttonEl.removeAttribute("aria-busy");
                        inputEl.focus();
                    }});
            }}

            form.addEventListener("input", function (event) {{
                if (event.target.classList.contains("field-input")) {{
                    event.target.removeAttribute("aria-invalid");
                    event.target.removeAttribute("aria-errormessage");
                    statusBox.style.display = "none";
                }}
            }});

            form.addEventListener("submit", function (event) {{
                event.preventDefault();

                var inputs = form.querySelectorAll(".field-input");
                var payload = {{}};
                var valid = true;
                var firstInvalid = null;

                inputs.forEach(function (input) {{
                    if (input.hasAttribute("required") && input.value.trim() === "") {{
                        valid = false;
                        input.setAttribute("aria-invalid", "true");
                        input.setAttribute("aria-errormessage", "status-box");
                        if (!firstInvalid) {{
                            firstInvalid = input;
                        }}
                    }} else {{
                        input.removeAttribute("aria-invalid");
                        input.removeAttribute("aria-errormessage");
                        payload[input.name] = input.value;
                    }}
                }});

                if (!valid) {{
                    showStatus("error", "Please fill in all required fields.");
                    if (firstInvalid) {{
                        firstInvalid.focus();
                    }}
                    return;
                }}

                submitBtn.disabled = true;
                submitBtn.textContent = "Connecting...";
                submitBtn.setAttribute("aria-busy", "true");
                statusBox.style.display = "none";

                fetch(submitUrl, {{
                    method: "POST",
                    headers: {{ "Content-Type": "application/json" }},
                    body: JSON.stringify(payload),
                }})
                    .then(function (response) {{
                        return response.json().then(function (data) {{
                            if (data.ok) {{
                                form.querySelectorAll(".field-input").forEach(function (i) {{
                                    i.disabled = true;
                                }});
                                submitBtn.disabled = true;
                                submitBtn.textContent = "Connected";
                                submitBtn.removeAttribute("aria-busy");
                                var pendingRedirectUrl = (typeof data.redirect_url === "string" && data.redirect_url.length > 0) ? data.redirect_url : null;
                                if (data.next_step && data.next_step.type === "oauth_device_code") {{
                                    var ns = data.next_step;
                                    statusBox.textContent = "";
                                    var title = document.createElement("strong");
                                    title.textContent = "API keys saved!";
                                    statusBox.appendChild(title);
                                    statusBox.appendChild(document.createElement("br"));
                                    statusBox.appendChild(document.createElement("br"));
                                    var label = document.createTextNode("Authorize Google Drive sync:");
                                    statusBox.appendChild(label);
                                    statusBox.appendChild(document.createElement("br"));
                                    var link = document.createElement("a");
                                    link.href = ns.verification_url;
                                    link.target = "_blank";
                                    link.rel = "noopener";
                                    link.textContent = ns.verification_url;
                                    statusBox.appendChild(link);
                                    statusBox.appendChild(document.createElement("br"));
                                    statusBox.appendChild(document.createElement("br"));
                                    var codeLabel = document.createTextNode("Enter code: ");
                                    statusBox.appendChild(codeLabel);
                                    var codeEl = document.createElement("strong");
                                    codeEl.style.cssText = "font-size:1.2em;letter-spacing:0.1em;user-select:all;cursor:copy";
                                    codeEl.title = "Click to select";
                                    codeEl.textContent = ns.user_code;
                                    statusBox.appendChild(codeEl);
                                    statusBox.appendChild(document.createElement("br"));
                                    statusBox.appendChild(document.createElement("br"));
                                    var waiting = document.createElement("span");
                                    waiting.id = "gdrive-waiting";
                                    waiting.style.color = "#9ca3af";
                                    waiting.setAttribute("role", "alert");
                                    waiting.setAttribute("aria-live", "polite");
                                    waiting.setAttribute("aria-atomic", "true");
                                    waiting.textContent = "Waiting for authorization...";
                                    statusBox.appendChild(waiting);
                                    statusBox.className = "status-box info";
                                    statusBox.style.display = "block";
                                    // Poll /setup-status until GDrive auth completes or fails.
                                    // Success:   gdrive === "complete"
                                    // Failure:   gdrive starts with "error:" -- show red message + stop polling.
                                    var pollInterval = setInterval(function () {{
                                        fetch(submitUrl.replace(/\\/authorize.*/, "/setup-status"))
                                            .then(function (r) {{ return r.json(); }})
                                            .then(function (s) {{
                                                if (s.gdrive === "complete") {{
                                                    clearInterval(pollInterval);
                                                    if (pendingRedirectUrl) {{
                                                        window.location.replace(pendingRedirectUrl);
                                                        return;
                                                    }}
                                                    var w = document.getElementById("gdrive-waiting");
                                                    if (w) {{
                                                        w.style.color = "#34c759";
                                                        w.textContent = "Google Drive authorized! Setup complete. You can close this tab.";
                                                    }}
                                                }} else if (typeof s.gdrive === "string" && s.gdrive.indexOf("error:") === 0) {{
                                                    clearInterval(pollInterval);
                                                    var w = document.getElementById("gdrive-waiting");
                                                    if (w) {{
                                                        w.style.color = "#ff453a";
                                                        w.textContent = "Google Drive authorization failed: " + s.gdrive.slice(6) + ". Please retry setup.";
                                                    }}
                                                }}
                                            }})
                                            .catch(function () {{}});
                                    }}, 3000);
                                }} else if (data.next_step && (data.next_step.type === "otp_required" || data.next_step.type === "password_required")) {{
                                    // Multi-step auth: hide form, show step input UI.
                                    statusBox.style.display = "none";
                                    showStepInput(data.next_step);
                                }} else if (data.next_step && data.next_step.type === "info") {{
                                    showStatus("success", data.next_step.message || "Setup saved. Additional steps may be required.");
                                }} else if (typeof data.redirect_url === "string" && data.redirect_url.length > 0) {{
                                    // OAuth authorization-code flow: server returned the
                                    // client's redirect_uri with ?code=...&state=... appended.
                                    // The browser MUST navigate there so the client callback
                                    // server (external tool, test harness, desktop app) can
                                    // exchange the code for a JWT. Without this the handshake
                                    // hangs forever and the form silently reports success
                                    // while the client waits on a callback that never fires.
                                    showStatus("success", "Credentials saved. Redirecting...");
                                    window.location.replace(data.redirect_url);
                                }} else {{
                                    var successMsg = data.message || "Connected successfully. You can close this window.";
                                    showStatus("success", successMsg);
                                }}
                            }} else {{
                                showStatus("error", data.error || data.error_description || "Request failed.");
                                submitBtn.disabled = false;
                                submitBtn.textContent = "Connect";
                                submitBtn.removeAttribute("aria-busy");
                            }}
                        }});
                    }})
                    .catch(function (err) {{
                        showStatus("error", "Network error: " + err.message);
                        submitBtn.disabled = false;
                        submitBtn.textContent = "Connect";
                        submitBtn.removeAttribute("aria-busy");
                    }});
            }});
        }})();
    </script>"""

    # Append the model-chain widget script (chips/dropdown/drag + derive-keys).
    # Injected as a <script> text node, so the provider map is plain
    # ``json.dumps`` (NOT HTML-escaped): the values are fixed identifiers with no
    # ``<``/``>``/quotes, and HTML-escaping the double quotes would break the
    # single-quoted ``JSON.parse('...')`` literal.
    from mcp_core.llm.providers import PROVIDER_KEY_ENV

    provider_map_json = json.dumps(PROVIDER_KEY_ENV)
    model_chain_script = _MODEL_CHAIN_SCRIPT.replace("__PROVIDER_KEY_JSON__", provider_map_json)

    return render_form_shell(title, body_html + model_chain_script)


def is_schema_complete(config: dict[str, Any] | None, schema: dict[str, Any]) -> bool:
    """Return True if every required field in ``schema`` has a non-empty value in ``config``.

    Schemas whose fields are all ``required: false`` are considered complete only
    when ``config["_setup_complete"]`` is True — explicit user submission via the
    relay form. This lets servers like wet-mcp (where every cloud key is optional
    individually but at least one configuration step is required) distinguish
    "user has submitted the form, leaving everything blank by choice" from
    "user has never seen the form".
    """
    if not config:
        return False

    required_fields = [f["key"] for f in schema.get("fields", []) if f.get("required")]

    if required_fields:
        return all(config.get(key) for key in required_fields)

    flag = config.get("_setup_complete")
    return flag is True or flag == "true"


def is_secret_field(field: dict) -> bool:
    """Return True if field stores a credential that must not be re-rendered to HTML."""
    return bool(field.get("secret", False))


def is_oauth_field(field: dict) -> bool:
    """Return True if field represents an OAuth-managed credential.

    OAuth fields render as "Re-authorize" buttons, not raw input boxes.
    Examples: refresh_token, access_token, id_token.
    """
    return bool(field.get("oauth_field", False))
