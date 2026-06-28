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

        .model-chain { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; position: relative; padding: 8px; border: 1px solid #2a2a3a; border-radius: 8px; background: #14141f; }
        .mc-chips { display: flex; flex-wrap: wrap; gap: 6px; width: 100%; }
        .mc-chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 8px; background: #23233a; border: 1px solid #34344a; border-radius: 6px; font-size: 13px; cursor: grab; }
        .mc-chip.dragging { opacity: 0.4; }
        .mc-chip .mc-order { color: #8a8aa5; font-variant-numeric: tabular-nums; }
        .mc-chip button { background: none; border: none; color: #b56; cursor: pointer; font-size: 14px; line-height: 1; padding: 0; }
        .mc-typeahead { flex: 1; min-width: 140px; background: transparent; border: none; color: inherit; outline: none; font-size: 14px; padding: 4px; }
        .mc-dropdown { position: absolute; top: 100%; left: 0; right: 0; z-index: 10; background: #1b1b2a; border: 1px solid #2a2a3a; border-radius: 8px; margin-top: 4px; max-height: 220px; overflow-y: auto; }
        .mc-dropdown label { display: flex; align-items: center; gap: 8px; padding: 6px 10px; cursor: pointer; font-size: 13px; }
        .mc-dropdown label:hover { background: #23233a; }
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
"""


def render_form_shell(title: str, body_html: str) -> str:
    """Wrap ``body_html`` in the shared dark-theme HTML shell.

    The shell provides ``<!DOCTYPE html>``, ``<head>`` (charset, viewport,
    escaped ``<title>``, embedded ``_FORM_SHELL_CSS``) and a ``<body>`` whose
    only child is ``body_html``. ``body_html`` is inserted verbatim, so
    callers MUST pre-escape any untrusted values they interpolate.

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


def _normalize_litellm_id(model: str, provider: str) -> str:
    """Prefix a bare curated-provider model id so prefix-inference derives the
    correct key; leave already-prefixed and non-curated ids untouched."""
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
                _add(_normalize_litellm_id(str(m["model"]), str(m.get("provider", ""))))
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
                spellcheck="false"{value_attr}{required_attr}{aria_describedby}
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


def render_credential_form(
    schema: dict[str, Any],
    *,
    submit_url: str,
    page_title: str | None = None,
    prefill: dict[str, str] | None = None,
    include_username_field: bool = False,
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

    Returns:
        Complete HTML document string, XSS-safe with all dynamic content escaped.
    """
    display_name = _escape(schema.get("displayName", schema.get("server", "Configuration")))
    server = _escape(schema.get("server", ""))
    description = _escape(schema.get("description", ""))
    title = page_title if page_title is not None else schema.get("displayName", schema.get("server", "Configuration"))
    submit_url_escaped = _escape(submit_url)

    fields: list[dict[str, Any]] = schema.get("fields", [])
    capability_info: list[dict[str, Any]] = schema.get("capabilityInfo", [])

    prefill = prefill or {}
    fields_html = "".join(_render_field(f, prefill.get(f.get("key", ""), "")) for f in fields)

    # Optional workspace-username field (opt-in via include_username_field). It has
    # the .field-input class so the form's field collector picks it up into the POST
    # JSON as __sub_username; the local OAuth AS pops it and derives a STABLE sub.
    username_html = ""
    if include_username_field:
        username_html = (
            '<div class="field-group">'
            '<label for="field-__sub_username" class="field-label">Workspace / username'
            ' <span class="optional-badge" aria-hidden="true">Optional</span></label>'
            '<input id="field-__sub_username" type="text" name="__sub_username"'
            ' class="field-input" placeholder="e.g. alice"'
            ' autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" />'
            '<p class="field-help">Leave blank for a one-off session. Set the same value on'
            " every device to keep your saved data (one shared bucket per username).</p>"
            "</div>"
        )

    capabilities_html = ""
    if capability_info:
        items_html = "".join(_render_capability(c) for c in capability_info)
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

                <div class="status-box" id="status-box" role="alert"></div>
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
                                    done.setAttribute("role", "alert");
                                    done.className = "status-box success";
                                    done.style.display = "block";
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
                                    done.setAttribute("role", "alert");
                                    done.className = "status-box success";
                                    done.style.display = "block";
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
                                    codeEl.style.cssText = "font-size:1.2em;letter-spacing:0.1em";
                                    codeEl.textContent = ns.user_code;
                                    statusBox.appendChild(codeEl);
                                    statusBox.appendChild(document.createElement("br"));
                                    statusBox.appendChild(document.createElement("br"));
                                    var waiting = document.createElement("span");
                                    waiting.id = "gdrive-waiting";
                                    waiting.style.color = "#9ca3af";
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
