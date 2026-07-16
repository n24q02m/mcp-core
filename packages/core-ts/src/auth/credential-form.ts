/**
 * Credential form HTML renderer.
 *
 * Renders a dark-themed HTML form from a RelayConfigSchema.
 * Used as the OAuth authorization page presented to the user during relay config.
 *
 * This is a TypeScript port of core-py's `credential_form.py`. CSS and embedded JS
 * are kept verbatim so the rendered form has visual + behavioral parity between
 * Python and TS servers.
 */

export interface ConfigField {
  key: string
  label: string
  type: string
  placeholder?: string
  helpText?: string
  helpUrl?: string
  required?: boolean
  /** Regex string for client-side validation; rendered as the input's `pattern` attribute. */
  validation?: string
}

/**
 * Return true iff every required field in `schema` has a non-empty value in
 * `config`. For schemas whose fields are all optional, requires the explicit
 * `_setup_complete: "true"` flag — see core-py `is_schema_complete` docstring.
 *
 * Strict equality on the flag: only the literal string `"true"` counts. This
 * guards against legacy / partial bootstrap entries (e.g. peer-shared cloud
 * keys) tricking the auto-open gate into thinking the user has configured.
 */
export function isSchemaComplete(
  config: Record<string, string> | null | undefined,
  schema: RelayConfigSchema
): boolean {
  if (!config) return false

  const fields = schema.fields ?? []
  let hasRequired = false

  for (let i = 0; i < fields.length; i++) {
    const field = fields[i]
    if (field.required === true) {
      hasRequired = true
      if (!config[field.key]) {
        return false
      }
    }
  }

  if (hasRequired) {
    return true
  }

  return config._setup_complete === 'true'
}

export interface CapabilityInfo {
  label: string
  priority?: string
  description?: string
}

/**
 * A credential-form tab (schema-level `tabs` capability). Each tab is a
 * mutually-exclusive credential mode; only the active tab's fields submit.
 */
export interface TabGroup {
  id: string
  label: string
  fields: ConfigField[]
}

/**
 * A repeatable field group (schema-level `cardGroup` capability). Renders
 * Add/Remove cards, each cloning `fields`; submitted as a JSON array under
 * `key` (e.g. `{ accounts: [{...}, {...}] }`).
 */
export interface CardGroup {
  key: string
  fields: ConfigField[]
  itemLabel?: string
  heading?: string
  addButtonLabel?: string
  minItems?: number
  titleField?: string
}

export interface RelayConfigSchema {
  server: string
  displayName?: string
  description?: string
  fields?: ConfigField[]
  capabilityInfo?: CapabilityInfo[]
  /** Mutually-exclusive credential modes; see the tabbed render path. */
  tabs?: TabGroup[]
  /** One repeatable field group; see the card-group render path. */
  cardGroup?: CardGroup
}

export interface RenderOptions {
  submitUrl: string
  pageTitle?: string
  /**
   * Optional ``{KEY: VALUE}`` map populated by the OAuth AS from
   * ``?prefill_<KEY>=<VALUE>`` query params on GET /authorize. Each matching
   * field renders with an HTML-escaped ``value="..."`` attr so users only
   * type what skret cannot supply (OTP / 2FA / one-time codes). Non-matching
   * keys are ignored.
   */
  prefill?: Record<string, string>
  /**
   * For a `tabs` schema, the id of the tab to render active on load (defaults
   * to the first tab). Ignored for non-tabbed schemas.
   */
  initialTab?: string
  /**
   * Opt-in workspace-username field (multi-user stable-sub). Honoured by the
   * `tabs` and `cardGroup` render paths.
   */
  includeUsernameField?: boolean
}

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/**
 * Shared CSS for every relay/auth HTML page rendered by core-ts.
 *
 * Kept verbatim with `packages/core-py/src/mcp_core/auth/credential_form.py`'s
 * `_FORM_SHELL_CSS` constant so the credential form, the `/login` password
 * gate, and any future relay page have identical visual styling regardless of
 * which language renders them. Extending this string requires updating the
 * Python parity copy in the same commit.
 */
const FORM_SHELL_CSS = `        *, *::before, *::after {
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
`

/**
 * Wrap `bodyHtml` in the shared dark-theme HTML shell.
 *
 * The shell provides `<!DOCTYPE html>`, `<head>` (charset, viewport, escaped
 * `<title>`, embedded `FORM_SHELL_CSS`) and a `<body>` whose only child is
 * `bodyHtml`. `bodyHtml` is inserted verbatim, so callers MUST pre-escape any
 * untrusted values they interpolate.
 *
 * `title` is HTML-escaped before being placed in `<title>`.
 *
 * Used by `renderCredentialForm` (relay credential form) and by
 * `loginGetHandler` in `relay-login.ts` (the `/login` password gate) so both
 * pages share identical typography, palette, card layout, and input styling.
 * Parity with Python `render_form_shell` in
 * `packages/core-py/src/mcp_core/auth/credential_form.py`.
 */
export function renderFormShell(title: string, bodyHtml: string): string {
  const safeTitle = escapeHtml(title)
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${safeTitle}</title>
    <style>
${FORM_SHELL_CSS}    </style>
</head>
<body>
${bodyHtml}
</body>
</html>`
}

function renderField(field: ConfigField, value = ''): string {
  const key = escapeHtml(field.key ?? '')
  const label = escapeHtml(field.label ?? '')
  const fieldType = escapeHtml(field.type ?? 'text')
  const placeholder = escapeHtml(field.placeholder ?? '')
  const helpText = escapeHtml(field.helpText ?? '')
  const helpUrl = escapeHtml(field.helpUrl ?? '')
  const required = Boolean(field.required)

  const requiredAttr = required ? ' required' : ''
  const requiredBadge = required
    ? '<span class="required-badge" aria-hidden="true">Required</span>'
    : '<span class="optional-badge" aria-hidden="true">Optional</span>'

  const valueAttr = value ? ` value="${escapeHtml(value)}"` : ''
  const patternAttr = field.validation ? ` pattern="${escapeHtml(field.validation)}"` : ''

  let helpHtml = ''
  let ariaDescribedby = ''
  if (helpText) {
    ariaDescribedby = ` aria-describedby="help-${key}"`
    if (helpUrl) {
      helpHtml = `<p class="help-text" id="help-${key}"><a href="${helpUrl}" target="_blank" rel="noopener noreferrer">${helpText}</a></p>`
    } else {
      helpHtml = `<p class="help-text" id="help-${key}">${helpText}</p>`
    }
  }

  return `
        <div class="field-group">
            <label for="field-${key}" class="field-label">
                ${label}
                ${requiredBadge}
            </label>
            <input
                id="field-${key}"
                name="${key}"
                type="${fieldType}"
                placeholder="${placeholder}"
                class="field-input"
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck="false"${valueAttr}${patternAttr}${requiredAttr}${ariaDescribedby}
            />
            ${helpHtml}
        </div>`
}

function renderCapability(cap: CapabilityInfo): string {
  const label = escapeHtml(cap.label ?? '')
  const priority = escapeHtml(cap.priority ?? '')
  const description = escapeHtml(cap.description ?? '')

  const priorityClass = priority ? `priority-${priority}` : 'priority-medium'

  const descHtml = description ? `<p class="capability-desc">${description}</p>` : ''

  return `
            <li class="capability-item">
                <div class="capability-header">
                    <span class="capability-label">${label}</span>
                    <span class="capability-priority ${priorityClass}">${priority}</span>
                </div>
                ${descHtml}
            </li>`
}

// ===========================================================================
// Schema-level tabs + dynamic card group (W4.1)
// ---------------------------------------------------------------------------
// Two OPT-IN capabilities that let servers declare richer credential UIs
// through the schema alone (no forked renderer):
//   * `tabs`      -> mutually-exclusive credential modes (e.g. telegram
//                    bot-token vs phone/OTP), only the active tab submits.
//   * `cardGroup` -> a repeatable field group with Add/Remove (e.g. email
//                    multi-account), submitted as a JSON array.
// A schema that declares NEITHER key renders through the unchanged flat-field
// path in `renderCredentialForm` below, byte-for-byte identical to before.
// The feature CSS ships as a `<style>` block inside the body — only when the
// feature is used — so the shared `FORM_SHELL_CSS` (and the flat form) stay
// untouched. Kept in parity with core-py `credential_form.py`.
// ===========================================================================

// Tab CSS (scoped `.tabs`/`.tab`/`.tab-panel`); emitted in-body only for
// tabbed forms. Palette mirrors the shared shell so tabs blend into the card.
const TABS_CSS = `    <style>
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
`

// Card-group CSS (scoped `.card-group-*`); emitted in-body only for card
// forms. `.card-group-item` avoids the shell's `.card` name deliberately.
const CARD_GROUP_CSS = `    <style>
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
`

// Multi-step (OTP / 2FA) step-input UI, shared by tab forms. Mirrors the flat
// form's `showStepInput`/`submitStep` semantics (same `/otp` POST, same
// redirect-follow on completion) so a tabbed server's phone->OTP->2FA chain
// behaves identically to the default form.
const STEP_UI_JS = `
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
                    errorEl.setAttribute("role", "alert"); errorEl.style.display = "none"; container.appendChild(errorEl);
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
                                done.setAttribute("role", "alert"); done.textContent = "Setup complete! Redirecting..."; c.appendChild(done);
                                window.location.replace(data.redirect_url);
                            } else {
                                var c2 = document.getElementById("step-container"); while (c2.firstChild) { c2.removeChild(c2.firstChild); }
                                var done2 = document.createElement("div"); done2.className = "status-box success"; done2.style.display = "block";
                                done2.setAttribute("role", "alert"); done2.textContent = "Setup complete! You can close this tab."; c2.appendChild(done2);
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
`

// Tab form behaviour: tab switching (click + ARIA-tablist arrow keys), then a
// submit that collects ONLY the active panel's fields. `__SUBMIT_URL__` and
// `__INITIAL_TAB__` are substituted at render time; `STEP_UI_JS` is spliced in
// for OTP/2FA support.
const TABS_SCRIPT = `    <script>
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
${STEP_UI_JS}
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
    </script>`

// Card-group behaviour: a JS builder that clones the declared fields per card,
// Add/Remove with focus management, and a submit that serialises every card into
// a JSON array under `__GROUP_KEY__`. All DOM is built with
// createElement/textContent/setAttribute (no innerHTML with user values).
const CARD_GROUP_SCRIPT = `    <script>
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
                codeEl.textContent = nextStep.user_code;
                statusBox.appendChild(codeEl);
                statusBox.appendChild(document.createElement("br"));
                statusBox.appendChild(document.createElement("br"));
                var waiting = document.createElement("span");
                waiting.id = "device-waiting";
                waiting.setAttribute("role", "alert");
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
                    var firstInvalid = form.querySelector(":invalid");
                    if (firstInvalid) {
                        firstInvalid.setAttribute("aria-invalid", "true");
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
    </script>`

/** Escape a string for safe embedding inside a double-quoted JS literal. */
function jsString(value: string): string {
  return value.replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('<', '\\u003c')
}

/**
 * Return the id of the tab that should render active on load. Defaults to the
 * first tab; a valid `initialTab` hint wins, an unknown hint falls back.
 */
function resolveActiveTab(tabs: TabGroup[], initialTab: string | undefined): string {
  const ids = tabs.map((t) => String(t.id ?? ''))
  if (initialTab !== undefined && ids.includes(initialTab)) {
    return initialTab
  }
  return ids.length > 0 ? ids[0] : ''
}

/**
 * Optional workspace-username field shared by the flat + feature forms. Carries
 * the `.field-input` class so the form collector picks it into the POST as
 * `__sub_username`. Optional, so it never blocks submit.
 */
function usernameFieldHtml(): string {
  return (
    '<div class="field-group">' +
    '<label for="field-__sub_username" class="field-label">Workspace / username' +
    ' <span class="optional-badge" aria-hidden="true">Optional</span></label>' +
    '<input id="field-__sub_username" type="text" name="__sub_username"' +
    ' class="field-input" placeholder="e.g. alice"' +
    ' autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" />' +
    '<p class="help-text">Leave blank for a one-off session. Set the same value on' +
    ' every device to keep your saved data (one shared bucket per username).</p>' +
    '</div>'
  )
}

function renderCapabilitiesSection(capabilityInfo: CapabilityInfo[]): string {
  if (capabilityInfo.length === 0) {
    return ''
  }
  const itemsHtml = capabilityInfo.map(renderCapability).join('')
  return `
        <section class="capabilities-section" aria-labelledby="capabilities-title">
            <h2 class="capabilities-title" id="capabilities-title">Capabilities Requested</h2>
            <ul class="capabilities-list">${itemsHtml}
            </ul>
        </section>`
}

/**
 * Render a credential form whose fields are split across mutually-exclusive
 * tabs. Only the active tab's fields are collected on submit. Multi-step
 * (OTP / 2FA) chaining works exactly as the flat form.
 */
function renderTabbedCredentialForm(schema: RelayConfigSchema, options: RenderOptions): string {
  const displayName = escapeHtml(schema.displayName ?? schema.server ?? 'Configuration')
  const server = escapeHtml(schema.server ?? '')
  const description = escapeHtml(schema.description ?? '')
  const title = options.pageTitle !== undefined ? escapeHtml(options.pageTitle) : displayName
  const submitUrlEscaped = escapeHtml(options.submitUrl)
  const prefill = options.prefill ?? {}

  const tabs = schema.tabs ?? []
  const activeId = resolveActiveTab(tabs, options.initialTab)

  const tabButtons: string[] = []
  const tabPanels: string[] = []
  for (const tab of tabs) {
    const tid = escapeHtml(tab.id ?? '')
    const label = escapeHtml(tab.label ?? '')
    const isActive = (tab.id ?? '') === activeId
    const activeCls = isActive ? ' active' : ''
    const ariaSelected = isActive ? 'true' : 'false'
    const tabindex = isActive ? '0' : '-1'
    tabButtons.push(
      `<button type="button" id="tab-${tid}" class="tab${activeCls}" data-tab="${tid}"` +
        ` role="tab" aria-selected="${ariaSelected}" tabindex="${tabindex}"` +
        ` aria-controls="panel-${tid}">${label}</button>`
    )
    const panelFields = (tab.fields ?? []).map((f) => renderField(f, prefill[f.key] ?? '')).join('')
    tabPanels.push(
      `<div id="panel-${tid}" class="tab-panel${activeCls}" data-panel="${tid}"` +
        ` role="tabpanel" aria-labelledby="tab-${tid}">${panelFields}\n                </div>`
    )
  }

  const tabsHtml = tabButtons.join('\n                ')
  const panelsHtml = tabPanels.join('\n                ')
  const usernameHtml = options.includeUsernameField ? usernameFieldHtml() : ''
  const capabilitiesHtml = renderCapabilitiesSection(schema.capabilityInfo ?? [])
  const descriptionHtml = description ? `<p class="server-description" id="server-desc">${description}</p>` : ''

  const script = TABS_SCRIPT.replaceAll('__SUBMIT_URL__', submitUrlEscaped).replaceAll('__INITIAL_TAB__', activeId)

  const bodyHtml = `${TABS_CSS}    <div class="container">
        <div class="card">
            <div class="server-header">
                <h1 class="server-name">${displayName}</h1>
                <div class="server-id">${server}</div>
                ${descriptionHtml}
            </div>

            <div class="tabs" role="tablist" aria-label="Credential mode">
                ${tabsHtml}
            </div>

            <form id="credential-form" novalidate>
                ${usernameHtml}${panelsHtml}

                <button type="submit" class="submit-btn" id="submit-btn">Connect</button>

                <div class="status-box" id="status-box" role="alert"></div>
            </form>
        </div>
        ${capabilitiesHtml}
    </div>
${script}`

  return renderFormShell(title, bodyHtml)
}

/**
 * Render a credential form built around one repeatable card group. The group's
 * fields are cloned per card (Add/Remove) and submitted as a JSON array under
 * the group `key`. An Outlook-style device-code follow-up is supported.
 */
function renderCardGroupCredentialForm(schema: RelayConfigSchema, options: RenderOptions): string {
  const displayName = escapeHtml(schema.displayName ?? schema.server ?? 'Configuration')
  const server = escapeHtml(schema.server ?? '')
  const description = escapeHtml(schema.description ?? '')
  const title = options.pageTitle !== undefined ? escapeHtml(options.pageTitle) : displayName
  const submitUrlEscaped = escapeHtml(options.submitUrl)

  const group = schema.cardGroup as CardGroup
  const groupKey = String(group.key ?? 'items')
  const itemLabel = String(group.itemLabel ?? 'Item')
  const addLabel = escapeHtml(group.addButtonLabel ?? '+ Add')
  const minItems = Number(group.minItems ?? 1)
  const titleField = String(group.titleField ?? '')
  const groupHeading = escapeHtml(group.heading ?? `${itemLabel}s`)
  const fields = group.fields ?? []

  // `<` is escaped to `<` so the JSON cannot terminate the <script> early.
  const fieldsJson = JSON.stringify(fields).replaceAll('<', '\\u003c')

  const usernameHtml = options.includeUsernameField ? usernameFieldHtml() : ''
  const capabilitiesHtml = renderCapabilitiesSection(schema.capabilityInfo ?? [])
  const descriptionHtml = description ? `<p class="server-description" id="server-desc">${description}</p>` : ''

  // `__CARD_FIELDS__` (the only placeholder carrying user-controlled JSON) is
  // substituted LAST so a crafted field value cannot masquerade as another token.
  const script = CARD_GROUP_SCRIPT.replaceAll('__SUBMIT_URL__', submitUrlEscaped)
    .replaceAll('__GROUP_KEY__', jsString(groupKey))
    .replaceAll('__TITLE_FIELD__', jsString(titleField))
    .replaceAll('__ITEM_LABEL__', jsString(itemLabel))
    .replaceAll('__MIN_ITEMS__', String(minItems))
    .replaceAll('__CARD_FIELDS__', fieldsJson)

  const bodyHtml = `${CARD_GROUP_CSS}    <div class="container">
        <div class="card">
            <div class="server-header">
                <h1 class="server-name">${displayName}</h1>
                <div class="server-id">${server}</div>
                ${descriptionHtml}
            </div>

            <h2 class="form-title" id="form-title">${groupHeading}</h2>

            <form id="credential-form" aria-labelledby="form-title" novalidate>
                <fieldset id="form-fieldset" style="border: none; padding: 0; margin: 0;">
                    ${usernameHtml}<div id="card-group-container"></div>

                    <button type="button" class="card-group-add" id="card-group-add">${addLabel}</button>

                    <button type="submit" class="submit-btn" id="submit-btn">Connect</button>
                </fieldset>

                <div class="status-box" id="status-box" role="alert"></div>
            </form>
        </div>
        ${capabilitiesHtml}
    </div>
${script}`

  return renderFormShell(title, bodyHtml)
}

/**
 * Render a dark-themed HTML credential form from a RelayConfigSchema.
 *
 * @param schema RelayConfigSchema with server metadata and field definitions.
 * @param options.submitUrl URL the form POSTs to as JSON via fetch().
 * @param options.pageTitle Optional browser tab title. Defaults to displayName.
 * @param options.prefill Optional ``{KEY: VALUE}`` map for input ``value=`` attrs.
 * @returns Complete HTML document string, XSS-safe with all dynamic content escaped.
 */
export function renderCredentialForm(schema: RelayConfigSchema, options: RenderOptions): string {
  // Schema-level capabilities (opt-in): dispatch to the dedicated renderer.
  // A schema declaring neither key falls through to the unchanged flat form.
  if (schema.tabs && schema.tabs.length > 0) {
    return renderTabbedCredentialForm(schema, options)
  }
  if (schema.cardGroup) {
    return renderCardGroupCredentialForm(schema, options)
  }

  const displayName = escapeHtml(schema.displayName ?? schema.server ?? 'Configuration')
  const server = escapeHtml(schema.server ?? '')
  const description = escapeHtml(schema.description ?? '')
  const title = options.pageTitle !== undefined ? escapeHtml(options.pageTitle) : displayName
  const submitUrlEscaped = escapeHtml(options.submitUrl)

  const fields = schema.fields ?? []
  const capabilityInfo = schema.capabilityInfo ?? []
  const prefill = options.prefill ?? {}

  const fieldsHtml = fields.map((f) => renderField(f, prefill[f.key] ?? '')).join('')

  let capabilitiesHtml = ''
  if (capabilityInfo.length > 0) {
    const itemsHtml = capabilityInfo.map(renderCapability).join('')
    capabilitiesHtml = `
        <section class="capabilities-section" aria-labelledby="capabilities-title">
            <h2 class="capabilities-title" id="capabilities-title">Capabilities Requested</h2>
            <ul class="capabilities-list">${itemsHtml}
            </ul>
        </section>`
  }

  const descriptionHtml = description ? `<p class="server-description" id="server-desc">${description}</p>` : ''
  const formAria = description ? ' aria-describedby="server-desc"' : ''

  // The body is wrapped in `renderFormShell` below. The shell injects the
  // `<head>` (with the shared `FORM_SHELL_CSS`) and the `<body>` opening +
  // closing tags, so this template starts at the first child of `<body>`.
  const bodyHtml = `    <div class="container">
        <div class="card">
            <div class="server-header">
                <h1 class="server-name">${displayName}</h1>
                <div class="server-id">${server}</div>
                ${descriptionHtml}
            </div>

            <p class="form-title" id="form-title">Enter your credentials</p>

            <form id="credential-form" aria-labelledby="form-title"${formAria} novalidate>
                ${fieldsHtml}

                <button type="submit" class="submit-btn" id="submit-btn">
                    Connect
                </button>

                <div class="status-box" id="status-box" role="alert"></div>
            </form>
        </div>
        ${capabilitiesHtml}
    </div>

    <script>
        (function () {
            var form = document.getElementById("credential-form");
            var submitBtn = document.getElementById("submit-btn");
            var statusBox = document.getElementById("status-box");
            var submitUrl = "${submitUrlEscaped}";

            function showStatus(type, message) {
                statusBox.className = "status-box " + type;
                statusBox.textContent = message;
                statusBox.style.display = "block";
            }

            // Derive /otp endpoint URL from submitUrl (replaces /authorize... with /otp).
            function otpUrl() {
                return submitUrl.replace(/\\/authorize.*/, "/otp");
            }

            // Render (or update in-place) a step-input UI for otp_required / password_required.
            // ns: next_step object with { text, field, input_type, placeholder }.
            // All textual content from ns is inserted via textContent (never innerHTML).
            function showStepInput(ns) {
                // Hide the original credential form after first transition.
                if (form && form.style.display !== "none") {
                    form.style.display = "none";
                }

                // If a step container already exists, update it in-place (chained next_step).
                var container = document.getElementById("step-container");
                var promptEl, inputEl, buttonEl, errorEl;
                if (container) {
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
                } else {
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
                    buttonEl.addEventListener("click", function () {
                        submitStep();
                    });
                    inputEl.addEventListener("keydown", function (evt) {
                        if (evt.key === "Enter") {
                            evt.preventDefault();
                            submitStep();
                        }
                    });
                    inputEl.addEventListener("input", function() {
                        inputEl.removeAttribute("aria-invalid");
                        inputEl.removeAttribute("aria-errormessage");
                        errorEl.style.display = "none";
                    });
                }

                // Populate prompt + input attributes via safe DOM APIs.
                promptEl.textContent = ns.text || "";
                inputEl.setAttribute("type", ns.input_type || "text");
                inputEl.setAttribute("placeholder", ns.placeholder || "");
                // Stash field name so submitStep can read it at click time.
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
                    errorEl.textContent = "Please enter a value.";
                    errorEl.style.display = "block";
                    inputEl.setAttribute("aria-invalid", "true");
                    inputEl.setAttribute("aria-errormessage", "step-error");
                    inputEl.focus();
                    return;
                }
                errorEl.style.display = "none";
                errorEl.textContent = "";
                buttonEl.disabled = true;
                buttonEl.textContent = "Verifying...";
                buttonEl.setAttribute("aria-busy", "true");
                inputEl.disabled = true;
                inputEl.removeAttribute("aria-invalid");

                var body = {};
                body[fieldName] = value;

                fetch(otpUrl(), {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(body),
                })
                    .then(function (response) {
                        return response.json().then(function (data) {
                            if (data.ok) {
                                if (data.next_step && (data.next_step.type === "otp_required" || data.next_step.type === "password_required")) {
                                    // Chain: update in place with new prompt/field/type.
                                    showStepInput(data.next_step);
                                } else if (typeof data.redirect_url === "string" && data.redirect_url.length > 0) {
                                    // Multi-step auth finished: follow the OAuth redirect so
                                    // the originating client callback server receives the
                                    // code. Without this the external client hangs forever.
                                    var container = document.getElementById("step-container");
                                    while (container.firstChild) {
                                        container.removeChild(container.firstChild);
                                    }
                                    var done = document.createElement("div");
                                    done.className = "status-box success";
                                    done.style.display = "block";
                                    done.setAttribute("role", "alert");
                                    done.textContent = "Setup complete! Redirecting...";
                                    container.appendChild(done);
                                    window.location.replace(data.redirect_url);
                                } else {
                                    // Completed.
                                    var container = document.getElementById("step-container");
                                    while (container.firstChild) {
                                        container.removeChild(container.firstChild);
                                    }
                                    var done = document.createElement("div");
                                    done.className = "status-box success";
                                    done.style.display = "block";
                                    done.setAttribute("role", "alert");
                                    done.textContent = "Setup complete! You can close this tab.";
                                    container.appendChild(done);
                                }
                            } else {
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
                            }
                        });
                    })
                    .catch(function (err) {
                        errorEl.textContent = "Network error: " + err.message;
                        errorEl.style.display = "block";
                        inputEl.disabled = false;
                        inputEl.setAttribute("aria-invalid", "true");
                        inputEl.setAttribute("aria-errormessage", "step-error");
                        buttonEl.disabled = false;
                        buttonEl.textContent = "Verify";
                        buttonEl.removeAttribute("aria-busy");
                        inputEl.focus();
                    });
            }

            form.addEventListener("input", function (event) {
                if (event.target.classList.contains("field-input")) {
                    event.target.removeAttribute("aria-invalid");
                    event.target.removeAttribute("aria-errormessage");
                    statusBox.style.display = "none";
                }
            });

            form.addEventListener("submit", function (event) {
                event.preventDefault();

                var inputs = form.querySelectorAll(".field-input");
                var payload = {};
                var valid = true;
                var firstInvalid = null;

                inputs.forEach(function (input) {
                    if (input.hasAttribute("required") && input.value.trim() === "") {
                        valid = false;
                        input.setAttribute("aria-invalid", "true");
                        input.setAttribute("aria-errormessage", "status-box");
                        if (!firstInvalid) {
                            firstInvalid = input;
                        }
                    } else {
                        input.removeAttribute("aria-invalid");
                        input.removeAttribute("aria-errormessage");
                        payload[input.name] = input.value;
                    }
                });

                if (!valid) {
                    showStatus("error", "Please fill in all required fields.");
                    if (firstInvalid) {
                        firstInvalid.focus();
                    }
                    return;
                }

                submitBtn.disabled = true;
                submitBtn.textContent = "Connecting...";
                submitBtn.setAttribute("aria-busy", "true");
                statusBox.style.display = "none";

                fetch(submitUrl, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload),
                })
                    .then(function (response) {
                        return response.json().then(function (data) {
                            if (data.ok) {
                                form.querySelectorAll(".field-input").forEach(function (i) {
                                    i.disabled = true;
                                });
                                submitBtn.disabled = true;
                                submitBtn.textContent = "Connected";
                                submitBtn.removeAttribute("aria-busy");
                                var pendingRedirectUrl = (typeof data.redirect_url === "string" && data.redirect_url.length > 0) ? data.redirect_url : null;
                                if (data.next_step && data.next_step.type === "oauth_device_code") {
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
                                    waiting.setAttribute("role", "alert");
                                    waiting.textContent = "Waiting for authorization...";
                                    statusBox.appendChild(waiting);
                                    statusBox.className = "status-box info";
                                    statusBox.style.display = "block";
                                    // Poll /setup-status until GDrive auth completes or fails.
                                    // Success:   gdrive === "complete"
                                    // Failure:   gdrive starts with "error:" -- show red message + stop polling.
                                    var pollInterval = setInterval(function () {
                                        fetch(submitUrl.replace(/\\/authorize.*/, "/setup-status"))
                                            .then(function (r) { return r.json(); })
                                            .then(function (s) {
                                                if (s.gdrive === "complete") {
                                                    clearInterval(pollInterval);
                                                    if (pendingRedirectUrl) {
                                                        window.location.replace(pendingRedirectUrl);
                                                        return;
                                                    }
                                                    var w = document.getElementById("gdrive-waiting");
                                                    if (w) {
                                                        w.style.color = "#34c759";
                                                        w.textContent = "Google Drive authorized! Setup complete. You can close this tab.";
                                                    }
                                                } else if (typeof s.gdrive === "string" && s.gdrive.indexOf("error:") === 0) {
                                                    clearInterval(pollInterval);
                                                    var w = document.getElementById("gdrive-waiting");
                                                    if (w) {
                                                        w.style.color = "#ff453a";
                                                        w.textContent = "Google Drive authorization failed: " + s.gdrive.slice(6) + ". Please retry setup.";
                                                    }
                                                }
                                            })
                                            .catch(function () {});
                                    }, 3000);
                                } else if (data.next_step && (data.next_step.type === "otp_required" || data.next_step.type === "password_required")) {
                                    // Multi-step auth: hide form, show step input UI.
                                    statusBox.style.display = "none";
                                    showStepInput(data.next_step);
                                } else if (data.next_step && data.next_step.type === "info") {
                                    showStatus("success", data.next_step.message || "Setup saved. Additional steps may be required.");
                                } else if (typeof data.redirect_url === "string" && data.redirect_url.length > 0) {
                                    // OAuth authorization-code flow: server returned the
                                    // client's redirect_uri with ?code=...&state=... appended.
                                    // The browser MUST navigate there so the client callback
                                    // server (external tool, test harness, desktop app) can
                                    // exchange the code for a JWT. Without this the handshake
                                    // hangs forever and the form silently reports success
                                    // while the client waits on a callback that never fires.
                                    showStatus("success", "Credentials saved. Redirecting...");
                                    window.location.replace(data.redirect_url);
                                } else {
                                    var successMsg = data.message || "Connected successfully. You can close this window.";
                                    showStatus("success", successMsg);
                                }
                            } else {
                                showStatus("error", data.error || data.error_description || "Request failed.");
                                submitBtn.disabled = false;
                                submitBtn.textContent = "Connect";
                                submitBtn.removeAttribute("aria-busy");
                            }
                        });
                    })
                    .catch(function (err) {
                        showStatus("error", "Network error: " + err.message);
                        submitBtn.disabled = false;
                        submitBtn.textContent = "Connect";
                        submitBtn.removeAttribute("aria-busy");
                    });
            });
        })();
    </script>`

  return renderFormShell(title, bodyHtml)
}

/**
 * Relay config field schema (D7).
 *
 * Each field supports:
 *   name (string, required): config.enc key
 *   label (string, required): UI label
 *   required (boolean, required): server gate
 *   secret (boolean, optional, default false): true = never re-render value to HTML
 *   oauthField (boolean, optional, default false): true = managed by OAuth flow,
 *     render as Re-authorize button instead of input
 *   type (string, optional, default "text"): UI input type
 *   description (string, optional): help text
 *   default (unknown, optional): default value if user submits empty
 *   pattern (string, optional): client-side regex validation
 *
 * Parity with core-py `RelayConfigField` (snake_case `oauth_field` -> camelCase
 * `oauthField` per TS convention).
 */
export interface RelayConfigField {
  name: string
  label: string
  required: boolean
  secret?: boolean
  oauthField?: boolean
  type?: 'text' | 'password' | 'url' | 'email'
  description?: string
  default?: unknown
  pattern?: string
}

/** Return true if field stores a credential that must not be re-rendered to HTML. */
export function isSecretField(field: RelayConfigField): boolean {
  return field.secret === true
}

/**
 * Return true if field represents an OAuth-managed credential.
 *
 * OAuth fields render as "Re-authorize" buttons, not raw input boxes.
 * Examples: refresh_token, access_token, id_token.
 */
export function isOAuthField(field: RelayConfigField): boolean {
  return field.oauthField === true
}
