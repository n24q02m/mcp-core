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
}

export interface CapabilityInfo {
  label: string
  priority?: string
  description?: string
}

export interface RelayConfigSchema {
  server: string
  displayName?: string
  description?: string
  fields: ConfigField[]
  capabilityInfo?: CapabilityInfo[]
}

export interface RenderOptions {
  submitUrl: string
  pageTitle?: string
}

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function renderField(field: ConfigField): string {
  const key = escapeHtml(field.key ?? '')
  const label = escapeHtml(field.label ?? '')
  const fieldType = escapeHtml(field.type ?? 'text')
  const placeholder = escapeHtml(field.placeholder ?? '')
  const helpText = escapeHtml(field.helpText ?? '')
  const helpUrl = escapeHtml(field.helpUrl ?? '')
  const required = Boolean(field.required)

  const requiredAttr = required ? ' required' : ''
  const requiredBadge = required
    ? '<span class="required-badge">Required</span>'
    : '<span class="optional-badge">Optional</span>'

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
                spellcheck="false"${requiredAttr}${ariaDescribedby}
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

/**
 * Render a dark-themed HTML credential form from a RelayConfigSchema.
 *
 * @param schema RelayConfigSchema with server metadata and field definitions.
 * @param options.submitUrl URL the form POSTs to as JSON via fetch().
 * @param options.pageTitle Optional browser tab title. Defaults to displayName.
 * @returns Complete HTML document string, XSS-safe with all dynamic content escaped.
 */
export function renderCredentialForm(schema: RelayConfigSchema, options: RenderOptions): string {
  const displayName = escapeHtml(schema.displayName ?? schema.server ?? 'Configuration')
  const server = escapeHtml(schema.server ?? '')
  const description = escapeHtml(schema.description ?? '')
  const title = options.pageTitle !== undefined ? escapeHtml(options.pageTitle) : displayName
  const submitUrlEscaped = escapeHtml(options.submitUrl)

  const fields = schema.fields ?? []
  const capabilityInfo = schema.capabilityInfo ?? []

  const fieldsHtml = fields.map(renderField).join('')

  let capabilitiesHtml = ''
  if (capabilityInfo.length > 0) {
    const itemsHtml = capabilityInfo.map(renderCapability).join('')
    capabilitiesHtml = `
        <section class="capabilities-section">
            <h2 class="capabilities-title">Capabilities Requested</h2>
            <ul class="capabilities-list">${itemsHtml}
            </ul>
        </section>`
  }

  const descriptionHtml = description ? `<p class="server-description">${description}</p>` : ''

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${title}</title>
    <style>
        *, *::before, *::after {
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
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="server-header">
                <h1 class="server-name">${displayName}</h1>
                <div class="server-id">${server}</div>
                ${descriptionHtml}
            </div>

            <p class="form-title">Enter your credentials</p>

            <form id="credential-form" novalidate>
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

                    promptEl = document.createElement("p");
                    promptEl.id = "step-prompt";
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
                    inputEl.setAttribute("aria-labelledby", "step-prompt");
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
                if (value.trim() === "") {
                    errorEl.textContent = "Please enter a value.";
                    errorEl.style.display = "block";
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
                                    done.textContent = "Setup complete! You can close this tab.";
                                    container.appendChild(done);
                                }
                            } else {
                                // Error: show message, re-enable input + button for retry, keep value.
                                errorEl.textContent = data.error || data.error_description || "Verification failed.";
                                errorEl.style.display = "block";
                                inputEl.disabled = false;
                                inputEl.setAttribute("aria-invalid", "true");
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
                        buttonEl.disabled = false;
                        buttonEl.textContent = "Verify";
                        buttonEl.removeAttribute("aria-busy");
                    });
            }

            form.addEventListener("input", function (event) {
                if (event.target.classList.contains("field-input")) {
                    event.target.removeAttribute("aria-invalid");
                    statusBox.style.display = "none";
                }
            });

            form.addEventListener("submit", function (event) {
                event.preventDefault();

                var inputs = form.querySelectorAll(".field-input");
                var payload = {};
                var valid = true;

                inputs.forEach(function (input) {
                    if (input.hasAttribute("required") && input.value.trim() === "") {
                        valid = false;
                        input.setAttribute("aria-invalid", "true");
                    } else {
                        input.removeAttribute("aria-invalid");
                        payload[input.name] = input.value;
                    }
                });

                if (!valid) {
                    showStatus("error", "Please fill in all required fields.");
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
                                    link.style.cssText = "color:#60a5fa;font-weight:bold";
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
    </script>
</body>
</html>`
}
