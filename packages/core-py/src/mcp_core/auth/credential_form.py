"""Credential form HTML renderer.

Renders a dark-themed HTML form from a RelayConfigSchema dict.
Used as the OAuth authorization page presented to the user during relay config.
"""

import html
from typing import Any


def _escape(value: Any) -> str:
    """Escape a value for safe HTML insertion."""
    return html.escape(str(value), quote=True)


def _render_field(field: dict[str, Any]) -> str:
    """Render a single ConfigField as an HTML input block."""
    key = _escape(field.get("key", ""))
    label = _escape(field.get("label", ""))
    field_type = _escape(field.get("type", "text"))
    placeholder = _escape(field.get("placeholder", ""))
    help_text = _escape(field.get("helpText", ""))
    help_url = _escape(field.get("helpUrl", ""))
    required = field.get("required", False)

    required_attr = " required" if required else ""
    required_badge = (
        '<span class="required-badge">Required</span>' if required else '<span class="optional-badge">Optional</span>'
    )

    help_html = ""
    aria_describedby = ""
    if help_text:
        aria_describedby = f' aria-describedby="help-{key}"'
        if help_url:
            help_html = f'<p class="help-text" id="help-{key}"><a href="{help_url}" target="_blank" rel="noopener noreferrer">{help_text}</a></p>'
        else:
            help_html = f'<p class="help-text" id="help-{key}">{help_text}</p>'

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
                spellcheck="false"{required_attr}{aria_describedby}
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


def _generate_js(submit_url_escaped: str, *, dynamic_flow: bool = True, device_code_poll: bool = True) -> str:
    """Generate the JavaScript for the credential form.

    Args:
        submit_url_escaped: The HTML-escaped URL to submit the form to.
        dynamic_flow: Whether to include multi-step auth (OTP/password) support.
        device_code_poll: Whether to include OAuth device code polling support.

    Returns:
        A string containing the JavaScript code.
    """
    # otp_logic contains functions for handling multi-step flows (OTP/password required).
    otp_logic = ""
    if dynamic_flow:
        otp_logic = r"""
            // Derive /otp endpoint URL from submitUrl (replaces /authorize... with /otp).
            function otpUrl() {
                return submitUrl.replace(/\/authorize.*/, "/otp");
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
                inputEl.disabled = true;

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
                                buttonEl.disabled = false;
                                buttonEl.textContent = "Verify";
                                inputEl.focus();
                            }
                        });
                    })
                    .catch(function (err) {
                        errorEl.textContent = "Network error: " + err.message;
                        errorEl.style.display = "block";
                        inputEl.disabled = false;
                        buttonEl.disabled = false;
                        buttonEl.textContent = "Verify";
                    });
            }"""

    device_code_logic = ""
    if device_code_poll:
        device_code_logic = r"""else if (data.next_step && data.next_step.type === "oauth_device_code") {
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
                                    waiting.style.color = "#888";
                                    waiting.textContent = "Waiting for authorization...";
                                    statusBox.appendChild(waiting);
                                    statusBox.className = "status-box info";
                                    statusBox.style.display = "block";
                                    // Poll /setup-status until GDrive auth completes
                                    var pollInterval = setInterval(function () {
                                        fetch(submitUrl.replace(/\/authorize.*/, "/setup-status"))
                                            .then(function (r) { return r.json(); })
                                            .then(function (s) {
                                                if (s.gdrive === "complete") {
                                                    clearInterval(pollInterval);
                                                    var w = document.getElementById("gdrive-waiting");
                                                    if (w) {
                                                        w.style.color = "#34c759";
                                                        w.textContent = "Google Drive authorized! Setup complete. You can close this tab.";
                                                    }
                                                }
                                            })
                                            .catch(function () {});
                                    }, 3000);
                                }"""

    dynamic_flow_logic = ""
    if dynamic_flow:
        dynamic_flow_logic = """else if (data.next_step && (data.next_step.type === "otp_required" || data.next_step.type === "password_required")) {
                                    // Multi-step auth: hide form, show step input UI.
                                    statusBox.style.display = "none";
                                    showStepInput(data.next_step);
                                }"""

    return f"""
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
{otp_logic}

            form.addEventListener("submit", function (event) {{
                event.preventDefault();

                var inputs = form.querySelectorAll(".field-input");
                var payload = {{}};
                var valid = true;

                inputs.forEach(function (input) {{
                    if (input.hasAttribute("required") && input.value.trim() === "") {{
                        valid = false;
                        input.style.borderColor = "#f87171";
                        input.setAttribute("aria-invalid", "true");
                    }} else {{
                        input.style.borderColor = "";
                        input.removeAttribute("aria-invalid");
                        payload[input.name] = input.value;
                    }}
                }});

                if (!valid) {{
                    showStatus("error", "Please fill in all required fields.");
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
                                if (false) {{
                                    // Placeholder for conditional branches
                                }} {device_code_logic} {dynamic_flow_logic} else if (data.next_step && data.next_step.type === "info") {{
                                    showStatus("success", data.next_step.message || "Setup saved. Additional steps may be required.");
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
        }})();"""


def render_credential_form(
    schema: dict[str, Any],
    *,
    submit_url: str,
    page_title: str | None = None,
    dynamic_flow: bool = True,
    device_code_poll: bool = True,
) -> str:
    """Render a dark-themed HTML credential form from a RelayConfigSchema dict.

    Args:
        schema: RelayConfigSchema dict with server metadata and field definitions.
        submit_url: URL the form POSTs to as JSON via fetch().
        page_title: Optional browser tab title. Defaults to displayName.
        dynamic_flow: Whether to include multi-step auth (OTP/password) support in JS.
        device_code_poll: Whether to include OAuth device code polling support in JS.

    Returns:
        Complete HTML document string, XSS-safe with all dynamic content escaped.
    """
    display_name = _escape(schema.get("displayName", schema.get("server", "Configuration")))
    server = _escape(schema.get("server", ""))
    description = _escape(schema.get("description", ""))
    title = _escape(page_title) if page_title is not None else display_name
    submit_url_escaped = _escape(submit_url)

    fields: list[dict[str, Any]] = schema.get("fields", [])
    capability_info: list[dict[str, Any]] = schema.get("capabilityInfo", [])

    fields_html = "".join(_render_field(f) for f in fields)

    capabilities_html = ""
    if capability_info:
        items_html = "".join(_render_capability(c) for c in capability_info)
        capabilities_html = f"""
        <section class="capabilities-section">
            <h2 class="capabilities-title">Capabilities Requested</h2>
            <ul class="capabilities-list">{items_html}
            </ul>
        </section>"""

    description_html = f'<p class="server-description">{description}</p>' if description else ""

    js_code = _generate_js(submit_url_escaped, dynamic_flow=dynamic_flow, device_code_poll=device_code_poll)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{title}</title>
    <style>
        *, *::before, *::after {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
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
        }}

        .container {{
            width: 100%;
            max-width: 480px;
        }}

        .card {{
            background-color: #1a1a1a;
            border: 1px solid #333;
            border-radius: 12px;
            padding: 2.5rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
        }}

        .header {{
            text-align: center;
            margin-bottom: 2.5rem;
        }}

        .server-name {{
            font-size: 1.5rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 0.5rem;
        }}

        .server-id {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 0.85rem;
            color: #888;
            background-color: #222;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            display: inline-block;
        }}

        .server-description {{
            margin-top: 1.25rem;
            color: #aaa;
            font-size: 0.95rem;
        }}

        .form-title {{
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: #fff;
        }}

        .field-group {{
            margin-bottom: 1.5rem;
        }}

        .field-label {{
            display: block;
            font-size: 0.9rem;
            font-weight: 500;
            margin-bottom: 0.5rem;
            color: #ddd;
        }}

        .required-badge {{
            font-size: 0.75rem;
            color: #f87171;
            margin-left: 0.5rem;
            opacity: 0.9;
        }}

        .optional-badge {{
            font-size: 0.75rem;
            color: #666;
            margin-left: 0.5rem;
        }}

        .field-input {{
            width: 100%;
            background-color: #262626;
            border: 1px solid #444;
            border-radius: 6px;
            padding: 0.75rem 1rem;
            color: #fff;
            font-size: 1rem;
            transition: border-color 0.2s, box-shadow 0.2s;
        }}

        .field-input:focus {{
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
        }}

        .field-input::placeholder {{
            color: #666;
        }}

        .help-text {{
            font-size: 0.8rem;
            color: #888;
            margin-top: 0.4rem;
        }}

        .help-text a {{
            color: #60a5fa;
            text-decoration: none;
        }}

        .help-text a:hover {{
            text-decoration: underline;
        }}

        .submit-btn {{
            width: 100%;
            background-color: #2563eb;
            color: #fff;
            border: none;
            border-radius: 6px;
            padding: 0.85rem;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s;
            margin-top: 1rem;
        }}

        .submit-btn:hover:not(:disabled) {{
            background-color: #1d4ed8;
        }}

        .submit-btn:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}

        .status-box {{
            margin-top: 1.5rem;
            padding: 1rem;
            border-radius: 6px;
            font-size: 0.9rem;
            display: none;
        }}

        .status-box.error {{
            background-color: rgba(239, 68, 68, 0.1);
            border: 1px solid #ef4444;
            color: #f87171;
        }}

        .status-box.success {{
            background-color: rgba(34, 197, 94, 0.1);
            border: 1px solid #22c55e;
            color: #4ade80;
        }}

        .status-box.info {{
            background-color: rgba(59, 130, 246, 0.1);
            border: 1px solid #3b82f6;
            color: #93c5fd;
        }}

        .capabilities-section {{
            margin-top: 2rem;
            border-top: 1px solid #333;
            padding-top: 2rem;
        }}

        .capabilities-title {{
            font-size: 1rem;
            font-weight: 600;
            color: #fff;
            margin-bottom: 1.25rem;
        }}

        .capabilities-list {{
            list-style: none;
        }}

        .capability-item {{
            margin-bottom: 1.25rem;
        }}

        .capability-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 0.25rem;
        }}

        .capability-label {{
            font-weight: 500;
            color: #eee;
        }}

        .capability-priority {{
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 0.1rem 0.4rem;
            border-radius: 4px;
            font-weight: 700;
        }}

        .priority-high {{ background-color: #7c2d12; color: #fdba74; }}
        .priority-medium {{ background-color: #78350f; color: #fcd34d; }}
        .priority-low {{ background-color: #14532d; color: #86efac; }}

        .capability-desc {{
            font-size: 0.85rem;
            color: #888;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <h1 class="server-name">{display_name}</h1>
                <div class="server-id">{server}</div>
                {description_html}
            </div>

            <p class="form-title">Enter your credentials</p>

            <form id="credential-form" novalidate>
                {fields_html}

                <button type="submit" class="submit-btn" id="submit-btn">
                    Connect
                </button>

                <div class="status-box" id="status-box" role="alert"></div>
            </form>
        </div>
        {capabilities_html}
    </div>

    <script>
{js_code}
    </script>
</body>
</html>"""
