## 2026-05-26 - Explicit Label Linking

**Learning:** When building custom HTML forms, using implicit labeling (e.g., `<label>Text <input></label>`) is valid but explicitly linking `<label>` and `<input>` elements with `for` and `id` attributes is recognized as an accessibility best practice. This provides more robust support across a wider range of assistive technologies.

**Action:** Always explicitly link `<label>` elements to their corresponding `<input>` elements using matching `for` and `id` attributes when generating custom HTML forms.
## 2026-06-21 - Accessible Landmarks
**Learning:** When using `<section>` elements for visual groupings (like Capabilities Requested), they need an accessible name (via `aria-labelledby`) to be exposed as proper region landmarks to screen readers.
**Action:** Always pair `<section>` elements with `aria-labelledby` pointing to their heading's ID.
## 2026-06-25 - Dynamically Created Alerts
**Learning:** When dynamically creating and appending status messages (like success or error toasts) via JavaScript, they must be given `role="alert"` to be immediately announced by screen readers.
**Action:** Always set `setAttribute("role", "alert")` on dynamically created status/notification DOM elements.

## 2026-07-03 - Dynamically Created Alerts in OAuth Forms
**Learning:** When dynamically creating status messages or waiting indicators (like Google Drive authorization status) via JavaScript, they must be given `role="alert"` to be immediately announced by screen readers. This ensures visually impaired users are kept informed of background state changes without needing to manually poll the interface.
**Action:** Always set `setAttribute("role", "alert")` on dynamically created status/notification DOM elements in HTML forms and OAuth pages.
## 2026-07-07 - Added accessible focus states to model chain widget
**Learning:** Parity between core-py and core-ts for frontend UI involves shared HTML/CSS templates inside strings. Interactive elements rendered inside these components must have focus states applied via CSS (like `:focus-within` and `:focus-visible`) for accessibility since the baseline templates may lack them.
**Action:** Always maintain UI parity between the Python and TS frontend string templates when introducing a11y improvements to credential forms or login pages.
## 2026-07-17 - ARIA Live Regions on Dynamic Status Boxes
**Learning:** The credential and login forms across the repository dynamically inject and modify status/error message containers (e.g., `.status-box`). While they had `role="alert"`, they lacked explicit `aria-live` and `aria-atomic` attributes. When manipulating DOM elements via JavaScript (like in `STEP_UI_JS` or the fetch callbacks), screen readers rely heavily on `aria-live` to know when to interrupt or queue announcements, and `aria-atomic` ensures the entire message block is read rather than just the changed node.
**Action:** When implementing or modifying dynamically updated form status messages (e.g., success or error boxes) in HTML templates or via JS across the codebase, always explicitly set `role="alert"`, `aria-live="polite"`, and `aria-atomic="true"` on the container element to ensure screen readers announce the full content immediately and non-disruptively.
## 2026-07-15 - Explicit Description Linking

**Learning:** When building custom HTML forms, static inputs with optional help text (such as the optional username field in the credential forms) need to explicitly link their help text for screen readers. While `for` and `id` pair the label, the `<p class="help-text">` remains semantically unlinked without additional attributes.
**Action:** Always link `<input>` elements to their corresponding help text using the `aria-describedby` attribute pointing to the ID of the help text paragraph.
## 2026-07-16 - Consistent Explicit Description Linking in Forms

**Learning:** When generating custom HTML forms, static inputs with optional help text (such as the optional username field in the credential forms) need to explicitly link their help text for screen readers. The TypeScript implementation already did this, but the Python implementation was missing it, leading to inconsistent accessibility between `core-ts` and `core-py`.
**Action:** Always maintain UI accessibility parity between Python and TS frontend string templates. Ensure `<input>` elements are linked to their corresponding help text using the `aria-describedby` attribute pointing to the ID of the help text paragraph in both codebases.
## 2026-08-01 - Accessible Error States in Card Groups (sweep complete)
**Learning:** `aria-errormessage` is only honoured while the input also carries `aria-invalid="true"` AND the element it points at is rendered. The card-group form set `aria-invalid` but left the status box at `display: none`, so a reference to it would have pointed at nothing -- the fix has to reveal the box in the same branch, not just add the attribute.
**Action:** The sweep is finished -- all 9 `setAttribute("aria-invalid", "true")` sites in `credential_form.py` and all 9 in `credential-form.ts` now set `aria-errormessage` in the same branch, pointing at `status-box` or `step-error`, and every branch that sets it also makes that element visible. Treat this class as closed; a new proposal here should first show a call site that still sets `aria-invalid` alone.

Note on dates: three entries above carried impossible dates (`$(date +%Y-%m-%d)` unexpanded, and two `2024-` dates predating the repository). They have been corrected from `git log -S` on the line that introduced each. Write the real date -- an undated or wrongly dated ledger cannot be used to tell which decision came first.
