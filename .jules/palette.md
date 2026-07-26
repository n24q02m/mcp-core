## 2024-08-01 - Explicit Label Linking

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
## 2024-05-18 - ARIA Live Regions on Dynamic Status Boxes
**Learning:** The credential and login forms across the repository dynamically inject and modify status/error message containers (e.g., `.status-box`). While they had `role="alert"`, they lacked explicit `aria-live` and `aria-atomic` attributes. When manipulating DOM elements via JavaScript (like in `STEP_UI_JS` or the fetch callbacks), screen readers rely heavily on `aria-live` to know when to interrupt or queue announcements, and `aria-atomic` ensures the entire message block is read rather than just the changed node.
**Action:** When implementing or modifying dynamically updated form status messages (e.g., success or error boxes) in HTML templates or via JS across the codebase, always explicitly set `role="alert"`, `aria-live="polite"`, and `aria-atomic="true"` on the container element to ensure screen readers announce the full content immediately and non-disruptively.
## 2026-07-15 - Explicit Description Linking

**Learning:** When building custom HTML forms, static inputs with optional help text (such as the optional username field in the credential forms) need to explicitly link their help text for screen readers. While `for` and `id` pair the label, the `<p class="help-text">` remains semantically unlinked without additional attributes.
**Action:** Always link `<input>` elements to their corresponding help text using the `aria-describedby` attribute pointing to the ID of the help text paragraph.
## 2024-08-01 - Accessible Error States in Card Groups
**Learning:** When dynamically validating form fields built via JavaScript (like in a repeating card group) and focusing the first invalid input, explicitly setting `aria-errormessage` alongside `aria-invalid` links the input to the status box containing the validation message. This provides screen readers with context on *why* the input is invalid, not just that it *is* invalid.
**Action:** When implementing manual form validation that sets `aria-invalid="true"`, ensure `aria-errormessage` is also set on the invalid input, pointing to the ID of the element displaying the error message.
