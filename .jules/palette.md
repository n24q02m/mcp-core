## $(date +%Y-%m-%d) - Explicit Label Linking

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
