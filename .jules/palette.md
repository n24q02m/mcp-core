## 2024-06-25 - Prevent redundant screen reader announcements on required form fields
**Learning:** When form inputs use the native HTML `required` attribute, screen readers will automatically announce the field as required. If a visual "Required" (or "Optional") text badge is also present in the label, the screen reader will read the badge text as well, resulting in redundant and confusing announcements (e.g., "Email, required, edit text, required").
**Action:** Always add `aria-hidden="true"` to visual text badges (like `.required-badge` or `.optional-badge`) that accompany inputs with native `required` attributes to ensure a clean and concise screen reader experience.
## 2024-05-24 - Explicitly link labels to inputs
**Learning:** When custom HTML forms are generated and inputs are dynamically rendered, omitting explicit `for` and `id` attributes on `<label>` and `<input>` elements reduces the clickable area and breaks screen reader context.
**Action:** Always ensure that every `<label>` element has a `for` attribute that precisely matches the `id` attribute of its corresponding `<input>`.
