## $(date +%Y-%m-%d) - Explicit Label Linking

**Learning:** When building custom HTML forms, using implicit labeling (e.g., `<label>Text <input></label>`) is valid but explicitly linking `<label>` and `<input>` elements with `for` and `id` attributes is recognized as an accessibility best practice. This provides more robust support across a wider range of assistive technologies.

**Action:** Always explicitly link `<label>` elements to their corresponding `<input>` elements using matching `for` and `id` attributes when generating custom HTML forms.
## 2026-06-21 - Accessible Landmarks
**Learning:** When using `<section>` elements for visual groupings (like Capabilities Requested), they need an accessible name (via `aria-labelledby`) to be exposed as proper region landmarks to screen readers.
**Action:** Always pair `<section>` elements with `aria-labelledby` pointing to their heading's ID.
