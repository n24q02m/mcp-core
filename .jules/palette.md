## 2024-05-16 - Prevent Redundant Screen Reader Announcements on Visual Badges
**Learning:** When form inputs use the native HTML `required` attribute, screen readers automatically announce the field as required. Adding a visual badge (e.g., `<span class="required-badge">Required</span>`) without `aria-hidden="true"` causes screen readers to redundantly read "Required" multiple times, confusing the user.
**Action:** Always add `aria-hidden="true"` to visual text badges accompanying form fields that already convey state via native HTML attributes (like `required`) or explicit ARIA attributes.
