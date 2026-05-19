## 2024-05-19 - Screen reader redundancy for native form validation
**Learning:** When form inputs use the native HTML `required` attribute, screen readers will automatically announce the field's requirement status. Adding visual text badges (like "Required" or "Optional") without hiding them from assistive technology causes redundant and confusing dual-announcements for users.
**Action:** Always add `aria-hidden="true"` to visual requirement/optional badges that accompany inputs utilizing native `required` attributes.
