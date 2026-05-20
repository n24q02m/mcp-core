## 2024-05-20 - Redundant Screen Reader Announcements in Form Badges
**Learning:** When form inputs use the native HTML `required` attribute, screen readers automatically announce the field as required. If there are accompanying visual text badges (e.g., `<span class="required-badge">Required</span>`), they create redundant and annoying double-announcements for screen reader users.
**Action:** Always add `aria-hidden="true"` to visual status badges that duplicate native HTML form states (like `required`) to prevent redundant announcements.
