
## 2026-04-17 - Dark Mode Contrast & A11y in Dynamic HTML
**Learning:** Automatically generated Python/TS HTML string templates (e.g., `credential_form.py`, `credential-form.ts`) for dark mode interfaces (#0f0f0f, #1a1a1a backgrounds) frequently use low-contrast text colors (#666, #555). These are missed by automated web linters because the HTML is embedded in strings.
**Action:** Always manually verify WCAG AA compliance (>4.5:1) for text colors in dynamically generated UI templates, prioritizing high-contrast colors like `#9ca3af` (Tailwind gray-400) for secondary text. Additionally, ensure ARIA attributes (`aria-invalid`, `aria-busy`) handled by embedded vanilla JS are manually synchronized across both Python and TS implementations.
