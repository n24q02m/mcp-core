## 2025-02-28 - Dark Mode Contrast on Python-Generated HTML
**Learning:** When HTML is generated dynamically via Python strings (like `credential_form.py`), styling attributes such as inline CSS or dark mode templates are easy to miss with standard web-based linting/accessibility tools, resulting in WCAG failures (like contrast ratios under 4.5:1).
**Action:** Always manually verify text contrast ratios (>4.5:1 for AA) on dark mode interfaces explicitly in the Python template rendering files where automated accessibility tools may not scan.
