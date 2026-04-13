## 2025-02-18 - Improved text contrast for dark mode form
**Learning:** Default dark mode grays (#555, #666) often fail WCAG AA contrast requirements (e.g. #555 on #111 has a 2.53 ratio vs the required 4.5).
**Action:** Always verify dark mode text contrasts. Use #9ca3af (Tailwind gray-400) or lighter for secondary text on dark backgrounds (#111/#1a1a1a) to maintain readable >4.5 contrast ratios.
