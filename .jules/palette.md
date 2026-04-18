## 2024-05-18 - Improve Credential Form Contrast and Focus States
**Learning:** Hardcoded `#666` and `#555` gray text values on `#1a1a1a` and `#111` dark backgrounds fail to meet the WCAG AA contrast ratio of 4.5:1. Using `#9ca3af` provides excellent legibility while maintaining a subtle aesthetic.
**Action:** When implementing dark mode interfaces, verify contrast ratios for gray text elements to ensure they exceed 4.5:1, and ensure buttons and links have distinct `:focus-visible` styles with sufficient outline offset for keyboard navigation.
