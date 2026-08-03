#!/usr/bin/env python3
"""Tests for no-emoji.py.

Run with: python scripts/test_no_emoji.py
Exit code 0 => all pass; non-zero => at least one failure.
"""

from __future__ import annotations

import importlib.util
import tempfile
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("no_emoji", _HERE / "no-emoji.py")
assert _SPEC is not None and _SPEC.loader is not None
_MOD = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MOD)

find_emoji = _MOD.find_emoji
scan_file = _MOD.scan_file
_iter_paths = _MOD._iter_paths


def test_find_emoji_detects_expected_codepoints() -> None:
    text = "Safe prose, Vietnamese: xin ch\u00e0o. Danger: \U0001f3a8, \u26a1, and \U0001f680 again \U0001f3a8."
    assert find_emoji(text) == ["U+1F3A8", "U+26A1", "U+1F680"]


def test_scan_file_reports_line_numbers_and_ignores_vietnamese() -> None:
    path = _HERE / "tmp-no-emoji-sample.txt"
    path.write_text(
        "Hello \u0111\u01b0\u1ee3c.\n"
        "Launch \U0001f680 now.\n"
        "Punctuation only: \u2014 \u2026 \u2192.\n",
        encoding="utf-8",
    )
    try:
        findings = scan_file(path)
    finally:
        path.unlink(missing_ok=True)

    assert findings == [(2, "Launch \U0001f680 now.", ["U+1F680"])]


def test_iter_paths_prunes_skipped_dirs_recursively_and_skips_generated_files() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "src" / "main.py"
        source.parent.mkdir(parents=True)
        source.write_text("print('hello')\n", encoding="utf-8")

        nested_skip = root / "src" / ".venv" / "lib" / "hidden.txt"
        nested_skip.parent.mkdir(parents=True)
        nested_skip.write_text("Hidden \u26a1 file\n", encoding="utf-8")

        ruff_cache = root / "src" / ".ruff_cache" / "cache" / "data.bin"
        ruff_cache.parent.mkdir(parents=True)
        ruff_cache.write_bytes(b"\xff\xfe\x00\x80")

        coverage = root / ".coverage"
        coverage.write_text("Generated \u26a1 file\n", encoding="utf-8")

        assert _iter_paths([str(root)]) == [source]


def main() -> int:
    tests = [
        test_find_emoji_detects_expected_codepoints,
        test_scan_file_reports_line_numbers_and_ignores_vietnamese,
        test_iter_paths_prunes_skipped_dirs_recursively_and_skips_generated_files,
    ]
    for test in tests:
        test()
    print(f"OK: {len(tests)} test(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
