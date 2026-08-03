#!/usr/bin/env python3
"""Scan files for the specific emoji codepoints blocked by issue #722."""

from __future__ import annotations

import os
import io
import re
import sys
from pathlib import Path

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )
if hasattr(sys.stderr, "buffer"):
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )

_EMOJI_RE = re.compile("[\u2600-\u27bf\u2b00-\u2bff\U0001f300-\U0001faff]")
_SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "coverage",
}
_SKIP_FILES = {
    ".coverage",
    ".coverage.xml",
}


def _codepoint(ch: str) -> str:
    return f"U+{ord(ch):X}"


def find_emoji(text: str) -> list[str]:
    seen: set[str] = set()
    codes: list[str] = []
    for match in _EMOJI_RE.finditer(text):
        code = _codepoint(match.group(0))
        if code not in seen:
            seen.add(code)
            codes.append(code)
    return codes


def scan_file(path: Path) -> list[tuple[int, str, list[str]]]:
    findings: list[tuple[int, str, list[str]]] = []
    for line_no, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        codes = find_emoji(line)
        if codes:
            findings.append((line_no, line, codes))
    return findings


def _iter_paths(paths: list[str]) -> list[Path]:
    resolved: list[Path] = []
    for raw in paths:
        root = Path(raw)
        if not root.exists():
            raise FileNotFoundError(root)
        if root.is_file():
            if root.name in _SKIP_FILES:
                continue
            resolved.append(root)
            continue
        for current_dir, dir_names, file_names in os.walk(root):
            dir_names[:] = sorted(name for name in dir_names if name not in _SKIP_DIRS)
            current_path = Path(current_dir)
            for file_name in sorted(file_names):
                if file_name in _SKIP_FILES:
                    continue
                resolved.append(current_path / file_name)
    return resolved


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    targets = args or ["packages"]

    violations = False
    for path in _iter_paths(targets):
        for line_no, line, codes in scan_file(path):
            violations = True
            print(f"{path}:{line_no}: {', '.join(codes)}")

    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
