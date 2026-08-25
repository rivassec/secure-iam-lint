#!/usr/bin/env python3
"""Fail if the built site contains anything a strict CSP would block.

Run against the Pelican output dir:

    python3 scripts/csp_audit.py output

Exits 0 if the tree is clean, 1 and prints the first offending lines
otherwise. Catches:

  * <tag ... style="..."> attributes   (blocked by style-src 'self')
  * <style> ... </style> blocks        (blocked by style-src 'self')
  * on<event>="..." handlers           (blocked by script-src 'self')

Safe against the GitHub Actions runner quirk where a piped
`head -c1 > /dev/null` on an empty stream under `set -e` can itself
exit non-zero and mask the real signal.
"""
from __future__ import annotations

import pathlib
import re
import sys

STYLE_ATTR = re.compile(r'\bstyle="[^"]*"')
STYLE_BLOCK = re.compile(r'<style\b', re.IGNORECASE)
EVENT_HANDLER = re.compile(r'\bon[a-z]+="[^"]*"', re.IGNORECASE)

# HTML meta attributes that contain the substring "on" or "style" but
# are NOT CSP violations. These are false positives to suppress.
EVENT_FALSE_POSITIVES = re.compile(
    r'http-equiv=|content=|name="[^"]*on[a-z]+"',
    re.IGNORECASE,
)


def scan(root: pathlib.Path) -> int:
    violations: list[tuple[str, int, str]] = []

    for path in sorted(root.rglob("*.html")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"::warning ::skipped {path}: {exc}", file=sys.stderr)
            continue

        for lineno, line in enumerate(text.splitlines(), start=1):
            if STYLE_ATTR.search(line):
                violations.append((str(path), lineno, line.strip()))
            if STYLE_BLOCK.search(line):
                violations.append((str(path), lineno, line.strip()))
            for match in EVENT_HANDLER.finditer(line):
                snippet = line[max(0, match.start() - 20):match.end() + 20]
                if EVENT_FALSE_POSITIVES.search(snippet):
                    continue
                violations.append((str(path), lineno, line.strip()))

    if violations:
        print(
            "::error ::Strict CSP would block the following output. "
            "Hoist inline style/script into a stylesheet or JS file.",
            file=sys.stderr,
        )
        for path, lineno, snippet in violations[:20]:
            print(f"  {path}:{lineno}: {snippet[:200]}", file=sys.stderr)
        if len(violations) > 20:
            print(
                f"  ... and {len(violations) - 20} more",
                file=sys.stderr,
            )
        return 1

    print("csp_audit: OK - no inline styles, <style> blocks, or event handlers.")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <output-dir>", file=sys.stderr)
        return 2
    root = pathlib.Path(argv[1])
    if not root.is_dir():
        print(f"{argv[0]}: {root} is not a directory", file=sys.stderr)
        return 2
    return scan(root)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
