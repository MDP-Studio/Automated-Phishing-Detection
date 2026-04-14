#!/usr/bin/env python3
"""
API Diagnostic CLI — Tests each external service with a real HTTP request.
No mocks, no defaults. Shows you exactly what works and what doesn't.

This script is a thin colored-output wrapper around
`src/diagnostics/api_checks.py`. The actual checks live there. Editing
this file should only mean editing how things print, never editing what
gets checked. Cycle 10 audit item #10 closed the three-way duplication
between this file, the deleted `test_apis.py`, and the `/api/diagnose`
endpoint in `main.py` — all three now share the one implementation.

Usage: python diagnose_apis.py
"""
import asyncio
import os
import sys
from pathlib import Path

# Load .env manually so this script can be run without dotenv installed.
env_path = Path(".env")
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip())

# Add project root to the import path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.diagnostics import CheckStatus, run_all_checks
from src.diagnostics.api_checks import summarize


# ANSI colour codes for the formatted output. Falls back to plain text
# when stdout isn't a tty (CI logs, file redirects).
_USE_COLOR = sys.stdout.isatty()


def _colored(label: str, color_code: str) -> str:
    if not _USE_COLOR:
        return label
    return f"\033[{color_code}m{label}\033[0m"


_LABELS = {
    CheckStatus.PASS: _colored("[PASS]", "92"),
    CheckStatus.FAIL: _colored("[FAIL]", "91"),
    CheckStatus.SKIP: _colored("[SKIP]", "93"),
    CheckStatus.WARN: _colored("[WARN]", "93"),
}


def _format_result(result) -> str:
    label = _LABELS.get(result.status, str(result.status))
    line = f"  {label} {result.service}: {result.message}"
    if result.http_status is not None:
        line += f" (HTTP {result.http_status})"
    return line


async def main() -> int:
    print("\n=== API Diagnostic Tool ===\n")
    print("Testing each configured external service with a live HTTP request.")
    print("Services without an API key configured are SKIPped.\n")

    results = await run_all_checks()
    for r in results:
        print(_format_result(r))

    summary = summarize(results)
    print(f"\n{summary['headline']}")
    print(f"  pass: {summary['counts']['pass']}, "
          f"fail: {summary['counts']['fail']}, "
          f"warn: {summary['counts']['warn']}, "
          f"skip: {summary['counts']['skip']}")

    # Exit non-zero if anything failed — useful for shell scripting.
    return 0 if summary["counts"]["fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
