#!/usr/bin/env python3
"""Print provider-specific mailbox connection guidance as JSON."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.support.mailbox_guides import mailbox_guide_payload  # noqa: E402  # agent-quality: allow: scoped lint suppression is required for import order or optional dependency compatibility


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print simple mailbox setup guidance for PhishAnalyze and PayShield.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--provider",
        default="all",
        help="Provider to explain: all, gmail, outlook, yahoo, icloud, zoho, fastmail, proton, aol, or imap.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    args = parser.parse_args()

    payload = mailbox_guide_payload(args.provider)
    print(json.dumps(payload, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
