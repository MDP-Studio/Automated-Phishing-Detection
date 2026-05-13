#!/usr/bin/env python3
"""CLI wrapper for preparing prompt-injection ML data."""
from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.eval.prompt_injection_dataset import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
