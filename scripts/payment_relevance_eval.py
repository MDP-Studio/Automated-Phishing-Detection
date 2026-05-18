#!/usr/bin/env python3
"""Evaluate PayShield payment relevance labels and skip routing."""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.eval.payment_dataset import DEFAULT_DATASET_DIR  # noqa: E402
from src.eval.payment_relevance_eval import evaluate_payment_relevance  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate payment_relevance labels against the PayShield relevance rules.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--output-prefix", type=Path, default=None)
    parser.add_argument("--split", default=None)
    parser.add_argument("--source-type", default=None)
    args = parser.parse_args()

    summary = asyncio.run(
        evaluate_payment_relevance(
            dataset_dir=args.dataset,
            output_prefix=args.output_prefix,
            split=args.split,
            source_type=args.source_type,
        )
    )
    print(f"Payment relevance eval complete: {summary.dataset_dir}")
    print(f"  rows:                 {summary.row_count}")
    print(f"  label accuracy:       {summary.label_accuracy:.3f}")
    print(f"  should-scan accuracy: {summary.should_scan_accuracy:.3f}")
    print(f"  false negatives:      {summary.false_negatives}")
    print(f"  false positives:      {summary.false_positives}")
    print(f"  json:                 {summary.json_path}")
    print(f"  csv:                  {summary.csv_path}")
    print(f"  markdown:             {summary.markdown_path}")
    return 0 if summary.false_negatives == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
