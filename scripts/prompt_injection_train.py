#!/usr/bin/env python3
"""Train/test a shared prompt-injection classifier."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.eval.prompt_injection_dataset import DEFAULT_OUTPUT_JSONL  # noqa: E402
from src.ml.prompt_injection_classifier import (  # noqa: E402
    DEFAULT_MODEL_DIR,
    train_prompt_injection_classifier,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Train/test a TF-IDF + logistic regression prompt-injection classifier.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_OUTPUT_JSONL)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_MODEL_DIR)
    args = parser.parse_args()

    metrics = train_prompt_injection_classifier(
        dataset_path=args.dataset,
        output_dir=args.output_dir,
    )
    print(f"Prompt-injection ML training complete: {args.dataset}")
    print(f"  train rows:   {metrics.train_rows}")
    print(f"  val rows:     {metrics.validation_rows}")
    print(f"  test rows:    {metrics.test_rows}")
    print(f"  classes:      {', '.join(metrics.classes)}")
    print(f"  test accuracy:{metrics.test_accuracy: .3f}")
    print("  matrix:")
    for expected, predictions in sorted(metrics.confusion_matrix.items()):
        for predicted, count in sorted(predictions.items()):
            print(f"    {expected} -> {predicted}: {count}")
    print(f"  model:        {metrics.model_path}")
    print(f"  metrics:      {metrics.metrics_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
