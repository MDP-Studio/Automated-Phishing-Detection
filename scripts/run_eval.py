#!/usr/bin/env python3
"""
Eval harness CLI.

Runs the pipeline against a labeled corpus and writes per-sample JSONL
plus an aggregate summary to `eval_runs/`. The harness itself is the
deliverable; the numbers from any single run are data, not goalposts.

Default corpus: tests/real_world_samples/ (the project's own 22-sample
labeled set). Prepare larger external corpora with
scripts/eval_prepare_corpus.py, then pass its output directory and
labels.json here.

Usage:
    # Default: run against tests/real_world_samples/
    python scripts/run_eval.py

    # Custom corpus + labels file
    python scripts/run_eval.py --corpus path/to/eml/dir --labels path/to/labels.json

Labels file format (JSON):
    {
        "sample_01.eml": "PHISHING",
        "sample_02.eml": "CLEAN",
        ...
    }
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Load .env so analyzers needing API keys don't fail on import
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


# Default labels for the 22-sample real_world_samples corpus.
# Mirrors tests/real_world_samples/run_batch_test.py.
DEFAULT_CORPUS = PROJECT_ROOT / "tests" / "real_world_samples"
DEFAULT_LABELS = {
    "sample_01_microsoft_credential_harvest.eml":  "PHISHING",
    "sample_02_paypal_account_suspension.eml":      "PHISHING",
    "sample_03_dhl_delivery_notification.eml":      "PHISHING",
    "sample_04_apple_id_disabled.eml":              "PHISHING",
    "sample_05_netflix_payment_failed.eml":         "PHISHING",
    "sample_06_bank_of_america_wire_confirm.eml":   "PHISHING",
    "sample_07_amazon_order_confirm.eml":           "PHISHING",
    "sample_08_google_workspace_shared_doc.eml":    "PHISHING",
    "sample_09_irs_tax_refund.eml":                 "PHISHING",
    "sample_10_linkedin_connection_request.eml":    "PHISHING",
    "sample_11_legitimate_github_notification.eml": "CLEAN",
    "sample_12_legitimate_work_email.eml":          "CLEAN",
    "sample_13_legitimate_amazon_order.eml":         "CLEAN",
    "sample_14_legitimate_paypal_receipt.eml":       "CLEAN",
    "sample_15_legitimate_google_security_alert.eml": "CLEAN",
    "sample_16_legitimate_netflix_new_show.eml":     "CLEAN",
    "sample_17_legitimate_linkedin_digest.eml":      "CLEAN",
    "sample_18_legitimate_bank_statement.eml":       "CLEAN",
    "sample_19_legitimate_dhl_tracking.eml":         "CLEAN",
    "sample_20_legitimate_stripe_invoice.eml":       "CLEAN",
    "sample_21_legitimate_newsletter.eml":           "CLEAN",
    "sample_22_legitimate_docusign.eml":             "CLEAN",
}


async def _main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS,
                        help="Directory containing .eml samples (default: tests/real_world_samples/)")
    parser.add_argument("--labels", type=Path, default=None,
                        help="JSON file mapping filename->label. Default: built-in 22-sample labels.")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "eval_runs",
                        help="Where to write JSONL + summary (default: eval_runs/)")
    parser.add_argument("--projection", choices=["permissive", "strict"], default="permissive",
                        help="Binary projection for the per-row TP/FP flags (default: permissive)")
    args = parser.parse_args()

    if args.labels:
        labels = json.loads(args.labels.read_text(encoding="utf-8"))
    else:
        labels = DEFAULT_LABELS

    from src.eval import run_eval

    print(f"Running eval against {args.corpus} ({len(labels)} samples)...")
    eval_run = await run_eval(
        corpus_dir=args.corpus,
        labels=labels,
        output_dir=args.output,
        projection=args.projection,
    )

    print(f"\nRun ID: {eval_run.run_id}")
    print(f"Per-sample JSONL: {args.output}/{eval_run.run_id}.jsonl")
    print(f"Aggregate summary: {args.output}/{eval_run.run_id}.summary.json")
    print(f"\nPermissive (SUSPICIOUS+ counts as PHISHING):")
    perm = eval_run.aggregates_permissive
    print(f"  TP={perm.true_positive} FP={perm.false_positive} TN={perm.true_negative} FN={perm.false_negative}")
    print(f"  precision={perm.precision:.3f} recall={perm.recall:.3f} f1={perm.f1:.3f}")
    print(f"\nStrict (LIKELY_PHISHING+ counts as PHISHING):")
    strict = eval_run.aggregates_strict
    print(f"  TP={strict.true_positive} FP={strict.false_positive} TN={strict.true_negative} FN={strict.false_negative}")
    print(f"  precision={strict.precision:.3f} recall={strict.recall:.3f} f1={strict.f1:.3f}")
    print(f"\nErrors: {perm.errors}/{eval_run.sample_count}")
    print()
    print("These numbers are a baseline. They are not a goal. Detection-quality")
    print("improvements should be tracked by diffing the per-sample JSONL between")
    print("commits, not by chasing the aggregate metrics in isolation.")


if __name__ == "__main__":
    asyncio.run(_main())
