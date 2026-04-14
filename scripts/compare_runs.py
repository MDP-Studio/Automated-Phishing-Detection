#!/usr/bin/env python3
"""
Run the same set of email samples through the pipeline twice — once with
calibration enabled (the new default) and once with REGISTRY temporarily
emptied — and print the diff side by side.

This is the eval harness diff tool from cycle 6. It's deliberately small
because the project doesn't have a full eval harness yet (that's a roadmap
item). What it gives you today:

  - The "calibrated vs uncalibrated" view that ADR 0001 §FM2 calls out as
    the early warning for analyzer regressions.
  - Concrete proof that the LinkedIn FP (sample_17) flips and the BEC
    sample (sample_08) doesn't regress.
  - A negative-case check that the typo-squat sample (sample_10) is NOT
    "improved" by the calibration rule.

Usage:
    python scripts/compare_runs.py

By default it runs three samples chosen for the cycle 6 commit:
  - sample_17_legitimate_linkedin_digest.eml      (the FP this cycle fixes)
  - sample_08_google_workspace_shared_doc.eml     (BEC must not regress)
  - sample_10_linkedin_connection_request.eml     (typo squat must not benefit)

Pass `--all` to run all samples in tests/real_world_samples/.
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

# Load .env so any analyzers needing API keys don't fail on import.
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass


from src.config import PipelineConfig
from src.extractors.eml_parser import EMLParser
from src.orchestrator.pipeline import PhishingPipeline
from src.scoring import calibration as cal_module


CYCLE6_SAMPLES = [
    "sample_17_legitimate_linkedin_digest.eml",
    "sample_08_google_workspace_shared_doc.eml",
    "sample_10_linkedin_connection_request.eml",
]

SAMPLES_DIR = PROJECT_ROOT / "tests" / "real_world_samples"


async def _analyze_one(pipeline: PhishingPipeline, eml_path: Path):
    parser = EMLParser()
    # parse_file is synchronous in this repo (see src/extractors/eml_parser.py)
    email = parser.parse_file(str(eml_path))
    return await pipeline.analyze(email)


async def _run_set(samples: list[Path], with_calibration: bool):
    """Run the sample set through the pipeline. Returns list of dicts."""
    config = PipelineConfig.from_env()
    pipeline = PhishingPipeline.from_config(config)

    saved_registry = list(cal_module.REGISTRY)
    if not with_calibration:
        # Empty the registry so apply_calibration_rules is a no-op.
        # The decision engine still calls it; it just gets back an empty
        # CalibrationOutcome and the verdict cap path is skipped.
        cal_module.REGISTRY = []  # type: ignore[assignment]

    results = []
    try:
        for sample in samples:
            try:
                r = await _analyze_one(pipeline, sample)
                results.append({
                    "sample": sample.name,
                    "verdict": r.verdict.value,
                    "score": round(r.overall_score, 3),
                    "confidence": round(r.overall_confidence, 3),
                    "calibration": r.calibration,
                })
            except Exception as e:
                results.append({"sample": sample.name, "error": str(e)})
    finally:
        cal_module.REGISTRY = saved_registry  # type: ignore[assignment]
        await pipeline.close()

    return results


def _diff(off, on):
    """Pretty-print the side-by-side diff."""
    print()
    print("=" * 88)
    print(f"{'sample':<55}  {'OFF (verdict/score)':<22}  {'ON (verdict/score)':<22}")
    print("-" * 88)
    for off_row, on_row in zip(off, on):
        name = off_row["sample"][:54]
        if "error" in off_row:
            off_disp = f"ERR: {off_row['error'][:18]}"
        else:
            off_disp = f"{off_row['verdict']:<18} {off_row['score']:.2f}"
        if "error" in on_row:
            on_disp = f"ERR: {on_row['error'][:18]}"
        else:
            on_disp = f"{on_row['verdict']:<18} {on_row['score']:.2f}"
        marker = "  ← FLIPPED" if (
            "error" not in off_row and "error" not in on_row
            and off_row["verdict"] != on_row["verdict"]
        ) else ""
        print(f"{name:<55}  {off_disp:<22}  {on_disp:<22}{marker}")
        if "calibration" in on_row and on_row.get("calibration"):
            for line in on_row["calibration"].get("rules_fired", []):
                print(f"{'':<55}    rule fired: {line}")
    print("=" * 88)
    print()


async def _main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true",
                        help="Run every sample in tests/real_world_samples/")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON instead of the pretty diff")
    args = parser.parse_args()

    if args.all:
        samples = sorted(SAMPLES_DIR.glob("sample_*.eml"))
    else:
        samples = [SAMPLES_DIR / name for name in CYCLE6_SAMPLES]

    print(f"Running {len(samples)} samples WITHOUT calibration...")
    off = await _run_set(samples, with_calibration=False)
    print(f"Running {len(samples)} samples WITH calibration...")
    on = await _run_set(samples, with_calibration=True)

    if args.json:
        print(json.dumps({"off": off, "on": on}, indent=2, default=str))
    else:
        _diff(off, on)


if __name__ == "__main__":
    asyncio.run(_main())
