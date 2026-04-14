"""
Detection eval harness.

The harness runs a labeled corpus of `.eml` files through the pipeline
and stores ONE JSON row per sample to `eval_runs/<timestamp>_<sha>.jsonl`,
plus a small aggregate summary alongside it.

The per-sample row shape is the highest-leverage decision in this module
— it's what lets future cycles diff eval runs and identify which specific
samples flipped between commits. See ADR... actually no ADR for this one,
the cycle 9 review captured the design directly. Re-reading
`docs/EVALUATION.md` and the cycle 10 directive is the right pointer.
"""
from src.eval.harness import (
    AggregateMetrics,
    EvalRun,
    PerSampleRow,
    run_eval,
)

__all__ = ["AggregateMetrics", "EvalRun", "PerSampleRow", "run_eval"]
