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
from src.eval.corpus_prepare import PreparedCorpus, prepare_corpus
from src.eval.failure_inspector import FailureReport, FailureRow, build_report
from src.eval.payment_dataset import ValidationResult, init_dataset, validate_dataset

__all__ = [
    "AggregateMetrics",
    "EvalRun",
    "FailureReport",
    "FailureRow",
    "PerSampleRow",
    "PreparedCorpus",
    "ValidationResult",
    "build_report",
    "init_dataset",
    "prepare_corpus",
    "run_eval",
    "validate_dataset",
]
