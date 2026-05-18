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
    aggregate_rows_by_channel,
    run_eval,
    run_mixed_channel_eval,
)
from src.eval.corpus_prepare import PreparedCorpus, prepare_corpus
from src.eval.failure_inspector import FailureReport, FailureRow, build_report
from src.eval.payment_dataset import (
    MLExportSummary,
    PaymentAssuranceReport,
    PaymentRelevancePrelabelSummary,
    PublicCorpusPaymentSeedSummary,
    RedactionFinding,
    RedactionSummary,
    SeedSummary,
    ValidationResult,
    audit_dataset_pii,
    build_payment_assurance_report,
    export_ml_jsonl,
    init_dataset,
    prelabel_payment_relevance,
    redact_eml,
    scan_redaction_findings,
    seed_public_corpus_payment_examples,
    seed_synthetic_bank_change_dataset,
    validate_dataset,
    write_payment_assurance_report,
)
from src.eval.payment_decision_eval import (
    PaymentDecisionEvalRow,
    PaymentDecisionEvalSummary,
    evaluate_payment_decisions,
)
from src.eval.payment_relevance_eval import (
    PaymentRelevanceEvalRow,
    PaymentRelevanceEvalSummary,
    evaluate_payment_relevance,
)

__all__ = [
    "AggregateMetrics",
    "EvalRun",
    "FailureReport",
    "FailureRow",
    "MLExportSummary",
    "PerSampleRow",
    "PaymentDecisionEvalRow",
    "PaymentDecisionEvalSummary",
    "PaymentAssuranceReport",
    "PaymentRelevanceEvalRow",
    "PaymentRelevanceEvalSummary",
    "PaymentRelevancePrelabelSummary",
    "PreparedCorpus",
    "PublicCorpusPaymentSeedSummary",
    "RedactionFinding",
    "RedactionSummary",
    "SeedSummary",
    "ValidationResult",
    "audit_dataset_pii",
    "aggregate_rows_by_channel",
    "build_report",
    "build_payment_assurance_report",
    "export_ml_jsonl",
    "evaluate_payment_decisions",
    "evaluate_payment_relevance",
    "init_dataset",
    "prepare_corpus",
    "prelabel_payment_relevance",
    "redact_eml",
    "run_eval",
    "run_mixed_channel_eval",
    "scan_redaction_findings",
    "seed_public_corpus_payment_examples",
    "seed_synthetic_bank_change_dataset",
    "validate_dataset",
    "write_payment_assurance_report",
]
