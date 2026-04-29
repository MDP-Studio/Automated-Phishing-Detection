"""
Detection eval harness.

The harness is corpus-agnostic: give it a directory of .eml files and a
label dict, and it returns one row per sample plus an aggregate summary.
The default integration is the project's own `tests/real_world_samples/`
corpus (22 samples). Larger external mail corpora can be staged with
`scripts/eval_prepare_corpus.py`, then evaluated by passing its output
directory and labels.json.

Per-sample row shape (the high-leverage decision from the cycle 9 review):

    {
        "sample_id":           filename of the .eml
        "true_label":          "PHISHING" | "CLEAN"
        "predicted_verdict":   one of CLEAN / SUSPICIOUS / LIKELY_PHISHING / CONFIRMED_PHISHING
        "predicted_label":     "PHISHING" | "CLEAN" (binary projection of verdict)
        "overall_score":       float
        "overall_confidence":  float
        "per_analyzer_scores": {analyzer_name: {risk_score, confidence}}
        "calibration_fired":   list[str] of rule IDs (empty if none)
        "calibration_cap":     str | null (e.g. "SUSPICIOUS")
        "model_id":            LLM model the API actually used, "" if no LLM call
        "commit_sha":          short SHA at eval time
        "timestamp":           ISO-8601 UTC
        "true_positive":       bool — true_label PHISHING and predicted_label PHISHING
        "false_positive":      bool — true_label CLEAN and predicted_label PHISHING
        "true_negative":       bool — true_label CLEAN and predicted_label CLEAN
        "false_negative":      bool — true_label PHISHING and predicted_label CLEAN
        "error":               str | null — set if pipeline raised on this sample
    }

Storing per-sample rows is what lets future cycles run the harness, diff
the JSONL against a previous run, and answer "which 12 samples flipped
verdicts and which way" — a question aggregate metrics cannot answer.

The binary projection from verdict to label uses two configurable
thresholds in `BINARY_PROJECTIONS`:
- "permissive": SUSPICIOUS or higher counts as PHISHING (default)
- "strict": only LIKELY_PHISHING or higher counts as PHISHING

The default is "permissive" because the SUSPICIOUS verdict in this
pipeline is designed to route to analyst review — treating it as a
predicted-PHISHING for metric purposes matches operational reality.
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from src.config import PipelineConfig
from src.extractors.eml_parser import EMLParser
from src.models import PipelineResult, Verdict
from src.orchestrator.pipeline import PhishingPipeline

logger = logging.getLogger(__name__)


# Binary projections from 4-tier verdict to 2-class label.
# Permissive (default): SUSPICIOUS or higher -> PHISHING.
# Strict: only LIKELY_PHISHING or higher -> PHISHING.
BINARY_PROJECTIONS = {
    "permissive": {Verdict.SUSPICIOUS, Verdict.LIKELY_PHISHING, Verdict.CONFIRMED_PHISHING},
    "strict": {Verdict.LIKELY_PHISHING, Verdict.CONFIRMED_PHISHING},
}


@dataclass
class PerSampleRow:
    """One row per sample. Serialized to JSONL."""

    sample_id: str
    true_label: str
    predicted_verdict: str
    predicted_label: str
    overall_score: float
    overall_confidence: float
    per_analyzer_scores: dict
    calibration_fired: list[str]
    calibration_cap: Optional[str]
    model_id: str
    commit_sha: str
    timestamp: str
    true_positive: bool
    false_positive: bool
    true_negative: bool
    false_negative: bool
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AggregateMetrics:
    """Summary stats computed from per-sample rows."""

    total: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    errors: int
    projection: str  # "permissive" | "strict"

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return self.true_positive / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positive + self.false_negative
        return self.true_positive / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        denom = self.total - self.errors
        return (self.true_positive + self.true_negative) / denom if denom else 0.0

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "errors": self.errors,
            "projection": self.projection,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
        }


@dataclass
class EvalRun:
    """A single end-to-end eval run."""

    run_id: str
    timestamp: str
    commit_sha: str
    corpus_dir: str
    sample_count: int
    rows: list[PerSampleRow]
    aggregates_permissive: AggregateMetrics
    aggregates_strict: AggregateMetrics

    def to_summary_dict(self) -> dict:
        """Aggregate-only view; the per-sample rows live in the JSONL."""
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "commit_sha": self.commit_sha,
            "corpus_dir": self.corpus_dir,
            "sample_count": self.sample_count,
            "permissive": self.aggregates_permissive.to_dict(),
            "strict": self.aggregates_strict.to_dict(),
        }


# ─── helpers ────────────────────────────────────────────────────────────────


def _short_sha() -> str:
    """Return the current short commit SHA, or 'unknown' on failure."""
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return out.decode().strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"


def _project_verdict_to_label(verdict: Verdict, projection: str) -> str:
    threshold = BINARY_PROJECTIONS[projection]
    return "PHISHING" if verdict in threshold else "CLEAN"


def _row_from_pipeline_result(
    sample_id: str,
    true_label: str,
    result: PipelineResult,
    commit_sha: str,
    projection: str = "permissive",
) -> PerSampleRow:
    predicted_label = _project_verdict_to_label(result.verdict, projection)
    tp = true_label == "PHISHING" and predicted_label == "PHISHING"
    fp = true_label == "CLEAN" and predicted_label == "PHISHING"
    tn = true_label == "CLEAN" and predicted_label == "CLEAN"
    fn = true_label == "PHISHING" and predicted_label == "CLEAN"

    per_analyzer = {}
    for name, ar in (result.analyzer_results or {}).items():
        per_analyzer[name] = {
            "risk_score": round(float(ar.risk_score), 4),
            "confidence": round(float(ar.confidence), 4),
        }

    # Pull model_id from the nlp_intent details if the LLM ran
    nlp = (result.analyzer_results or {}).get("nlp_intent")
    model_id = ""
    if nlp and nlp.details:
        model_id = nlp.details.get("llm_model_version", "") or ""

    calibration_fired: list[str] = []
    calibration_cap: Optional[str] = None
    if result.calibration:
        calibration_fired = list(result.calibration.get("rules_fired", []))
        calibration_cap = result.calibration.get("verdict_cap")

    return PerSampleRow(
        sample_id=sample_id,
        true_label=true_label,
        predicted_verdict=result.verdict.value,
        predicted_label=predicted_label,
        overall_score=round(float(result.overall_score), 4),
        overall_confidence=round(float(result.overall_confidence), 4),
        per_analyzer_scores=per_analyzer,
        calibration_fired=calibration_fired,
        calibration_cap=calibration_cap,
        model_id=model_id,
        commit_sha=commit_sha,
        timestamp=datetime.now(timezone.utc).isoformat(),
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
        error=None,
    )


def _error_row(sample_id: str, true_label: str, commit_sha: str, error: str) -> PerSampleRow:
    return PerSampleRow(
        sample_id=sample_id,
        true_label=true_label,
        predicted_verdict="ERROR",
        predicted_label="ERROR",
        overall_score=0.0,
        overall_confidence=0.0,
        per_analyzer_scores={},
        calibration_fired=[],
        calibration_cap=None,
        model_id="",
        commit_sha=commit_sha,
        timestamp=datetime.now(timezone.utc).isoformat(),
        true_positive=False,
        false_positive=False,
        true_negative=False,
        false_negative=False,
        error=error,
    )


def aggregate_rows(rows: list[PerSampleRow], projection: str) -> AggregateMetrics:
    """
    Compute confusion-matrix and metrics from a list of per-sample rows.

    `projection` is informational here — the per-row TP/FP/TN/FN flags
    are already computed using whatever projection ran. This function
    just sums them. To compare projections you need to re-run the rows.
    """
    return AggregateMetrics(
        total=len(rows),
        true_positive=sum(1 for r in rows if r.true_positive),
        false_positive=sum(1 for r in rows if r.false_positive),
        true_negative=sum(1 for r in rows if r.true_negative),
        false_negative=sum(1 for r in rows if r.false_negative),
        errors=sum(1 for r in rows if r.error is not None),
        projection=projection,
    )


# ─── public entry point ─────────────────────────────────────────────────────


async def run_eval(
    corpus_dir: Union[str, Path],
    labels: dict[str, str],
    output_dir: Union[str, Path] = "eval_runs",
    projection: str = "permissive",
    config: Optional[PipelineConfig] = None,
) -> EvalRun:
    """
    Run the pipeline against every .eml in `corpus_dir` whose filename is a key in `labels`.

    Args:
        corpus_dir: directory containing .eml samples
        labels: dict mapping filename (basename) -> "PHISHING" | "CLEAN"
        output_dir: where to write the per-sample JSONL and summary JSON
        projection: "permissive" or "strict" (binary-from-4-tier mapping)
        config: optional PipelineConfig; defaults to PipelineConfig.from_env()

    Returns:
        EvalRun aggregating results. The per-sample JSONL and summary JSON
        are also written to disk as a side effect.
    """
    if projection not in BINARY_PROJECTIONS:
        raise ValueError(f"projection must be one of {list(BINARY_PROJECTIONS)}, got {projection!r}")

    corpus_path = Path(corpus_dir)
    if not corpus_path.exists():
        raise FileNotFoundError(f"corpus directory not found: {corpus_path}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    config = config or PipelineConfig.from_env()
    pipeline = PhishingPipeline.from_config(config)
    commit_sha = _short_sha()

    rows: list[PerSampleRow] = []
    parser = EMLParser()

    try:
        for sample_name, true_label in labels.items():
            sample_path = corpus_path / sample_name
            if not sample_path.exists():
                logger.warning("Sample not found: %s", sample_path)
                continue
            try:
                email = parser.parse_file(str(sample_path))
                if email is None:
                    rows.append(_error_row(sample_name, true_label, commit_sha, "parse_failed"))
                    continue
                result = await pipeline.analyze(email)
                rows.append(_row_from_pipeline_result(
                    sample_name, true_label, result, commit_sha, projection,
                ))
            except Exception as e:
                logger.exception("Pipeline raised on %s", sample_name)
                rows.append(_error_row(sample_name, true_label, commit_sha, str(e)))
    finally:
        await pipeline.close()

    # Build the run object
    now_utc = datetime.now(timezone.utc)
    run_id = f"{now_utc.strftime('%Y-%m-%d_%H%M')}_{commit_sha}"
    aggregates_permissive = aggregate_rows(rows, "permissive")
    # For the strict aggregate, recompute by re-projecting each row's verdict.
    strict_rows = []
    for r in rows:
        if r.error is not None:
            strict_rows.append(r)
            continue
        try:
            verdict = Verdict(r.predicted_verdict)
        except ValueError:
            strict_rows.append(r)
            continue
        strict_label = _project_verdict_to_label(verdict, "strict")
        strict_rows.append(PerSampleRow(
            **{**asdict(r),
               "predicted_label": strict_label,
               "true_positive": r.true_label == "PHISHING" and strict_label == "PHISHING",
               "false_positive": r.true_label == "CLEAN" and strict_label == "PHISHING",
               "true_negative": r.true_label == "CLEAN" and strict_label == "CLEAN",
               "false_negative": r.true_label == "PHISHING" and strict_label == "CLEAN"}
        ))
    aggregates_strict = aggregate_rows(strict_rows, "strict")

    eval_run = EvalRun(
        run_id=run_id,
        timestamp=now_utc.isoformat(),
        commit_sha=commit_sha,
        corpus_dir=str(corpus_path),
        sample_count=len(rows),
        rows=rows,
        aggregates_permissive=aggregates_permissive,
        aggregates_strict=aggregates_strict,
    )

    # Write per-sample JSONL
    jsonl_path = output_path / f"{run_id}.jsonl"
    with jsonl_path.open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row.to_dict(), default=str) + "\n")

    # Write aggregate summary alongside
    summary_path = output_path / f"{run_id}.summary.json"
    with summary_path.open("w", encoding="utf-8") as fh:
        json.dump(eval_run.to_summary_dict(), fh, indent=2, default=str)

    logger.info(
        "Eval run complete: %s — %d samples, %d errors, "
        "permissive precision=%.3f recall=%.3f, "
        "strict precision=%.3f recall=%.3f",
        run_id, eval_run.sample_count,
        aggregates_permissive.errors,
        aggregates_permissive.precision, aggregates_permissive.recall,
        aggregates_strict.precision, aggregates_strict.recall,
    )

    return eval_run
