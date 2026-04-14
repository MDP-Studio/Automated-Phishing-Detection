"""
Unit tests for src/eval/harness.py.

Tests are corpus-mocked. The actual pipeline run against a real corpus
is exercised by `scripts/run_eval.py` and lands in `eval_runs/` — that
is integration territory, not unit territory.

What's locked here:
- PerSampleRow schema: every field present, JSONL serialization clean
- Aggregate confusion-matrix counts add up
- Precision / recall / F1 formulas (incl. divide-by-zero handling)
- Binary projection (permissive vs strict) is correct
- Verdict-to-label mapping at the threshold edges
- Error rows don't pollute TP/FP/TN/FN counts
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.eval.harness import (
    BINARY_PROJECTIONS,
    AggregateMetrics,
    PerSampleRow,
    _project_verdict_to_label,
    _row_from_pipeline_result,
    _error_row,
    aggregate_rows,
)
from src.models import AnalyzerResult, PipelineResult, Verdict


# ─── Helpers ────────────────────────────────────────────────────────────────


def _build_result(
    verdict: Verdict,
    score: float = 0.5,
    confidence: float = 0.7,
    nlp_model_id: str = "claude-haiku-4-5-20251001",
    calibration_fired: list[str] = None,
    calibration_cap: str = None,
) -> PipelineResult:
    cal = None
    if calibration_fired:
        cal = {
            "rules_fired": calibration_fired,
            "verdict_cap": calibration_cap,
            "score_adjustments": [],
            "reasoning_lines": [],
        }
    return PipelineResult(
        email_id="test",
        verdict=verdict,
        overall_score=score,
        overall_confidence=confidence,
        analyzer_results={
            "header_analysis": AnalyzerResult(
                analyzer_name="header_analysis",
                risk_score=0.0, confidence=0.9, details={},
            ),
            "nlp_intent": AnalyzerResult(
                analyzer_name="nlp_intent",
                risk_score=0.95, confidence=0.85,
                details={"llm_model_version": nlp_model_id},
            ),
        },
        extracted_urls=[],
        iocs={},
        reasoning="test",
        calibration=cal,
    )


# ─── Binary projection ─────────────────────────────────────────────────────


class TestBinaryProjection:
    def test_permissive_includes_suspicious(self):
        assert _project_verdict_to_label(Verdict.SUSPICIOUS, "permissive") == "PHISHING"
        assert _project_verdict_to_label(Verdict.LIKELY_PHISHING, "permissive") == "PHISHING"
        assert _project_verdict_to_label(Verdict.CONFIRMED_PHISHING, "permissive") == "PHISHING"
        assert _project_verdict_to_label(Verdict.CLEAN, "permissive") == "CLEAN"

    def test_strict_excludes_suspicious(self):
        assert _project_verdict_to_label(Verdict.SUSPICIOUS, "strict") == "CLEAN"
        assert _project_verdict_to_label(Verdict.LIKELY_PHISHING, "strict") == "PHISHING"
        assert _project_verdict_to_label(Verdict.CONFIRMED_PHISHING, "strict") == "PHISHING"
        assert _project_verdict_to_label(Verdict.CLEAN, "strict") == "CLEAN"

    def test_both_projections_registered(self):
        assert "permissive" in BINARY_PROJECTIONS
        assert "strict" in BINARY_PROJECTIONS


# ─── PerSampleRow construction ──────────────────────────────────────────────


class TestRowFromPipelineResult:
    def test_true_positive(self):
        result = _build_result(Verdict.LIKELY_PHISHING)
        row = _row_from_pipeline_result(
            "phish.eml", "PHISHING", result, "abc123", "permissive",
        )
        assert row.true_positive is True
        assert row.false_positive is False
        assert row.false_negative is False
        assert row.true_negative is False
        assert row.predicted_label == "PHISHING"
        assert row.predicted_verdict == "LIKELY_PHISHING"

    def test_true_negative(self):
        result = _build_result(Verdict.CLEAN, score=0.05)
        row = _row_from_pipeline_result(
            "clean.eml", "CLEAN", result, "abc123", "permissive",
        )
        assert row.true_negative is True
        assert row.true_positive is False
        assert row.false_positive is False

    def test_false_positive_clean_predicted_phishing(self):
        result = _build_result(Verdict.SUSPICIOUS)
        row = _row_from_pipeline_result(
            "ham.eml", "CLEAN", result, "abc123", "permissive",
        )
        # SUSPICIOUS in permissive mode counts as PHISHING -> FP
        assert row.false_positive is True
        assert row.true_negative is False

    def test_false_negative_phishing_predicted_clean(self):
        result = _build_result(Verdict.CLEAN)
        row = _row_from_pipeline_result(
            "phish.eml", "PHISHING", result, "abc123", "permissive",
        )
        assert row.false_negative is True
        assert row.true_positive is False

    def test_strict_mode_suspicious_is_clean(self):
        """SUSPICIOUS in strict mode should NOT count as PHISHING."""
        result = _build_result(Verdict.SUSPICIOUS)
        row = _row_from_pipeline_result(
            "ham.eml", "CLEAN", result, "abc123", "strict",
        )
        # In strict mode, SUSPICIOUS -> CLEAN -> matches true label -> TN
        assert row.true_negative is True
        assert row.false_positive is False

    def test_per_analyzer_scores_extracted(self):
        result = _build_result(Verdict.SUSPICIOUS)
        row = _row_from_pipeline_result(
            "x.eml", "PHISHING", result, "abc123", "permissive",
        )
        assert "header_analysis" in row.per_analyzer_scores
        assert "nlp_intent" in row.per_analyzer_scores
        assert row.per_analyzer_scores["nlp_intent"]["risk_score"] == 0.95
        assert row.per_analyzer_scores["nlp_intent"]["confidence"] == 0.85

    def test_model_id_captured(self):
        result = _build_result(Verdict.SUSPICIOUS, nlp_model_id="claude-haiku-4-5-20260101")
        row = _row_from_pipeline_result(
            "x.eml", "PHISHING", result, "abc123", "permissive",
        )
        assert row.model_id == "claude-haiku-4-5-20260101"

    def test_model_id_empty_when_no_nlp(self):
        result = PipelineResult(
            email_id="test",
            verdict=Verdict.CLEAN,
            overall_score=0.0,
            overall_confidence=1.0,
            analyzer_results={},
            extracted_urls=[],
            iocs={},
            reasoning="",
        )
        row = _row_from_pipeline_result(
            "x.eml", "CLEAN", result, "abc123", "permissive",
        )
        assert row.model_id == ""

    def test_calibration_recorded_when_fired(self):
        result = _build_result(
            Verdict.SUSPICIOUS,
            calibration_fired=["linkedin_social_platform_corroboration"],
            calibration_cap="SUSPICIOUS",
        )
        row = _row_from_pipeline_result(
            "linkedin.eml", "CLEAN", result, "abc123", "permissive",
        )
        assert row.calibration_fired == ["linkedin_social_platform_corroboration"]
        assert row.calibration_cap == "SUSPICIOUS"

    def test_calibration_empty_when_none(self):
        result = _build_result(Verdict.LIKELY_PHISHING)
        row = _row_from_pipeline_result(
            "x.eml", "PHISHING", result, "abc123", "permissive",
        )
        assert row.calibration_fired == []
        assert row.calibration_cap is None

    def test_commit_sha_recorded(self):
        result = _build_result(Verdict.CLEAN)
        row = _row_from_pipeline_result(
            "x.eml", "CLEAN", result, "deadbee", "permissive",
        )
        assert row.commit_sha == "deadbee"

    def test_timestamp_iso8601(self):
        result = _build_result(Verdict.CLEAN)
        row = _row_from_pipeline_result(
            "x.eml", "CLEAN", result, "abc", "permissive",
        )
        # Should parse cleanly
        parsed = datetime.fromisoformat(row.timestamp)
        assert parsed.tzinfo is not None


# ─── PerSampleRow JSONL serialization ───────────────────────────────────────


class TestRowSerialization:
    def test_to_dict_round_trip_via_json(self):
        result = _build_result(Verdict.LIKELY_PHISHING)
        row = _row_from_pipeline_result(
            "x.eml", "PHISHING", result, "abc", "permissive",
        )
        d = row.to_dict()
        # Must serialize cleanly with no custom encoders
        encoded = json.dumps(d)
        decoded = json.loads(encoded)
        assert decoded["sample_id"] == "x.eml"
        assert decoded["true_label"] == "PHISHING"
        assert decoded["predicted_label"] == "PHISHING"
        assert decoded["true_positive"] is True

    def test_all_required_fields_present(self):
        """Schema lock — every column the cycle 9 review specified must exist."""
        result = _build_result(Verdict.SUSPICIOUS)
        row = _row_from_pipeline_result(
            "x.eml", "CLEAN", result, "abc", "permissive",
        )
        d = row.to_dict()
        required = {
            "sample_id", "true_label", "predicted_verdict", "predicted_label",
            "overall_score", "overall_confidence", "per_analyzer_scores",
            "calibration_fired", "calibration_cap", "model_id", "commit_sha",
            "timestamp", "true_positive", "false_positive", "true_negative",
            "false_negative", "error",
        }
        missing = required - set(d.keys())
        assert not missing, f"missing fields: {missing}"


# ─── Error rows ─────────────────────────────────────────────────────────────


class TestErrorRow:
    def test_error_row_has_no_tp_fp_tn_fn(self):
        row = _error_row("broken.eml", "PHISHING", "abc", "parse_failed")
        assert row.true_positive is False
        assert row.false_positive is False
        assert row.true_negative is False
        assert row.false_negative is False
        assert row.error == "parse_failed"
        assert row.predicted_verdict == "ERROR"


# ─── Aggregate metrics ──────────────────────────────────────────────────────


class TestAggregateMetrics:
    def _row(self, **flags) -> PerSampleRow:
        defaults = dict(
            sample_id="x", true_label="PHISHING", predicted_verdict="LIKELY_PHISHING",
            predicted_label="PHISHING", overall_score=0.7, overall_confidence=0.8,
            per_analyzer_scores={}, calibration_fired=[], calibration_cap=None,
            model_id="", commit_sha="abc", timestamp="2026-04-15T00:00:00+00:00",
            true_positive=False, false_positive=False, true_negative=False,
            false_negative=False, error=None,
        )
        defaults.update(flags)
        return PerSampleRow(**defaults)

    def test_perfect_classifier(self):
        rows = [
            self._row(true_positive=True),
            self._row(true_positive=True),
            self._row(true_negative=True),
            self._row(true_negative=True),
        ]
        agg = aggregate_rows(rows, "permissive")
        assert agg.true_positive == 2
        assert agg.false_positive == 0
        assert agg.true_negative == 2
        assert agg.false_negative == 0
        assert agg.precision == 1.0
        assert agg.recall == 1.0
        assert agg.f1 == 1.0
        assert agg.accuracy == 1.0

    def test_all_false_negative(self):
        rows = [
            self._row(false_negative=True),
            self._row(false_negative=True),
        ]
        agg = aggregate_rows(rows, "permissive")
        assert agg.recall == 0.0
        assert agg.precision == 0.0  # 0/0 -> 0.0 by convention

    def test_all_false_positive(self):
        rows = [
            self._row(false_positive=True),
            self._row(false_positive=True),
        ]
        agg = aggregate_rows(rows, "permissive")
        assert agg.precision == 0.0  # 0/2

    def test_f1_formula(self):
        # Construct: TP=3, FP=1, FN=2 -> precision=0.75, recall=0.6, f1=0.667
        rows = [
            self._row(true_positive=True),
            self._row(true_positive=True),
            self._row(true_positive=True),
            self._row(false_positive=True),
            self._row(false_negative=True),
            self._row(false_negative=True),
        ]
        agg = aggregate_rows(rows, "permissive")
        assert agg.true_positive == 3
        assert agg.false_positive == 1
        assert agg.false_negative == 2
        assert abs(agg.precision - 0.75) < 0.01
        assert abs(agg.recall - 0.60) < 0.01
        assert abs(agg.f1 - 0.6667) < 0.01

    def test_errors_not_counted_in_confusion_matrix(self):
        rows = [
            self._row(true_positive=True),
            self._row(error="boom"),
            self._row(error="boom"),
        ]
        agg = aggregate_rows(rows, "permissive")
        assert agg.errors == 2
        assert agg.true_positive == 1

    def test_to_dict_serialization(self):
        rows = [self._row(true_positive=True), self._row(true_negative=True)]
        agg = aggregate_rows(rows, "strict")
        d = agg.to_dict()
        assert d["projection"] == "strict"
        assert d["precision"] == 1.0
        assert d["total"] == 2

    def test_empty_rows(self):
        agg = aggregate_rows([], "permissive")
        assert agg.total == 0
        assert agg.precision == 0.0
        assert agg.recall == 0.0
        assert agg.f1 == 0.0


# ─── Invalid inputs ─────────────────────────────────────────────────────────


class TestInvalidInputs:
    @pytest.mark.asyncio
    async def test_run_eval_unknown_projection_raises(self, tmp_path):
        from src.eval.harness import run_eval
        with pytest.raises(ValueError, match="projection"):
            await run_eval(
                corpus_dir=tmp_path,
                labels={},
                projection="invalid",
            )

    @pytest.mark.asyncio
    async def test_run_eval_missing_corpus_raises(self):
        from src.eval.harness import run_eval
        with pytest.raises(FileNotFoundError):
            await run_eval(
                corpus_dir="/path/that/does/not/exist",
                labels={"x.eml": "CLEAN"},
            )
