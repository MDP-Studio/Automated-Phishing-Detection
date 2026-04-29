from __future__ import annotations

import json
from pathlib import Path

from src.eval.failure_inspector import build_report, load_jsonl, load_manifest, write_report


def _row(sample_id: str, true_label: str, verdict: str, **extra):
    row = {
        "sample_id": sample_id,
        "true_label": true_label,
        "predicted_verdict": verdict,
        "overall_score": 0.5,
        "overall_confidence": 0.7,
        "per_analyzer_scores": {
            "domain_intelligence": {"risk_score": 0.8, "confidence": 0.5},
            "nlp_intent": {"risk_score": 0.4, "confidence": 0.9},
        },
        "calibration_fired": [],
        "calibration_cap": None,
        "error": None,
    }
    row.update(extra)
    return row


def test_build_report_counts_permissive_failures():
    rows = [
        _row("tp.eml", "PHISHING", "SUSPICIOUS"),
        _row("fp.eml", "CLEAN", "SUSPICIOUS"),
        _row("tn.eml", "CLEAN", "CLEAN"),
        _row("fn.eml", "PHISHING", "CLEAN"),
        _row("err.eml", "PHISHING", "ERROR", error="parse_failed"),
    ]

    report = build_report(rows, projection="permissive")

    assert report.summary["true_positive"] == 1
    assert report.summary["false_positive"] == 1
    assert report.summary["true_negative"] == 1
    assert report.summary["false_negative"] == 1
    assert report.summary["errors"] == 1
    assert [row.failure_type for row in report.failures] == ["FP", "FN", "ERROR"]
    assert report.failures[0].top_analyzers[0]["analyzer"] == "domain_intelligence"


def test_strict_projection_turns_suspicious_phishing_into_fn():
    rows = [_row("phish.eml", "PHISHING", "SUSPICIOUS")]

    report = build_report(rows, projection="strict")

    assert report.summary["false_negative"] == 1
    assert report.failures[0].suggested_action.startswith("Strict recall candidate")


def test_write_report_outputs_json_csv_and_markdown(tmp_path: Path):
    manifest_path = tmp_path / "manifest.jsonl"
    manifest_path.write_text(
        json.dumps(
            {
                "filename": "fp.eml",
                "source_corpus": "enron_ham",
                "source_path": "enron/alice/sent/1",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    report = build_report(
        [_row("fp.eml", "CLEAN", "SUSPICIOUS")],
        manifest=load_manifest(manifest_path),
    )

    json_path, csv_path, md_path = write_report(report, tmp_path / "failures")

    assert json_path.exists()
    assert csv_path.exists()
    assert md_path.exists()
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["failures"][0]["source_corpus"] == "enron_ham"
    assert "Eval Failure Report" in md_path.read_text(encoding="utf-8")


def test_load_jsonl_skips_blank_lines(tmp_path: Path):
    path = tmp_path / "rows.jsonl"
    path.write_text('{"sample_id": "x"}\n\n', encoding="utf-8")

    assert load_jsonl(path) == [{"sample_id": "x"}]
