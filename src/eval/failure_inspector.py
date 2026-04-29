"""
Inspect eval JSONL output for false positives, false negatives, and errors.

This is intentionally separate from metric generation. Metrics answer "how
many"; this module answers "which samples and which analyzers should I look at
next".
"""
from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional


PHISHING_VERDICTS = {
    "permissive": {"SUSPICIOUS", "LIKELY_PHISHING", "CONFIRMED_PHISHING"},
    "strict": {"LIKELY_PHISHING", "CONFIRMED_PHISHING"},
}


@dataclass(frozen=True)
class FailureRow:
    sample_id: str
    failure_type: str
    true_label: str
    predicted_verdict: str
    predicted_label: str
    overall_score: float
    overall_confidence: float
    top_analyzers: list[dict[str, Any]]
    calibration_fired: list[str]
    calibration_cap: Optional[str]
    source_corpus: str
    source_path: str
    error: Optional[str]
    suggested_action: str


@dataclass(frozen=True)
class FailureReport:
    projection: str
    summary: dict[str, Any]
    failures: list[FailureRow]


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped:
                rows.append(json.loads(stripped))
    return rows


def load_manifest(path: Optional[Path]) -> dict[str, dict[str, Any]]:
    if path is None or not path.exists():
        return {}
    return {row["filename"]: row for row in load_jsonl(path)}


def project_verdict(verdict: str, projection: str) -> str:
    if projection not in PHISHING_VERDICTS:
        raise ValueError(f"unknown projection: {projection}")
    return "PHISHING" if verdict in PHISHING_VERDICTS[projection] else "CLEAN"


def classify_row(row: dict[str, Any], projection: str) -> tuple[str, str]:
    if row.get("error"):
        return "ERROR", "ERROR"

    true_label = row.get("true_label", "")
    predicted_label = project_verdict(row.get("predicted_verdict", ""), projection)

    if true_label == "PHISHING" and predicted_label == "PHISHING":
        return "TP", predicted_label
    if true_label == "CLEAN" and predicted_label == "PHISHING":
        return "FP", predicted_label
    if true_label == "CLEAN" and predicted_label == "CLEAN":
        return "TN", predicted_label
    if true_label == "PHISHING" and predicted_label == "CLEAN":
        return "FN", predicted_label
    return "UNKNOWN", predicted_label


def top_analyzers(row: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
    analyzer_scores = row.get("per_analyzer_scores") or {}
    ranked = []
    for name, scores in analyzer_scores.items():
        risk = float(scores.get("risk_score", 0.0) or 0.0)
        confidence = float(scores.get("confidence", 0.0) or 0.0)
        ranked.append(
            {
                "analyzer": name,
                "risk_score": round(risk, 4),
                "confidence": round(confidence, 4),
                "signal_strength": round(risk * confidence, 4),
            }
        )
    return sorted(ranked, key=lambda item: item["signal_strength"], reverse=True)[:limit]


def suggested_action(failure_type: str, row: dict[str, Any], top: list[dict[str, Any]]) -> str:
    if failure_type == "ERROR":
        return "Fix parser or analyzer exception first; this sample did not produce a usable verdict."

    analyzer_names = {item["analyzer"] for item in top[:3]}
    verdict = row.get("predicted_verdict", "")
    score = float(row.get("overall_score", 0.0) or 0.0)
    confidence = float(row.get("overall_confidence", 0.0) or 0.0)

    if failure_type == "FN" and verdict == "SUSPICIOUS":
        return "Strict recall candidate: multiple signals may be present but the verdict is capped below LIKELY_PHISHING."
    if failure_type == "FN" and confidence < 0.45:
        return "Low-confidence miss: inspect missing API coverage, parser output, and confidence capping."
    if failure_type == "FP" and {"domain_intelligence", "url_detonation"} & analyzer_names:
        return "Likely URL/domain false positive: inspect stale links, newsletter links, dead domains, and API error handling."
    if failure_type == "FP" and "sender_profiling" in analyzer_names:
        return "Sender-profile false positive candidate: inspect cold-start behavior or sender history assumptions."
    if failure_type == "FP" and score < 0.45:
        return "Borderline false positive: threshold or calibration rule may be too aggressive."
    return "Inspect top analyzer evidence and compare against the manifest source corpus."


def build_report(
    rows: list[dict[str, Any]],
    projection: str = "permissive",
    manifest: Optional[dict[str, dict[str, Any]]] = None,
    include_passed: bool = False,
    top_limit: int = 5,
) -> FailureReport:
    manifest = manifest or {}
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0, "UNKNOWN": 0}
    failures: list[FailureRow] = []

    for row in rows:
        failure_type, predicted_label = classify_row(row, projection)
        counts[failure_type] = counts.get(failure_type, 0) + 1
        if failure_type in {"TP", "TN"} and not include_passed:
            continue

        sample_id = row.get("sample_id", "")
        source = manifest.get(sample_id, {})
        top = top_analyzers(row, limit=top_limit)
        failures.append(
            FailureRow(
                sample_id=sample_id,
                failure_type=failure_type,
                true_label=row.get("true_label", ""),
                predicted_verdict=row.get("predicted_verdict", ""),
                predicted_label=predicted_label,
                overall_score=float(row.get("overall_score", 0.0) or 0.0),
                overall_confidence=float(row.get("overall_confidence", 0.0) or 0.0),
                top_analyzers=top,
                calibration_fired=list(row.get("calibration_fired") or []),
                calibration_cap=row.get("calibration_cap"),
                source_corpus=source.get("source_corpus", ""),
                source_path=source.get("source_path", ""),
                error=row.get("error"),
                suggested_action=suggested_action(failure_type, row, top),
            )
        )

    tp = counts["TP"]
    fp = counts["FP"]
    tn = counts["TN"]
    fn = counts["FN"]
    errors = counts["ERROR"]
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (len(rows) - errors) if len(rows) != errors else 0.0

    summary = {
        "projection": projection,
        "total": len(rows),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "errors": errors,
        "failure_count": fp + fn + errors,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }
    return FailureReport(projection=projection, summary=summary, failures=failures)


def write_report(report: FailureReport, output_prefix: Path) -> tuple[Path, Path, Path]:
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = output_prefix.with_suffix(".json")
    csv_path = output_prefix.with_suffix(".csv")
    md_path = output_prefix.with_suffix(".md")

    json_payload = {
        "projection": report.projection,
        "summary": report.summary,
        "failures": [asdict(row) for row in report.failures],
    }
    json_path.write_text(json.dumps(json_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        fieldnames = [
            "sample_id",
            "failure_type",
            "true_label",
            "predicted_verdict",
            "predicted_label",
            "overall_score",
            "overall_confidence",
            "top_analyzers",
            "calibration_fired",
            "source_corpus",
            "source_path",
            "suggested_action",
            "error",
        ]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in report.failures:
            writer.writerow(
                {
                    "sample_id": row.sample_id,
                    "failure_type": row.failure_type,
                    "true_label": row.true_label,
                    "predicted_verdict": row.predicted_verdict,
                    "predicted_label": row.predicted_label,
                    "overall_score": row.overall_score,
                    "overall_confidence": row.overall_confidence,
                    "top_analyzers": "; ".join(
                        f"{a['analyzer']}={a['signal_strength']}" for a in row.top_analyzers
                    ),
                    "calibration_fired": "; ".join(row.calibration_fired),
                    "source_corpus": row.source_corpus,
                    "source_path": row.source_path,
                    "suggested_action": row.suggested_action,
                    "error": row.error,
                }
            )

    md_path.write_text(format_markdown(report), encoding="utf-8")
    return json_path, csv_path, md_path


def format_markdown(report: FailureReport) -> str:
    lines = [
        f"# Eval Failure Report ({report.projection})",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for key, value in report.summary.items():
        lines.append(f"| {key} | {value} |")

    lines.extend(["", "## Rows", ""])
    if not report.failures:
        lines.append("No failures found for this projection.")
        lines.append("")
        return "\n".join(lines)

    lines.append("| Type | Sample | Verdict | Score | Confidence | Top analyzers | Source | Suggested action |")
    lines.append("|---|---|---|---:|---:|---|---|---|")
    for row in report.failures:
        analyzers = ", ".join(
            f"{item['analyzer']} {item['signal_strength']}" for item in row.top_analyzers[:3]
        )
        source = row.source_corpus or row.source_path or ""
        lines.append(
            "| "
            + " | ".join(
                [
                    row.failure_type,
                    row.sample_id,
                    row.predicted_verdict,
                    f"{row.overall_score:.4f}",
                    f"{row.overall_confidence:.4f}",
                    analyzers,
                    source,
                    row.suggested_action,
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect eval JSONL output and write FP/FN/error reports.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--results", type=Path, required=True, help="Eval JSONL file from scripts/run_eval.py")
    parser.add_argument("--manifest", type=Path, default=None, help="Optional corpus manifest.jsonl")
    parser.add_argument("--output", type=Path, required=True, help="Output prefix for .json/.csv/.md reports")
    parser.add_argument("--projection", choices=sorted(PHISHING_VERDICTS), default="permissive")
    parser.add_argument("--include-passed", action="store_true", help="Include TP/TN rows in the report")
    parser.add_argument("--top", type=int, default=5, help="Number of top analyzers to include per row")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    rows = load_jsonl(args.results)
    manifest = load_manifest(args.manifest)
    report = build_report(
        rows,
        projection=args.projection,
        manifest=manifest,
        include_passed=args.include_passed,
        top_limit=args.top,
    )
    json_path, csv_path, md_path = write_report(report, args.output)

    print(f"Projection: {report.projection}")
    print(f"Rows: {report.summary['total']}")
    print(f"Failures: {report.summary['failure_count']}")
    print(f"  FP={report.summary['false_positive']} FN={report.summary['false_negative']} ERR={report.summary['errors']}")
    print(f"JSON: {json_path}")
    print(f"CSV:  {csv_path}")
    print(f"MD:   {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
