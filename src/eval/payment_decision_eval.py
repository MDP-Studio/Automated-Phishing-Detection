"""
Evaluate payment-fraud business decisions against the payment dataset.

The generic eval harness answers PHISHING vs CLEAN. This module answers the
SME workflow question: did the analyzer choose SAFE, VERIFY, or DO_NOT_PAY?
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from src.analyzers.payment_fraud import PaymentFraudAnalyzer
from src.eval.payment_dataset import DEFAULT_DATASET_DIR, LABELS_CSV, REPORTS_DIR, SAMPLES_DIR, validate_dataset
from src.extractors.eml_parser import EMLParser


@dataclass(frozen=True)
class PaymentDecisionEvalRow:
    filename: str
    label: str
    scenario: str
    split: str
    expected_decision: str
    predicted_decision: str
    match: bool
    risk_score: float
    confidence: float
    signals: list[str]
    error: str = ""


@dataclass(frozen=True)
class PaymentDecisionEvalSummary:
    dataset_dir: Path
    row_count: int
    correct: int
    mismatches: int
    accuracy: float
    confusion_matrix: dict[str, dict[str, int]]
    rows: list[PaymentDecisionEvalRow]
    json_path: Optional[Path] = None
    csv_path: Optional[Path] = None
    markdown_path: Optional[Path] = None


def _read_dataset_rows(dataset_dir: Path) -> list[dict[str, str]]:
    with (dataset_dir / LABELS_CSV).open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _matrix(rows: list[PaymentDecisionEvalRow]) -> dict[str, dict[str, int]]:
    counts: Counter[tuple[str, str]] = Counter(
        (row.expected_decision, row.predicted_decision) for row in rows
    )
    expected_labels = sorted({row.expected_decision for row in rows})
    predicted_labels = sorted({row.predicted_decision for row in rows})
    return {
        expected: {
            predicted: counts[(expected, predicted)]
            for predicted in predicted_labels
            if counts[(expected, predicted)] > 0
        }
        for expected in expected_labels
    }


def _markdown(summary: PaymentDecisionEvalSummary) -> str:
    lines = [
        "# Payment Decision Eval",
        "",
        f"- Dataset: `{summary.dataset_dir}`",
        f"- Rows: {summary.row_count}",
        f"- Correct: {summary.correct}",
        f"- Mismatches: {summary.mismatches}",
        f"- Accuracy: {summary.accuracy:.3f}",
        "",
        "## Confusion Matrix",
        "",
        "| Expected | Predicted | Count |",
        "|---|---|---:|",
    ]
    for expected, predictions in sorted(summary.confusion_matrix.items()):
        for predicted, count in sorted(predictions.items()):
            lines.append(f"| {expected} | {predicted} | {count} |")

    mismatches = [row for row in summary.rows if not row.match]
    lines.extend(["", "## Mismatches", ""])
    if not mismatches:
        lines.append("No mismatches.")
    else:
        lines.extend([
            "| Filename | Scenario | Split | Expected | Predicted | Risk | Confidence | Signals | Error |",
            "|---|---|---|---|---|---:|---:|---|---|",
        ])
        for row in mismatches:
            signals = ", ".join(row.signals[:5])
            lines.append(
                f"| {row.filename} | {row.scenario} | {row.split} | "
                f"{row.expected_decision} | {row.predicted_decision} | "
                f"{row.risk_score:.3f} | {row.confidence:.3f} | {signals} | {row.error} |"
            )

    return "\n".join(lines) + "\n"


def _write_reports(summary: PaymentDecisionEvalSummary, output_prefix: Path) -> PaymentDecisionEvalSummary:
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = output_prefix.with_suffix(".json")
    csv_path = output_prefix.with_suffix(".csv")
    markdown_path = output_prefix.with_suffix(".md")

    payload = {
        "dataset_dir": str(summary.dataset_dir),
        "row_count": summary.row_count,
        "correct": summary.correct,
        "mismatches": summary.mismatches,
        "accuracy": summary.accuracy,
        "confusion_matrix": summary.confusion_matrix,
        "rows": [asdict(row) for row in summary.rows],
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        fieldnames = [
            "filename",
            "label",
            "scenario",
            "split",
            "expected_decision",
            "predicted_decision",
            "match",
            "risk_score",
            "confidence",
            "signals",
            "error",
        ]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in summary.rows:
            record = asdict(row)
            record["signals"] = ",".join(row.signals)
            writer.writerow(record)

    markdown_path.write_text(_markdown(summary), encoding="utf-8")

    return PaymentDecisionEvalSummary(
        dataset_dir=summary.dataset_dir,
        row_count=summary.row_count,
        correct=summary.correct,
        mismatches=summary.mismatches,
        accuracy=summary.accuracy,
        confusion_matrix=summary.confusion_matrix,
        rows=summary.rows,
        json_path=json_path,
        csv_path=csv_path,
        markdown_path=markdown_path,
    )


async def evaluate_payment_decisions(
    dataset_dir: Path = DEFAULT_DATASET_DIR,
    output_prefix: Optional[Path] = None,
) -> PaymentDecisionEvalSummary:
    dataset_dir = Path(dataset_dir)
    validation = validate_dataset(dataset_dir)
    if not validation.ok:
        raise ValueError("dataset validation failed: " + "; ".join(validation.errors))

    parser = EMLParser()
    analyzer = PaymentFraudAnalyzer()
    eval_rows: list[PaymentDecisionEvalRow] = []

    for row in _read_dataset_rows(dataset_dir):
        filename = row["filename"]
        expected = row["payment_decision"]
        sample_path = dataset_dir / SAMPLES_DIR / filename
        email = parser.parse_file(sample_path)
        if email is None:
            eval_rows.append(
                PaymentDecisionEvalRow(
                    filename=filename,
                    label=row["label"],
                    scenario=row["scenario"],
                    split=row["split"],
                    expected_decision=expected,
                    predicted_decision="ERROR",
                    match=False,
                    risk_score=0.0,
                    confidence=0.0,
                    signals=[],
                    error="failed to parse sample",
                )
            )
            continue

        result = await analyzer.analyze(email)
        details = result.details or {}
        predicted = str(details.get("decision", "ERROR"))
        signals = [
            str(signal.get("name", "unknown"))
            for signal in details.get("signals", [])
            if isinstance(signal, dict)
        ]
        eval_rows.append(
            PaymentDecisionEvalRow(
                filename=filename,
                label=row["label"],
                scenario=row["scenario"],
                split=row["split"],
                expected_decision=expected,
                predicted_decision=predicted,
                match=predicted == expected,
                risk_score=float(result.risk_score or 0.0),
                confidence=float(result.confidence or 0.0),
                signals=signals,
                error="; ".join(result.errors or []),
            )
        )

    correct = sum(1 for row in eval_rows if row.match)
    row_count = len(eval_rows)
    summary = PaymentDecisionEvalSummary(
        dataset_dir=dataset_dir,
        row_count=row_count,
        correct=correct,
        mismatches=row_count - correct,
        accuracy=round(correct / row_count, 3) if row_count else 0.0,
        confusion_matrix=_matrix(eval_rows),
        rows=eval_rows,
    )

    output_prefix = output_prefix or (dataset_dir / REPORTS_DIR / "payment_decision_eval")
    return _write_reports(summary, Path(output_prefix))
