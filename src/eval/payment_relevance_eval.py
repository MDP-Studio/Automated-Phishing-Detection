"""Evaluate PayShield payment relevance routing against labeled samples."""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from src.analyzers.payment_relevance import PaymentRelevanceAnalyzer
from src.eval.payment_dataset import (
    ALLOWED_PAYMENT_RELEVANCE_LABELS,
    DEFAULT_DATASET_DIR,
    LABELS_CSV,
    REPORTS_DIR,
    SAMPLES_DIR,
    validate_dataset,
)
from src.extractors.eml_parser import EMLParser


@dataclass(frozen=True)
class PaymentRelevanceEvalRow:
    filename: str
    expected_label: str
    predicted_label: str
    expected_should_scan: bool
    predicted_should_scan: bool
    label_match: bool
    should_scan_match: bool
    confidence: float
    split: str
    source_type: str
    error: str = ""


@dataclass(frozen=True)
class PaymentRelevanceEvalSummary:
    dataset_dir: Path
    row_count: int
    label_correct: int
    should_scan_correct: int
    false_negatives: int
    false_positives: int
    label_accuracy: float
    should_scan_accuracy: float
    confusion_matrix: dict[str, dict[str, int]]
    rows: list[PaymentRelevanceEvalRow]
    json_path: Optional[Path] = None
    csv_path: Optional[Path] = None
    markdown_path: Optional[Path] = None


def _read_rows(dataset_dir: Path) -> list[dict[str, str]]:
    with (dataset_dir / LABELS_CSV).open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _normalize_label(value: str) -> str:
    return (value or "").strip().lower().replace("-", "_")


def _should_scan(label: str) -> bool:
    return label != "non_payment"


def _matrix(rows: list[PaymentRelevanceEvalRow]) -> dict[str, dict[str, int]]:
    counts: Counter[tuple[str, str]] = Counter(
        (row.expected_label, row.predicted_label) for row in rows
    )
    expected_labels = sorted({row.expected_label for row in rows})
    predicted_labels = sorted({row.predicted_label for row in rows})
    return {
        expected: {
            predicted: counts[(expected, predicted)]
            for predicted in predicted_labels
            if counts[(expected, predicted)] > 0
        }
        for expected in expected_labels
    }


def _markdown(summary: PaymentRelevanceEvalSummary) -> str:
    lines = [
        "# Payment Relevance Eval",
        "",
        f"- Dataset: `{summary.dataset_dir}`",
        f"- Rows: {summary.row_count}",
        f"- Label accuracy: {summary.label_accuracy:.3f}",
        f"- Should-scan accuracy: {summary.should_scan_accuracy:.3f}",
        f"- False negatives: {summary.false_negatives}",
        f"- False positives: {summary.false_positives}",
        "",
        "## Confusion Matrix",
        "",
        "| Expected | Predicted | Count |",
        "|---|---|---:|",
    ]
    for expected, predictions in sorted(summary.confusion_matrix.items()):
        for predicted, count in sorted(predictions.items()):
            lines.append(f"| `{expected}` | `{predicted}` | {count} |")
    lines.extend(["", "## Mismatches", ""])
    mismatches = [row for row in summary.rows if not row.label_match or not row.should_scan_match]
    if not mismatches:
        lines.append("No mismatches.")
    else:
        lines.extend(
            f"- `{row.filename}` expected `{row.expected_label}` got `{row.predicted_label}`"
            for row in mismatches[:50]
        )
    lines.append("")
    return "\n".join(lines)


def _write_reports(
    summary: PaymentRelevanceEvalSummary,
    output_prefix: Path,
) -> PaymentRelevanceEvalSummary:
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = output_prefix.with_suffix(".json")
    csv_path = output_prefix.with_suffix(".csv")
    markdown_path = output_prefix.with_suffix(".md")

    payload = asdict(summary)
    payload["dataset_dir"] = str(summary.dataset_dir)
    payload.pop("json_path", None)
    payload.pop("csv_path", None)
    payload.pop("markdown_path", None)
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "filename",
                "expected_label",
                "predicted_label",
                "expected_should_scan",
                "predicted_should_scan",
                "label_match",
                "should_scan_match",
                "confidence",
                "split",
                "source_type",
                "error",
            ],
        )
        writer.writeheader()
        writer.writerows(asdict(row) for row in summary.rows)

    markdown_path.write_text(_markdown(summary), encoding="utf-8")
    return PaymentRelevanceEvalSummary(
        dataset_dir=summary.dataset_dir,
        row_count=summary.row_count,
        label_correct=summary.label_correct,
        should_scan_correct=summary.should_scan_correct,
        false_negatives=summary.false_negatives,
        false_positives=summary.false_positives,
        label_accuracy=summary.label_accuracy,
        should_scan_accuracy=summary.should_scan_accuracy,
        confusion_matrix=summary.confusion_matrix,
        rows=summary.rows,
        json_path=json_path,
        csv_path=csv_path,
        markdown_path=markdown_path,
    )


async def evaluate_payment_relevance(
    dataset_dir: Path = DEFAULT_DATASET_DIR,
    output_prefix: Optional[Path] = None,
    *,
    split: Optional[str] = None,
    source_type: Optional[str] = None,
) -> PaymentRelevanceEvalSummary:
    dataset_dir = Path(dataset_dir)
    validation = validate_dataset(dataset_dir)
    if validation.errors:
        raise ValueError("dataset validation failed: " + "; ".join(validation.errors))

    dataset_rows = _read_rows(dataset_dir)
    if split:
        dataset_rows = [row for row in dataset_rows if row.get("split") == split]
    if source_type:
        dataset_rows = [row for row in dataset_rows if row.get("source_type") == source_type]

    missing = [row.get("filename", "") for row in dataset_rows if not _normalize_label(row.get("payment_relevance", ""))]
    if missing:
        raise ValueError(
            "payment_relevance labels are missing; run scripts/payment_dataset.py prelabel-relevance "
            "and review the queue first: "
            + ", ".join(missing[:10])
        )

    parser = EMLParser()
    analyzer = PaymentRelevanceAnalyzer()
    eval_rows: list[PaymentRelevanceEvalRow] = []

    for row in dataset_rows:
        filename = row["filename"]
        expected_label = _normalize_label(row.get("payment_relevance", ""))
        if expected_label not in ALLOWED_PAYMENT_RELEVANCE_LABELS:
            raise ValueError(f"invalid payment_relevance for {filename}: {expected_label}")
        expected_should_scan = _should_scan(expected_label)
        sample_path = dataset_dir / SAMPLES_DIR / filename
        try:
            email = parser.parse_file(sample_path)
        except Exception:
            email = None
        if email is None:
            eval_rows.append(
                PaymentRelevanceEvalRow(
                    filename=filename,
                    expected_label=expected_label,
                    predicted_label="ERROR",
                    expected_should_scan=expected_should_scan,
                    predicted_should_scan=True,
                    label_match=False,
                    should_scan_match=False,
                    confidence=0.0,
                    split=row.get("split", ""),
                    source_type=row.get("source_type", ""),
                    error="failed to parse sample",
                )
            )
            continue
        analysis = analyzer.classify(email)
        predicted_label = analysis.label.value
        eval_rows.append(
            PaymentRelevanceEvalRow(
                filename=filename,
                expected_label=expected_label,
                predicted_label=predicted_label,
                expected_should_scan=expected_should_scan,
                predicted_should_scan=analysis.should_scan,
                label_match=predicted_label == expected_label,
                should_scan_match=analysis.should_scan == expected_should_scan,
                confidence=float(analysis.confidence),
                split=row.get("split", ""),
                source_type=row.get("source_type", ""),
            )
        )

    row_count = len(eval_rows)
    label_correct = sum(1 for row in eval_rows if row.label_match)
    should_scan_correct = sum(1 for row in eval_rows if row.should_scan_match)
    false_negatives = sum(
        1 for row in eval_rows
        if row.expected_should_scan and not row.predicted_should_scan
    )
    false_positives = sum(
        1 for row in eval_rows
        if not row.expected_should_scan and row.predicted_should_scan
    )
    summary = PaymentRelevanceEvalSummary(
        dataset_dir=dataset_dir,
        row_count=row_count,
        label_correct=label_correct,
        should_scan_correct=should_scan_correct,
        false_negatives=false_negatives,
        false_positives=false_positives,
        label_accuracy=round(label_correct / row_count, 3) if row_count else 0.0,
        should_scan_accuracy=round(should_scan_correct / row_count, 3) if row_count else 0.0,
        confusion_matrix=_matrix(eval_rows),
        rows=eval_rows,
    )
    output_prefix = output_prefix or (dataset_dir / REPORTS_DIR / "payment_relevance_eval")
    return _write_reports(summary, Path(output_prefix))
