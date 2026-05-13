"""Train and use a shared prompt-injection classifier.

This model is a hostile-input detector, not a PhishAnalyze verdict model and
not a PayShield payment-decision model.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.pipeline import Pipeline

from src.eval.prompt_injection_dataset import (
    ALLOWED_LABELS,
    ATTACK_LABEL,
    CLEAN_LABEL,
    DEFAULT_OUTPUT_JSONL,
)


DEFAULT_MODEL_DIR = Path(__file__).resolve().parents[2] / "models" / "prompt_injection_classifier"


@dataclass(frozen=True)
class PromptInjectionMLRecord:
    id: str
    text: str
    label: str
    source: str
    source_path: str
    split: str


@dataclass(frozen=True)
class PromptInjectionMLMetrics:
    model_path: Path
    metrics_path: Path
    dataset_path: Path
    train_rows: int
    validation_rows: int
    test_rows: int
    classes: list[str]
    test_accuracy: float
    confusion_matrix: dict[str, dict[str, int]]
    classification_report: dict
    by_label: dict[str, int]
    by_source: dict[str, int]
    by_split: dict[str, int]


@dataclass(frozen=True)
class PromptInjectionMLPrediction:
    label: str
    confidence: float
    class_probabilities: dict[str, float]


def load_prompt_injection_ml_records(path: Path = DEFAULT_OUTPUT_JSONL) -> list[PromptInjectionMLRecord]:
    records: list[PromptInjectionMLRecord] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            label = row.get("label", "")
            if label not in ALLOWED_LABELS:
                raise ValueError(f"label must be one of {sorted(ALLOWED_LABELS)}, got {label!r}")
            records.append(
                PromptInjectionMLRecord(
                    id=str(row.get("id") or ""),
                    text=str(row.get("text") or ""),
                    label=label,
                    source=str(row.get("source") or ""),
                    source_path=str(row.get("source_path") or ""),
                    split=str(row.get("split") or "unassigned"),
                )
            )
    return records


def _records_for_split(records: list[PromptInjectionMLRecord], split: str) -> list[PromptInjectionMLRecord]:
    return [record for record in records if record.split == split]


def _fallback_split(
    records: list[PromptInjectionMLRecord],
) -> tuple[list[PromptInjectionMLRecord], list[PromptInjectionMLRecord], list[PromptInjectionMLRecord]]:
    ordered = sorted(records, key=lambda record: record.id)
    train: list[PromptInjectionMLRecord] = []
    validation: list[PromptInjectionMLRecord] = []
    test: list[PromptInjectionMLRecord] = []
    by_class: dict[str, list[PromptInjectionMLRecord]] = {}
    for record in ordered:
        by_class.setdefault(record.label, []).append(record)
    for class_records in by_class.values():
        total = len(class_records)
        for index, record in enumerate(class_records):
            ratio = index / max(total, 1)
            if ratio < 0.8:
                train.append(record)
            elif ratio < 0.9:
                validation.append(record)
            else:
                test.append(record)
    return train, validation, test


def split_records(
    records: list[PromptInjectionMLRecord],
) -> tuple[list[PromptInjectionMLRecord], list[PromptInjectionMLRecord], list[PromptInjectionMLRecord]]:
    train = _records_for_split(records, "train")
    validation = _records_for_split(records, "validation")
    test = _records_for_split(records, "test")
    if train and test:
        return train, validation, test
    return _fallback_split(records)


def _build_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    ngram_range=(1, 2),
                    min_df=1,
                    max_features=30000,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]
    )


def _confusion_as_dict(classes: list[str], expected: list[str], predicted: list[str]) -> dict[str, dict[str, int]]:
    matrix = confusion_matrix(expected, predicted, labels=classes)
    result: dict[str, dict[str, int]] = {}
    for row_index, expected_label in enumerate(classes):
        row = {}
        for col_index, predicted_label in enumerate(classes):
            count = int(matrix[row_index][col_index])
            if count:
                row[predicted_label] = count
        result[expected_label] = row
    return result


def predict_prompt_injection(
    text: str,
    *,
    model_path: Path = DEFAULT_MODEL_DIR / "prompt_injection_model.joblib",
) -> PromptInjectionMLPrediction:
    model = joblib.load(model_path)
    prediction = str(model.predict([text])[0])
    probabilities: dict[str, float] = {}
    if hasattr(model, "predict_proba"):
        classes = [str(item) for item in model.classes_]
        values = model.predict_proba([text])[0]
        probabilities = {
            label: round(float(probability), 3)
            for label, probability in zip(classes, values)
        }
    confidence = probabilities.get(prediction, 0.0) if probabilities else 0.0
    return PromptInjectionMLPrediction(
        label=prediction,
        confidence=round(float(confidence), 3),
        class_probabilities=probabilities,
    )


def train_prompt_injection_classifier(
    dataset_path: Path = DEFAULT_OUTPUT_JSONL,
    output_dir: Path = DEFAULT_MODEL_DIR,
) -> PromptInjectionMLMetrics:
    dataset_path = Path(dataset_path)
    output_dir = Path(output_dir)
    records = load_prompt_injection_ml_records(dataset_path)
    if not records:
        raise ValueError("prompt-injection ML dataset has no rows")

    train, validation, test = split_records(records)
    if not train or not test:
        raise ValueError("prompt-injection ML dataset needs train and test rows")

    y_train = [record.label for record in train]
    y_test = [record.label for record in test]
    class_counts = Counter(y_train)
    if len(class_counts) < 2:
        raise ValueError(f"training split needs at least two classes, got {dict(class_counts)}")

    model = _build_pipeline()
    model.fit([record.text for record in train], y_train)
    predicted = model.predict([record.text for record in test]).tolist()
    classes = sorted(set(y_train) | set(y_test) | set(predicted))

    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "prompt_injection_model.joblib"
    metrics_path = output_dir / "prompt_injection_metrics.json"
    joblib.dump(model, model_path)

    metrics = PromptInjectionMLMetrics(
        model_path=model_path,
        metrics_path=metrics_path,
        dataset_path=dataset_path,
        train_rows=len(train),
        validation_rows=len(validation),
        test_rows=len(test),
        classes=classes,
        test_accuracy=round(float(accuracy_score(y_test, predicted)), 3),
        confusion_matrix=_confusion_as_dict(classes, y_test, predicted),
        classification_report=classification_report(
            y_test,
            predicted,
            labels=classes,
            output_dict=True,
            zero_division=0,
        ),
        by_label=dict(sorted(Counter(record.label for record in records).items())),
        by_source=dict(sorted(Counter(record.source for record in records).items())),
        by_split=dict(sorted(Counter(record.split for record in records).items())),
    )
    payload = asdict(metrics)
    payload["model_path"] = str(metrics.model_path)
    payload["metrics_path"] = str(metrics.metrics_path)
    payload["dataset_path"] = str(metrics.dataset_path)
    metrics_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metrics


__all__ = [
    "ATTACK_LABEL",
    "CLEAN_LABEL",
    "DEFAULT_MODEL_DIR",
    "PromptInjectionMLMetrics",
    "PromptInjectionMLPrediction",
    "PromptInjectionMLRecord",
    "load_prompt_injection_ml_records",
    "predict_prompt_injection",
    "split_records",
    "train_prompt_injection_classifier",
]
