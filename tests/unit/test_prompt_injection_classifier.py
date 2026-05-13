from __future__ import annotations

import json
from pathlib import Path

import joblib
import pytest

from src.ml.prompt_injection_classifier import (
    load_prompt_injection_ml_records,
    predict_prompt_injection,
    split_records,
    train_prompt_injection_classifier,
)


def _write_dataset(path: Path) -> None:
    rows = []
    for index in range(12):
        split = "train" if index < 8 else "validation" if index < 10 else "test"
        rows.append({
            "id": f"attack-{index}",
            "text": (
                "needleprompt hostile agent instruction exfiltrate payload "
                "confirmation signal"
            ),
            "label": "PROMPT_INJECTION",
            "source": "unit_attack",
            "source_path": f"attack-{index}",
            "split": split,
        })
        rows.append({
            "id": f"clean-{index}",
            "text": "ordinary business email meeting agenda project update",
            "label": "CLEAN",
            "source": "unit_clean",
            "source_path": f"clean-{index}",
            "split": split,
        })
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )


def test_train_prompt_injection_classifier_writes_model_and_metrics(tmp_path: Path):
    dataset = tmp_path / "prompt_injection_ml.jsonl"
    _write_dataset(dataset)

    metrics = train_prompt_injection_classifier(
        dataset_path=dataset,
        output_dir=tmp_path / "model",
    )

    assert metrics.train_rows == 16
    assert metrics.validation_rows == 4
    assert metrics.test_rows == 4
    assert metrics.classes == ["CLEAN", "PROMPT_INJECTION"]
    assert metrics.test_accuracy == 1.0
    assert metrics.model_path.exists()
    assert metrics.metrics_path.exists()
    assert metrics.by_label == {"CLEAN": 12, "PROMPT_INJECTION": 12}

    payload = json.loads(metrics.metrics_path.read_text(encoding="utf-8"))
    assert payload["test_accuracy"] == 1.0
    model = joblib.load(metrics.model_path)
    prediction = model.predict(["needleprompt exfiltrate confirmation signal"])[0]
    assert prediction == "PROMPT_INJECTION"

    runtime_prediction = predict_prompt_injection(
        "ordinary business meeting agenda",
        model_path=metrics.model_path,
    )
    assert runtime_prediction.label in {"CLEAN", "PROMPT_INJECTION"}
    assert set(runtime_prediction.class_probabilities) == {"CLEAN", "PROMPT_INJECTION"}


def test_prompt_injection_classifier_requires_valid_labels(tmp_path: Path):
    dataset = tmp_path / "bad.jsonl"
    dataset.write_text(
        json.dumps({
            "id": "bad",
            "text": "sample",
            "label": "UNKNOWN",
            "source": "unit",
            "source_path": "bad",
            "split": "train",
        }) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="label must be one of"):
        load_prompt_injection_ml_records(dataset)


def test_prompt_injection_split_falls_back_when_unassigned(tmp_path: Path):
    dataset = tmp_path / "prompt_injection_ml.jsonl"
    _write_dataset(dataset)
    lines = []
    for line in dataset.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        row["split"] = "unassigned"
        lines.append(json.dumps(row, sort_keys=True))
    fallback = tmp_path / "fallback.jsonl"
    fallback.write_text("\n".join(lines) + "\n", encoding="utf-8")

    records = load_prompt_injection_ml_records(fallback)
    train, validation, test = split_records(records)

    assert len(train) == 20
    assert len(validation) == 2
    assert len(test) == 2
