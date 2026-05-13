from __future__ import annotations

import csv
import json
from email.message import EmailMessage
from pathlib import Path

import joblib
import pytest

from src.ml.phishing_classifier import load_phishing_ml_records, train_phishing_classifier


def _write_eml(path: Path, subject: str, body: str, sender: str = "sender@example.com") -> None:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = "analyst@example.com"
    message["Subject"] = subject
    message.set_content(body)
    path.write_bytes(message.as_bytes())


def _write_corpus(corpus: Path, count_per_class: int = 10) -> None:
    corpus.mkdir(parents=True, exist_ok=True)
    rows = []
    for index in range(count_per_class):
        clean_name = f"clean_{index:03d}.eml"
        _write_eml(
            corpus / clean_name,
            f"Team update {index}",
            "The project notes and meeting agenda are attached for normal review.",
        )
        rows.append(
            {
                "filename": clean_name,
                "label": "CLEAN",
                "source_corpus": "unit_clean",
                "source_path": clean_name,
                "sha256": "clean",
                "size_bytes": "100",
            }
        )

        phish_name = f"phish_{index:03d}.eml"
        _write_eml(
            corpus / phish_name,
            f"Urgent password reset {index}",
            "Your mailbox will be closed. Verify your password at the secure portal now.",
            sender="security-alert@example.net",
        )
        rows.append(
            {
                "filename": phish_name,
                "label": "PHISHING",
                "source_corpus": "unit_phish",
                "source_path": phish_name,
                "sha256": "phish",
                "size_bytes": "100",
            }
        )

    with (corpus / "labels.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["filename", "label", "source_corpus", "source_path", "sha256", "size_bytes"],
        )
        writer.writeheader()
        writer.writerows(rows)


def test_train_phishing_classifier_writes_model_and_metrics(tmp_path: Path):
    corpus = tmp_path / "eval_corpus"
    _write_corpus(corpus)

    metrics = train_phishing_classifier(corpus_dir=corpus, output_dir=tmp_path / "model")

    assert metrics.train_rows == 16
    assert metrics.validation_rows == 2
    assert metrics.test_rows == 2
    assert metrics.classes == ["CLEAN", "PHISHING"]
    assert metrics.model_path.exists()
    assert metrics.metrics_path.exists()
    assert metrics.by_source_corpus == {"unit_clean": 10, "unit_phish": 10}

    payload = json.loads(metrics.metrics_path.read_text(encoding="utf-8"))
    assert payload["test_accuracy"] == metrics.test_accuracy
    model = joblib.load(metrics.model_path)
    prediction = model.predict(["verify your password immediately"])[0]
    assert prediction in {"CLEAN", "PHISHING"}


def test_load_phishing_ml_records_requires_valid_labels(tmp_path: Path):
    corpus = tmp_path / "eval_corpus"
    _write_corpus(corpus, count_per_class=1)
    rows = list(csv.DictReader((corpus / "labels.csv").open("r", encoding="utf-8")))
    rows[0]["label"] = "UNKNOWN"
    with (corpus / "labels.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="label must be one of"):
        load_phishing_ml_records(corpus)


def test_load_phishing_ml_records_tolerates_malformed_address_group(tmp_path: Path):
    corpus = tmp_path / "eval_corpus"
    corpus.mkdir(parents=True)
    sample = corpus / "malformed_group.eml"
    sample.write_bytes(
        b"From: Broken Group:;\r\n"
        b"To: analyst@example.com\r\n"
        b"Subject: Odd but readable\r\n"
        b"\r\n"
        b"Please review the attached notes.\r\n"
    )
    with (corpus / "labels.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["filename", "label", "source_corpus", "source_path", "sha256", "size_bytes"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "filename": sample.name,
                "label": "CLEAN",
                "source_corpus": "unit_clean",
                "source_path": sample.name,
                "sha256": "sample",
                "size_bytes": str(sample.stat().st_size),
            }
        )

    records = load_phishing_ml_records(corpus)

    assert records[0].label == "CLEAN"
    assert "Subject: Odd but readable" in records[0].text
    assert "Body:" in records[0].text
