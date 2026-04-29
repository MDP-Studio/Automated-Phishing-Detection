from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from src.eval.payment_dataset import add_sample, init_dataset, seed_synthetic_bank_change_dataset
from src.eval.payment_decision_eval import evaluate_payment_decisions


def _write_eml(path: Path, subject: str, body: str) -> Path:
    path.write_text(
        "\n".join(
            [
                "From: accounts@supplier.example",
                "To: ap@example.com",
                f"Subject: {subject}",
                "",
                body,
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.asyncio
async def test_payment_decision_eval_writes_reports_for_seed_dataset(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset_seed"
    seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=4,
        legit_count=4,
        seed=1337,
        clean=True,
    )

    summary = await evaluate_payment_decisions(dataset)

    assert summary.row_count == 8
    assert summary.correct == 8
    assert summary.mismatches == 0
    assert summary.accuracy == 1.0
    assert summary.confusion_matrix == {
        "DO_NOT_PAY": {"DO_NOT_PAY": 4},
        "VERIFY": {"VERIFY": 4},
    }
    assert summary.json_path and summary.json_path.exists()
    assert summary.csv_path and summary.csv_path.exists()
    assert summary.markdown_path and summary.markdown_path.exists()

    payload = json.loads(summary.json_path.read_text(encoding="utf-8"))
    assert payload["accuracy"] == 1.0
    assert len(payload["rows"]) == 8

    with summary.csv_path.open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 8
    assert "No mismatches." in summary.markdown_path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_payment_decision_eval_reports_mismatch(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment")
    sample = _write_eml(
        tmp_path / "non_payment.eml",
        subject="Team meeting",
        body="Reminder for the planning meeting tomorrow.",
    )
    add_sample(
        dataset_dir=dataset,
        source=sample,
        label="PAYMENT_SCAM",
        payment_decision="DO_NOT_PAY",
        scenario="bank_detail_change",
        source_type="synthetic",
        split="test",
        contains_real_pii="no",
    )

    summary = await evaluate_payment_decisions(dataset)

    assert summary.row_count == 1
    assert summary.correct == 0
    assert summary.mismatches == 1
    assert summary.confusion_matrix == {"DO_NOT_PAY": {"SAFE": 1}}
    assert summary.rows[0].predicted_decision == "SAFE"
