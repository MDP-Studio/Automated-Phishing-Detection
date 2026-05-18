from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

import pytest

from src.eval.payment_dataset import add_sample, init_dataset
from src.eval.payment_relevance_eval import evaluate_payment_relevance


def _write_mail(path: Path, subject: str, body: str) -> Path:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "ap@example.com"
    msg["Subject"] = subject
    msg.set_content(body)
    path.write_bytes(msg.as_bytes())
    return path


@pytest.mark.asyncio
async def test_payment_relevance_eval_reports_skip_metrics(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment_scam_dataset_seed")
    invoice = _write_mail(
        tmp_path / "invoice.eml",
        "Invoice INV-100",
        "Invoice INV-100 is due for AUD $500.00.",
    )
    non_payment = _write_mail(
        tmp_path / "planning.eml",
        "Planning notes",
        "Please bring quarterly roadmap notes to the planning session tomorrow.",
    )
    add_sample(
        dataset_dir=dataset,
        source=invoice,
        label="LEGITIMATE_PAYMENT",
        payment_decision="SAFE",
        payment_relevance="invoice",
        scenario="legitimate_invoice",
        source_type="synthetic",
        split="train",
        contains_real_pii="no",
    )
    add_sample(
        dataset_dir=dataset,
        source=non_payment,
        label="NON_PAYMENT",
        payment_decision="NOT_PAYMENT_SPECIFIC",
        payment_relevance="non_payment",
        scenario="non_payment",
        source_type="synthetic",
        split="test",
        contains_real_pii="no",
    )

    summary = await evaluate_payment_relevance(dataset)

    assert summary.row_count == 2
    assert summary.false_negatives == 0
    assert summary.false_positives == 0
    assert summary.should_scan_accuracy == 1.0
    assert summary.json_path and summary.json_path.exists()
    assert summary.csv_path and summary.csv_path.exists()
    assert summary.markdown_path and summary.markdown_path.exists()


@pytest.mark.asyncio
async def test_payment_relevance_eval_requires_labels(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment_scam_dataset_seed")
    sample = _write_mail(
        tmp_path / "invoice.eml",
        "Invoice INV-100",
        "Invoice INV-100 is due for AUD $500.00.",
    )
    add_sample(
        dataset_dir=dataset,
        source=sample,
        label="LEGITIMATE_PAYMENT",
        payment_decision="SAFE",
        scenario="legitimate_invoice",
        source_type="synthetic",
        split="train",
        contains_real_pii="no",
    )

    with pytest.raises(ValueError, match="prelabel-relevance"):
        await evaluate_payment_relevance(dataset)
