"""Unit tests for PayShield payment relevance routing."""

from datetime import datetime, timezone

import pytest

from src.analyzers.payment_relevance import PaymentRelevanceAnalyzer
from src.models import AttachmentObject, EmailObject


def make_email(
    subject: str,
    body: str,
    attachments: list[AttachmentObject] | None = None,
) -> EmailObject:
    return EmailObject(
        email_id="relevance_test",
        raw_headers={
            "from": ["sender@example.com"],
            "to": ["ap@example.com"],
            "subject": [subject],
            "date": ["Mon, 08 Mar 2026 10:00:00 +0000"],
            "message-id": ["<relevance@example.com>"],
        },
        from_address="sender@example.com",
        from_display_name="Sender",
        reply_to=None,
        to_addresses=["ap@example.com"],
        cc_addresses=[],
        subject=subject,
        body_plain=body,
        body_html="",
        date=datetime(2026, 3, 8, 10, 0, 0, tzinfo=timezone.utc),
        attachments=attachments or [],
        inline_images=[],
        message_id="relevance@example.com",
        received_chain=[],
    )


@pytest.mark.asyncio
async def test_invoice_attachment_is_payment_relevant():
    analyzer = PaymentRelevanceAnalyzer()
    email = make_email(
        "April statement",
        "Please process the attached document. Amount due AUD $880.00.",
        attachments=[
            AttachmentObject(
                filename="invoice-221.pdf",
                content_type="application/pdf",
                magic_type="application/pdf",
                size_bytes=1234,
                content=b"%PDF",
                is_archive=False,
                has_macros=False,
            )
        ],
    )

    result = await analyzer.analyze(email)

    assert result.details["label"] == "invoice"
    assert result.details["should_scan"] is True
    assert result.confidence >= 0.8


@pytest.mark.asyncio
async def test_invoice_shorthand_is_payment_relevant():
    analyzer = PaymentRelevanceAnalyzer()
    email = make_email(
        "INV-221 ready",
        "Amount due AUD $880.00 under PO-44.",
    )

    result = await analyzer.analyze(email)

    assert result.details["label"] == "invoice"
    assert result.details["should_scan"] is True


@pytest.mark.asyncio
async def test_bank_detail_change_is_payment_relevant():
    analyzer = PaymentRelevanceAnalyzer()
    email = make_email(
        "Supplier payment update",
        "Our bank account has changed. Use the new account details for the next remittance.",
    )

    result = await analyzer.analyze(email)

    assert result.details["label"] == "bank_detail_change"
    assert result.details["should_scan"] is True


@pytest.mark.asyncio
async def test_receipt_is_payment_relevant():
    analyzer = PaymentRelevanceAnalyzer()
    email = make_email(
        "Receipt for your payment",
        "Payment received. Total paid AUD $102.53.",
    )

    result = await analyzer.analyze(email)

    assert result.details["label"] == "receipt"
    assert result.details["should_scan"] is True


@pytest.mark.asyncio
async def test_clear_non_payment_can_skip_deep_payshield_scan():
    analyzer = PaymentRelevanceAnalyzer()
    email = make_email(
        "Team planning reminder",
        "Hi team, please bring your quarterly roadmap notes to the meeting tomorrow.",
    )

    result = await analyzer.analyze(email)

    assert result.details["label"] == "non_payment"
    assert result.details["should_scan"] is False
    assert result.confidence >= 0.9


@pytest.mark.asyncio
async def test_short_sparse_email_stays_unknown_and_scannable():
    analyzer = PaymentRelevanceAnalyzer()
    email = make_email("FYI", "See attached.")

    result = await analyzer.analyze(email)

    assert result.details["label"] == "unknown"
    assert result.details["should_scan"] is True


@pytest.mark.asyncio
async def test_relevance_ml_sidecar_does_not_override_non_payment_skip(tmp_path, monkeypatch):
    model_path = tmp_path / "payment_relevance_model.joblib"
    model_path.write_bytes(b"placeholder")

    class FakePrediction:
        label = "invoice"
        confidence = 0.99
        class_probabilities = {"invoice": 0.99, "non_payment": 0.01}

    def fake_predictor(text, *, model_path):
        return FakePrediction()

    monkeypatch.setattr(
        "src.analyzers.payment_relevance._load_payment_relevance_predictor",
        lambda: fake_predictor,
    )
    analyzer = PaymentRelevanceAnalyzer(relevance_model_path=model_path)
    email = make_email(
        "Team planning reminder",
        "Hi team, please bring your quarterly roadmap notes to the meeting tomorrow.",
    )

    result = await analyzer.analyze(email)

    assert result.details["label"] == "non_payment"
    assert result.details["should_scan"] is False
    assert result.details["ml_sidecar"]["available"] is True
    assert result.details["ml_sidecar"]["mode"] == "monitor"
    assert result.details["ml_sidecar"]["authority"] == "rules"
    assert result.details["ml_sidecar"]["prediction"] == "invoice"
    assert result.details["ml_sidecar"]["would_change_skip_decision"] is True
    assert "model_path" not in result.details["ml_sidecar"]


@pytest.mark.asyncio
async def test_relevance_ml_sidecar_cannot_skip_rules_scannable_unknown(tmp_path, monkeypatch):
    model_path = tmp_path / "payment_relevance_model.joblib"
    model_path.write_bytes(b"placeholder")

    class FakePrediction:
        label = "non_payment"
        confidence = 0.98
        class_probabilities = {"invoice": 0.02, "non_payment": 0.98}

    def fake_predictor(text, *, model_path):
        return FakePrediction()

    monkeypatch.setattr(
        "src.analyzers.payment_relevance._load_payment_relevance_predictor",
        lambda: fake_predictor,
    )
    analyzer = PaymentRelevanceAnalyzer(relevance_model_path=model_path)
    email = make_email("FYI", "See attached.")

    result = await analyzer.analyze(email)

    assert result.details["label"] == "unknown"
    assert result.details["should_scan"] is True
    assert result.details["ml_sidecar"]["prediction"] == "non_payment"
    assert result.details["ml_sidecar"]["would_change_skip_decision"] is True
