from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.analyzers.rmm_lure import RMMLureAnalyzer
from src.models import AttachmentObject, EmailObject, ExtractedURL, URLSource, Verdict
from src.orchestrator.pipeline import PhishingPipeline
from src.config import PipelineConfig


def _email(
    *,
    subject: str,
    body: str,
    attachments: list[AttachmentObject] | None = None,
) -> EmailObject:
    return EmailObject(
        email_id="rmm-001",
        raw_headers={},
        from_address="support@example-alerts.net",
        from_display_name="Support Team",
        reply_to=None,
        to_addresses=["user@example.com"],
        cc_addresses=[],
        subject=subject,
        body_plain=body,
        body_html=f"<html><body>{body}</body></html>",
        date=datetime(2026, 5, 7, 9, 0, 0, tzinfo=timezone.utc),
        attachments=attachments or [],
        inline_images=[],
        message_id="rmm-001@example-alerts.net",
        received_chain=[],
    )


@pytest.mark.asyncio
async def test_rmm_lure_detects_fake_document_to_installer_flow():
    analyzer = RMMLureAnalyzer()
    email = _email(
        subject="New SSA benefits statement available",
        body=(
            "Your Social Security statement is ready. View the protected document "
            "and download the secure viewer update. Run AnyDeskSetup.exe to open it."
        ),
    )
    urls = [
        ExtractedURL(
            url="https://ssa-benefits.example.net/document",
            source=URLSource.BODY_HTML,
            source_detail="href",
            resolved_url="https://cdn.example.net/download/AnyDeskSetup.exe",
            redirect_chain=[
                "https://ssa-benefits.example.net/document",
                "https://cdn.example.net/download/AnyDeskSetup.exe",
            ],
        )
    ]

    result = await analyzer.analyze(email=email, extracted_urls=urls)

    assert result.analyzer_name == "rmm_lure"
    assert result.status == "success"
    assert result.risk_score >= 0.9
    assert result.confidence >= 0.8
    assert result.details["lure_category"]["id"] == "ssa_statement"
    assert "AnyDesk" in result.details["detected_remote_tool_keywords"]
    assert result.details["risky_flow"] is True
    assert any("Executable-style download" in item for item in result.details["suspicious_download_indicators"])
    assert result.details["user_guidance"][0].startswith("Do not run")
    assert any(
        item["text"] == "This email may be trying to make the user install a remote access tool."
        for item in result.evidence
    )


@pytest.mark.asyncio
async def test_rmm_lure_skips_clean_email_without_diluting_score(sample_email_clean):
    result = await RMMLureAnalyzer().analyze(email=sample_email_clean, extracted_urls=[])

    assert result.status == "skipped"
    assert result.confidence == 0.0
    assert result.risk_score == 0.0


@pytest.mark.asyncio
async def test_pipeline_rmm_lure_can_raise_likely_phishing_verdict():
    pipeline = PhishingPipeline(PipelineConfig())
    rmm_result = await RMMLureAnalyzer().analyze(
        email=_email(
            subject="Teams update required",
            body=(
                "Your Teams update is required. Click to download the meeting viewer, "
                "then run setup.exe to start a remote support session."
            ),
        ),
        extracted_urls=[
            ExtractedURL(
                url="https://teams-update.example.net/view",
                source=URLSource.BODY_HTML,
                source_detail="href",
                resolved_url="https://download.example.net/setup.exe",
            )
        ],
    )

    verdict, _, _, reasoning = pipeline._phase_decision({"rmm_lure": rmm_result})

    assert verdict == Verdict.LIKELY_PHISHING
    assert "rmm_lure override" in reasoning
