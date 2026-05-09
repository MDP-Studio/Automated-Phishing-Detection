from __future__ import annotations

import pytest

from src.billing.entitlements import feature_entitlement
from src.config import PipelineConfig
from src.models import AnalyzerResult
from src.orchestrator.pipeline import PhishingPipeline


@pytest.mark.asyncio
async def test_pipeline_skips_locked_paid_analyzers_before_loading(sample_email_clean):
    pipeline = PhishingPipeline(PipelineConfig())
    paid_analyzers = {
        "url_reputation",
        "domain_intelligence",
        "url_detonation",
        "brand_impersonation",
        "attachment_analysis",
        "nlp_intent",
        "sender_profiling",
    }

    async def load_analyzer(name):
        if name in paid_analyzers:
            raise AssertionError(f"locked analyzer should not load: {name}")
        return None

    pipeline._load_analyzer = load_analyzer

    results = await pipeline._phase_analysis(
        sample_email_clean,
        {},
        [],
        feature_gate=lambda slug: feature_entitlement("free", slug).to_dict(),
    )

    assert results["url_reputation"].details["message"] == "feature_locked"
    assert results["url_reputation"].status == "feature_locked"
    assert results["url_reputation"].cost_tier == "paid_low"
    assert results["url_reputation"].details["required_plan_name"] == "Starter"
    assert results["url_detonation"].details["required_plan_name"] == "Pro"
    assert results["url_detonation"].cost_tier == "paid_high"
    assert results["header_analysis"].status == "not_configured"
    assert results["rmm_lure"].status == "not_configured"
    assert results["payment_fraud"].status == "not_configured"


@pytest.mark.asyncio
async def test_payment_relevance_skips_payment_fraud_before_loading(sample_email_clean):
    pipeline = PhishingPipeline(PipelineConfig())
    loaded = []

    class FakePaymentRelevance:
        async def analyze(self, **kwargs):
            return AnalyzerResult(
                analyzer_name="payment_relevance",
                risk_score=0.0,
                confidence=0.91,
                details={
                    "label": "non_payment",
                    "should_scan": False,
                    "confidence": 0.91,
                    "summary": "No payment context.",
                },
            )

    async def load_analyzer(name):
        loaded.append(name)
        if name == "payment_relevance":
            return FakePaymentRelevance()
        if name == "payment_fraud":
            raise AssertionError("payment_fraud should be skipped before loading")
        return None

    pipeline._load_analyzer = load_analyzer

    results = await pipeline._phase_analysis(sample_email_clean, {}, [])

    assert results["payment_relevance"].details["label"] == "non_payment"
    assert results["payment_fraud"].status == "skipped"
    assert results["payment_fraud"].details["message"] == "not_payment_related"
    assert "payment_fraud" not in loaded
