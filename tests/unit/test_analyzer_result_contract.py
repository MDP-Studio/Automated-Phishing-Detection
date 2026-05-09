from __future__ import annotations

import pytest

from src.analyzers.clients.base_client import BaseAPIClient
from src.analyzers.result_contract import normalize_analyzer_result
from src.models import AnalyzerResult
from src.product_verdicts import build_product_verdicts, enrich_payment_protection


def test_normalized_analyzer_contract_fields_and_cost_tier_mapping():
    result = AnalyzerResult(
        analyzer_name="url_reputation",
        risk_score=0.7,
        confidence=0.8,
        details={"urls_analyzed": {"https://example.test": {"risk": 0.7}}},
        timing_ms=12.3456,
        started_at="2026-05-06T00:00:00+00:00",
        completed_at="2026-05-06T00:00:00.012000+00:00",
    )

    payload = normalize_analyzer_result("url_reputation", result)

    assert payload["analyzer_id"] == "url_reputation"
    assert payload["display_name"] == "URL reputation"
    assert payload["status"] == "success"
    assert payload["plan_required"] == "starter"
    assert payload["cost_tier"] == "paid_low"
    assert payload["risk_contribution"] == pytest.approx(0.56)
    assert payload["started_at"] == "2026-05-06T00:00:00+00:00"
    assert payload["completed_at"] == "2026-05-06T00:00:00.012000+00:00"
    assert payload["duration_ms"] == pytest.approx(12.3456)
    assert payload["timing"]["duration_ms"] == payload["duration_ms"]
    assert payload["cached"] is False
    assert payload["evidence"]


def test_cached_status_and_safe_details_are_reported():
    result = AnalyzerResult(
        analyzer_name="domain_intelligence",
        risk_score=0.1,
        confidence=0.9,
        details={
            "cached": True,
            "api_key": "secret-key",
            "access_token": "secret-token",
            "message": "domain age looked normal",
        },
    )

    payload = normalize_analyzer_result("domain_intelligence", result)

    assert payload["status"] == "cached"
    assert payload["cached"] is True
    assert payload["cost_tier"] == "paid_low"
    assert payload["details"]["api_key"] == "(redacted)"
    assert payload["details"]["access_token"] == "(redacted)"


def test_rmm_lure_contract_is_free_local_and_customer_readable():
    result = AnalyzerResult(
        analyzer_name="rmm_lure",
        risk_score=0.82,
        confidence=0.9,
        details={
            "summary": "This email may be trying to make the user install a remote access tool.",
            "risky_flow": True,
        },
    )

    payload = normalize_analyzer_result("rmm_lure", result)

    assert payload["display_name"] == "Remote access lure detection"
    assert payload["plan_required"] == "free"
    assert payload["cost_tier"] == "free_local"
    assert payload["evidence"][0]["text"] == result.details["summary"]


def test_payment_relevance_contract_is_advisory_and_free():
    result = AnalyzerResult(
        analyzer_name="payment_relevance",
        risk_score=0.0,
        confidence=0.91,
        details={
            "label": "non_payment",
            "should_scan": False,
            "summary": "No payment context was detected.",
        },
        risk_contribution=0.0,
    )

    payload = normalize_analyzer_result("payment_relevance", result)

    assert payload["display_name"] == "Payment relevance"
    assert payload["plan_required"] == "free"
    assert payload["cost_tier"] == "free_local"
    assert payload["risk_contribution"] == 0.0
    assert payload["details"]["should_scan"] is False


def test_nested_api_client_cache_marker_promotes_cached_status():
    result = AnalyzerResult(
        analyzer_name="url_reputation",
        risk_score=0.1,
        confidence=0.7,
        details={
            "urls_analyzed": {
                "https://example.test": {
                    "virustotal": {"cached": True, "summary": "reused lookup"},
                }
            }
        },
    )

    payload = normalize_analyzer_result("url_reputation", result)

    assert payload["status"] == "cached"
    assert payload["cached"] is True


def test_payment_product_mapper_preserves_backend_enum_but_exposes_safe_copy():
    analyzer_results = {
        "payment_fraud": {
            "status": "success",
            "cost_tier": "free_local",
            "details": {
                "decision": "DO_NOT_PAY",
                "risk_score": 0.91,
                "summary": "Bank-detail change and urgency were found.",
            },
        }
    }

    verdicts = build_product_verdicts(
        phishing_verdict="CONFIRMED_PHISHING",
        overall_score=0.91,
        analyzer_results=analyzer_results,
    )
    enriched = enrich_payment_protection(
        analyzer_results["payment_fraud"]["details"],
        verdicts["payshield"],
    )

    assert verdicts["phishanalyze"]["verdict"] == "CONFIRMED_PHISHING"
    assert verdicts["payshield"]["backend_decision"] == "DO_NOT_PAY"
    assert verdicts["payshield"]["display_decision"] == "DO_NOT_PAY_UNTIL_VERIFIED"
    assert verdicts["payshield"]["label"] == "Do not pay until independently confirmed"
    assert enriched["decision"] == "DO_NOT_PAY"
    assert enriched["display_decision"] == "DO_NOT_PAY_UNTIL_VERIFIED"


def test_payment_product_mapper_labels_non_payment_skip_distinctly():
    analyzer_results = {
        "payment_fraud": {
            "status": "skipped",
            "cost_tier": "free_local",
            "details": {
                "message": "not_payment_related",
                "summary": "No payment context was detected.",
                "payment_relevance": {
                    "label": "non_payment",
                    "confidence": 0.91,
                },
            },
        }
    }

    verdicts = build_product_verdicts(
        phishing_verdict="CLEAN",
        overall_score=0.02,
        analyzer_results=analyzer_results,
    )
    enriched = enrich_payment_protection(
        analyzer_results["payment_fraud"]["details"],
        verdicts["payshield"],
    )

    assert verdicts["payshield"]["display_decision"] == "NOT_PAYMENT_SPECIFIC"
    assert verdicts["payshield"]["label"] == "Not payment-specific"
    assert enriched["display_decision"] == "NOT_PAYMENT_SPECIFIC"


class DummyAPIClient(BaseAPIClient):
    async def verify_api_key(self) -> bool:
        return True


def test_api_client_cache_hit_marks_analyzer_result_cached():
    client = DummyAPIClient(api_key="test", base_url="https://example.test")
    result = AnalyzerResult(
        analyzer_name="url_reputation",
        risk_score=0.2,
        confidence=0.5,
        details={},
    )
    key = client._get_cache_key("url", "https://example.test")

    client._cache_set(key, result)
    cached = client._cache_get(key)

    assert cached is result
    assert cached.cached is True
    assert cached.status == "cached"
    assert cached.details["cached"] is True
