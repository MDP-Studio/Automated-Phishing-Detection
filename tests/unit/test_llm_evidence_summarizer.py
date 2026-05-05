from __future__ import annotations

import json

import pytest

from src.analyzers.clients.anthropic_client import LLMResponse
from src.config import APIConfig
from src.llm_evidence_summarizer import (
    LLMEvidenceSummarizer,
    create_evidence_summary_client,
)


class FakeLLMClient:
    def __init__(self) -> None:
        self.prompt = ""

    async def analyze(self, prompt: str) -> LLMResponse:
        self.prompt = prompt
        return LLMResponse(
            text=json.dumps({
                "summary": "The existing verdict is supported by sender and URL evidence.",
                "supporting_evidence": ["URL reputation was locked", "Sender mismatch signal"],
                "recommended_actions": ["Verify out of band"],
                "confidence_note": "This explains evidence only and does not decide the verdict.",
            }),
            model_id="fake-evidence-model",
        )


@pytest.mark.asyncio
async def test_llm_evidence_summary_uses_structured_evidence_only():
    client = FakeLLMClient()
    payload = {
        "subject": "Private subject that should not be sent",
        "body_preview": "private email body that should not be sent",
        "overall_score": 0.72,
        "overall_confidence": 0.88,
        "product_verdicts": {
            "phishanalyze": {"verdict": "LIKELY_PHISHING"},
            "payshield": {"display_decision": "DO_NOT_PAY_UNTIL_VERIFIED"},
        },
        "analyzer_results": {
            "url_reputation": {
                "analyzer_id": "url_reputation",
                "display_name": "URL reputation",
                "status": "feature_locked",
                "cost_tier": "paid_low",
                "risk_contribution": 0,
                "failure_reason": "provider token=secret-token-value",
                "evidence": [{"text": "Locked until Starter with password=hunter2"}],
            },
            "sender_profiling": {
                "analyzer_id": "sender_profiling",
                "display_name": "Sender profiling",
                "status": "success",
                "cost_tier": "free_local",
                "risk_contribution": 0.31,
                "evidence": [{"text": "Reply-to domain differs from sender"}],
                "details": {"raw_email_body": "do not send raw details"},
            },
        },
    }

    result = await LLMEvidenceSummarizer(client).summarize(payload)

    assert result["llm_status"] == "success"
    assert result["model_id"] == "fake-evidence-model"
    assert result["summary"].startswith("The existing verdict")
    assert result["recommended_actions"] == ["Verify out of band"]
    assert "Private subject" not in client.prompt
    assert "private email body" not in client.prompt
    assert "raw_email_body" not in client.prompt
    assert "secret-token-value" not in client.prompt
    assert "hunter2" not in client.prompt
    assert "Reply-to domain differs from sender" in client.prompt
    assert "Do not decide or change the verdict" in client.prompt


def test_evidence_summary_client_defaults_to_deepseek_when_configured():
    client = create_evidence_summary_client(APIConfig(deepseek_key="deepseek-test-key"))

    assert client is not None
    assert client.base_url == "https://api.deepseek.com"
    assert client.model == "deepseek-v4-flash"
