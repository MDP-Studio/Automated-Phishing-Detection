from __future__ import annotations

from src.analyzers.clients.sandbox_client import (
    HybridAnalysisStrategy,
    SandboxClient,
    SandboxProvider,
)


def test_hybrid_analysis_accepts_api_key_without_optional_secret():
    strategy = HybridAnalysisStrategy(api_key="hybrid-test-key")

    assert strategy.api_secret == ""
    assert strategy._get_headers() == {
        "api-key": "hybrid-test-key",
        "user-agent": "Phishing-Detection-Pipeline/1.0",
    }


def test_sandbox_client_wires_hybrid_analysis_with_key_only():
    client = SandboxClient({"hybrid_analysis": {"api_key": "hybrid-test-key"}})

    assert SandboxProvider.HYBRID_ANALYSIS in client.strategies
    assert client.strategies[SandboxProvider.HYBRID_ANALYSIS].api_secret == ""
