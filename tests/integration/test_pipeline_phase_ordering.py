"""
Integration test for phase-2 brand_impersonation ordering.

Audit finding 5 (closed this cycle): brand_impersonation was kicked off
concurrently with url_detonation, but reads iocs["detonation_screenshots"]
at coroutine start — so it always saw an empty dict, even though the
pipeline wrote screenshots into iocs after url_detonation completed.
The visual-similarity signal was silently dead as a result.

Test strategy: patch _run_analyzer_with_limits to a lightweight stub
that records its start time and the iocs state it observed. The stub
also simulates url_detonation's screenshot payload being written to
iocs (matching the production handoff). brand_impersonation must start
strictly after url_detonation finishes, and must see the populated
screenshots dict at that moment.

If this test regresses, the race is back.
"""
from __future__ import annotations

import asyncio
import base64
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from src.config import PipelineConfig
from src.models import AnalyzerResult, EmailObject
from src.orchestrator.pipeline import PhishingPipeline


@pytest.fixture
def email() -> EmailObject:
    return EmailObject(
        email_id="ordering_test",
        raw_headers={},
        from_address="a@example.com",
        from_display_name="",
        reply_to=None,
        to_addresses=["b@example.com"],
        cc_addresses=[],
        subject="test",
        body_plain="",
        body_html="",
        date=datetime.now(timezone.utc),
        attachments=[],
        inline_images=[],
        message_id="ordering_test@example.com",
        received_chain=[],
    )


@pytest.mark.asyncio
async def test_brand_impersonation_runs_after_url_detonation(email):
    """Phase-2 analyzers observe iocs populated by phase 1."""
    pipeline = PhishingPipeline(PipelineConfig())
    log: list[dict] = []

    # url_detonation's synthetic screenshot payload, as returned from
    # production: base64-encoded PNG bytes keyed by URL. The pipeline
    # decodes these into iocs["detonation_screenshots"] after
    # url_detonation completes.
    screenshots_b64 = {"http://example.com": base64.b64encode(b"fake-png").decode()}

    async def fake_run(name, analyzer, email, iocs, urls):
        log.append({
            "name": name,
            "start": time.monotonic(),
            "saw_screenshots": bool(iocs.get("detonation_screenshots")),
        })
        if name == "url_detonation":
            # Simulate the 50ms detonation window during which phase 1
            # is still running. If brand_impersonation were in phase 1,
            # it would start at roughly the same monotonic time.
            await asyncio.sleep(0.05)
            return AnalyzerResult(
                analyzer_name=name, risk_score=0.0, confidence=0.0,
                details={"screenshots": screenshots_b64},
            )
        return AnalyzerResult(
            analyzer_name=name, risk_score=0.0, confidence=0.0, details={},
        )

    # Load-analyzer returns a sentinel object — its value doesn't
    # matter because fake_run ignores the instance and dispatches by
    # name.
    pipeline._load_analyzer = AsyncMock(return_value=object())
    pipeline._run_analyzer_with_limits = fake_run

    results = await pipeline._phase_analysis(email, iocs={}, extracted_urls=[])

    by_name = {entry["name"]: entry for entry in log}
    assert "url_detonation" in by_name
    assert "brand_impersonation" in by_name

    # Ordering: brand_impersonation must start AFTER url_detonation's
    # 50ms await. If phase-2 scheduling is broken (both launched
    # concurrently), the delta would be ≈0ms.
    delta = by_name["brand_impersonation"]["start"] - by_name["url_detonation"]["start"]
    assert delta >= 0.04, (
        f"brand_impersonation started only {delta*1000:.0f}ms after "
        f"url_detonation — phase-2 scheduling isn't actually waiting "
        f"for phase 1 to finish."
    )

    # Visibility: the whole point of the race fix — brand_impersonation
    # must see the populated screenshot payload at its start.
    assert by_name["brand_impersonation"]["saw_screenshots"] is True, (
        "brand_impersonation started with empty detonation_screenshots — "
        "the phase-1 iocs handoff did not reach phase 2."
    )

    # Sanity: both phase-1 and phase-2 produced results in the output.
    assert "url_detonation" in results
    assert "brand_impersonation" in results
