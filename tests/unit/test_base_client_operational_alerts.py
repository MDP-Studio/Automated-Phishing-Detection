from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from src.analyzers.clients.base_client import BaseAPIClient, CircuitBreaker


class _TestVendorClient(BaseAPIClient):
    async def verify_api_key(self) -> bool:
        return True


def test_circuit_breaker_reports_only_transition_into_open_state():
    breaker = CircuitBreaker(failure_threshold=2)

    assert breaker.record_failure() is False
    assert breaker.record_failure() is True
    assert breaker.record_failure() is False
    assert breaker.state == "open"


@pytest.mark.asyncio
async def test_analyzer_failure_alert_fires_once_when_circuit_opens():
    dispatcher = AsyncMock()
    client = _TestVendorClient(
        api_key="test-key",
        base_url="https://vendor.example.test",
        operational_alert_dispatcher=dispatcher,
    )
    client.circuit_breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=45)

    await client._record_request_failure()
    await client._record_request_failure()
    await client._record_request_failure()

    dispatcher.dispatch.assert_awaited_once_with(
        "analyzer_circuit_open",
        details={
            "analyzer": "_TestVendorClient",
            "failure_count": 2,
            "recovery_timeout_seconds": 45,
        },
        dedupe_key="analyzer-circuit:_TestVendorClient",
    )
