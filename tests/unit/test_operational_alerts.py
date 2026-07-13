from __future__ import annotations

import asyncio
import json

import pytest

from src.automation.operational_alerts import OperationalAlertDispatcher


@pytest.mark.asyncio
async def test_operational_alert_writes_only_closed_schema(tmp_path):
    path = tmp_path / "operational.jsonl"
    dispatcher = OperationalAlertDispatcher(
        log_path=path,
        hash_key="separate-alert-hash-key",
        cooldown_seconds=0,
    )

    result = await dispatcher.dispatch(
        "tenant_campaign_repeated",
        details={
            "related_count": 2,
            "signal_types": ["url_domain", "sender_domain"],
            "payment_risk": True,
        },
        tenant_id="org-private-123",
    )

    assert result["status"] == "logged"
    payload = json.loads(path.read_text(encoding="utf-8"))
    serialized = json.dumps(payload, sort_keys=True)
    assert payload["tenant_ref"].startswith("tenant_")
    assert payload["details"] == {
        "payment_risk": True,
        "related_count": 2,
        "signal_types": ["sender_domain", "url_domain"],
    }
    assert "org-private-123" not in serialized
    assert "subject" not in serialized
    assert "email" not in serialized


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unsafe_field,unsafe_value",
    [
        ("subject", "Urgent bank details"),
        ("email", "owner@example.com"),
        ("url", "https://private.example/invoice"),
        ("client_ip", "203.0.113.7"),
        ("token", "secret-value"),
    ],
)
async def test_operational_alert_rejects_sensitive_caller_fields(
    tmp_path,
    unsafe_field,
    unsafe_value,
):
    dispatcher = OperationalAlertDispatcher(
        log_path=tmp_path / "operational.jsonl",
        cooldown_seconds=0,
    )
    details = {
        "auth_namespace": "analyst",
        "attempt_count": 10,
        "window_seconds": 900,
        unsafe_field: unsafe_value,
    }

    with pytest.raises(ValueError, match="privacy schema"):
        await dispatcher.dispatch("auth_failure_threshold", details=details)

    assert not dispatcher.log_path.exists()


@pytest.mark.asyncio
async def test_operational_alert_omits_raw_tenant_without_hash_key(tmp_path):
    dispatcher = OperationalAlertDispatcher(
        log_path=tmp_path / "operational.jsonl",
        cooldown_seconds=0,
    )

    result = await dispatcher.dispatch(
        "payment_risk_escalation",
        details={
            "decision": "DO_NOT_PAY_UNTIL_VERIFIED",
            "related_count": 0,
        },
        tenant_id="org-must-not-leak",
    )

    assert "tenant_ref" not in result["payload"]
    assert "org-must-not-leak" not in dispatcher.log_path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_operational_alert_webhook_failure_is_explicit_and_keeps_local_record(
    tmp_path,
    monkeypatch,
):
    dispatcher = OperationalAlertDispatcher(
        log_path=tmp_path / "operational.jsonl",
        webhook_url="https://alerts.example.test/hook",
        cooldown_seconds=0,
    )

    async def failed_delivery(_payload):
        return False

    monkeypatch.setattr(dispatcher, "_deliver_webhook", failed_delivery)

    result = await dispatcher.dispatch(
        "analyzer_circuit_open",
        details={
            "analyzer": "VirusTotalClient",
            "failure_count": 5,
            "recovery_timeout_seconds": 300,
        },
    )

    assert result["status"] == "partial"
    assert result["log_written"] is True
    assert result["webhook_configured"] is True
    assert result["webhook_delivered"] is False
    assert dispatcher.log_path.exists()


@pytest.mark.asyncio
async def test_operational_alert_cooldown_suppresses_duplicate_delivery(tmp_path):
    now = [100.0]
    dispatcher = OperationalAlertDispatcher(
        log_path=tmp_path / "operational.jsonl",
        cooldown_seconds=60,
        clock=lambda: now[0],
    )
    details = {
        "auth_namespace": "saas-user",
        "attempt_count": 10,
        "window_seconds": 900,
    }

    first = await dispatcher.dispatch(
        "auth_failure_threshold",
        details=details,
        dedupe_key="saas-user:budget",
    )
    duplicate = await dispatcher.dispatch(
        "auth_failure_threshold",
        details=details,
        dedupe_key="saas-user:budget",
    )
    now[0] += 61
    later = await dispatcher.dispatch(
        "auth_failure_threshold",
        details=details,
        dedupe_key="saas-user:budget",
    )

    rows = dispatcher.log_path.read_text(encoding="utf-8").splitlines()
    assert first["status"] == "logged"
    assert duplicate["status"] == "suppressed"
    assert later["status"] == "logged"
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_concurrent_operational_alert_writes_remain_valid_jsonl(tmp_path):
    dispatcher = OperationalAlertDispatcher(
        log_path=tmp_path / "operational.jsonl",
        cooldown_seconds=0,
    )

    await asyncio.gather(*(
        dispatcher.dispatch(
            "analyzer_circuit_open",
            details={
                "analyzer": f"Vendor{index}",
                "failure_count": 5,
                "recovery_timeout_seconds": 300,
            },
        )
        for index in range(20)
    ))

    rows = [
        json.loads(line)
        for line in dispatcher.log_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(rows) == 20
    assert {row["details"]["analyzer"] for row in rows} == {
        f"Vendor{index}" for index in range(20)
    }
