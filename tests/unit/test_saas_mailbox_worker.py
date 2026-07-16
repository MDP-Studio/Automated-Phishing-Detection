from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from src.saas.database import SaaSStore
from src.saas.mailbox_worker import SaaSMailboxWorker


def _paid_mailbox(store: SaaSStore, *, email: str, external_id: str):
    context = store.create_user_with_org(
        email=email,
        password="correct horse battery",
        org_name=f"Workspace {external_id}",
    )
    store.set_subscription(org_id=context.org_id, plan_slug="pro", status="active")
    mailbox = store.register_mail_account(
        org_id=context.org_id,
        user_id=context.user_id,
        provider="gmail",
        external_account_id=external_id,
        encrypted_token_ref="encrypted-test-credential",
        status="active",
    )
    mailbox = store.set_mailbox_automation(
        org_id=context.org_id,
        actor_user_id=context.user_id,
        mail_account_id=mailbox.id,
        enabled=True,
        poll_interval_seconds=300,
    )
    return context, mailbox


def test_due_mailbox_claim_is_single_owner_under_concurrency(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context, mailbox = _paid_mailbox(
        store,
        email="owner@example.com",
        external_id="inbox@example.com",
    )

    def claim(owner: str):
        return store.claim_due_mailboxes(lease_owner=owner, limit=1, lease_seconds=300)

    with ThreadPoolExecutor(max_workers=2) as executor:
        claimed = list(executor.map(claim, ["worker-a", "worker-b"]))

    flattened = [item for batch in claimed for item in batch]
    assert [item.id for item in flattened] == [mailbox.id]
    assert all(item.org_id == context.org_id for item in flattened)
    assert store.claim_mailbox_for_scan(
        org_id="another-tenant",
        mail_account_id=mailbox.id,
        lease_owner="manual",
    ) is False


def test_monthly_scan_reservations_are_atomic_under_concurrency(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context = store.create_user_with_org(
        email="owner@example.com",
        password="correct horse battery",
    )

    def reserve(index: int):
        return store.reserve_scan_quota(
            org_id=context.org_id,
            user_id=context.user_id,
            idempotency_key=f"concurrent-scan-{index}",
        )

    with ThreadPoolExecutor(max_workers=6) as executor:
        decisions = list(executor.map(reserve, range(6)))

    assert sum(decision.available for decision in decisions) == 5
    assert store.monthly_usage_count(context.org_id, "manual_scan") == 5


@pytest.mark.asyncio
async def test_worker_revalidates_and_processes_each_mailbox_in_its_tenant(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    first_context, first_mailbox = _paid_mailbox(
        store,
        email="first@example.com",
        external_id="first-inbox@example.com",
    )
    second_context, second_mailbox = _paid_mailbox(
        store,
        email="second@example.com",
        external_id="second-inbox@example.com",
    )
    processed: list[tuple[str, str, str]] = []

    async def scan_mailbox(*, context, mailbox, max_results: int):
        processed.append((context.org_id, mailbox.org_id, mailbox.id))
        assert context.org_id == mailbox.org_id
        assert max_results == 7
        return {"status": "ok"}

    worker = SaaSMailboxWorker(
        store=store,
        scan_mailbox=scan_mailbox,
        worker_id="worker-test",
        batch_size=10,
        max_results=7,
    )
    stats = await worker.run_once()

    assert stats.claimed == 2
    assert stats.completed == 2
    assert set(processed) == {
        (first_context.org_id, first_context.org_id, first_mailbox.id),
        (second_context.org_id, second_context.org_id, second_mailbox.id),
    }
    assert (await worker.run_once()).claimed == 0
    for context, mailbox in (
        (first_context, first_mailbox),
        (second_context, second_mailbox),
    ):
        updated = store.get_mail_account(org_id=context.org_id, mail_account_id=mailbox.id)
        assert updated is not None
        assert updated.automation_enabled is True
        assert updated.failure_count == 0
        assert updated.last_polled_at is not None
        assert updated.next_poll_at is not None


@pytest.mark.asyncio
async def test_worker_disables_polling_when_entitlement_is_revoked(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context, mailbox = _paid_mailbox(
        store,
        email="owner@example.com",
        external_id="inbox@example.com",
    )
    store.set_subscription(org_id=context.org_id, plan_slug="free", status="active")
    called = False

    async def scan_mailbox(**_kwargs):
        nonlocal called
        called = True
        return {"status": "ok"}

    worker = SaaSMailboxWorker(
        store=store,
        scan_mailbox=scan_mailbox,
        worker_id="worker-test",
    )
    stats = await worker.run_once()

    assert called is False
    assert stats.disabled == 1
    updated = store.get_mail_account(org_id=context.org_id, mail_account_id=mailbox.id)
    assert updated is not None
    assert updated.automation_enabled is False
    assert updated.status == "active"
    assert updated.last_error_code == "entitlement_revoked"


@pytest.mark.asyncio
async def test_worker_backoff_and_credential_failure_are_fail_closed(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context, mailbox = _paid_mailbox(
        store,
        email="owner@example.com",
        external_id="inbox@example.com",
    )

    async def timeout_scan(**_kwargs):
        raise TimeoutError("test timeout")

    timeout_worker = SaaSMailboxWorker(
        store=store,
        scan_mailbox=timeout_scan,
        worker_id="worker-timeout",
    )
    timeout_stats = await timeout_worker.run_once()
    after_timeout = store.get_mail_account(org_id=context.org_id, mail_account_id=mailbox.id)
    assert timeout_stats.failed == 1
    assert after_timeout is not None
    assert after_timeout.automation_enabled is True
    assert after_timeout.failure_count == 1
    assert after_timeout.last_error_code == "scan_timeout"
    assert datetime.fromisoformat(after_timeout.next_poll_at) > datetime.now(timezone.utc)

    with store._connect() as conn:
        conn.execute(
            "UPDATE mail_accounts SET next_poll_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), mailbox.id),
        )
        conn.commit()

    async def credential_failure(**_kwargs):
        raise HTTPException(status_code=502, detail="test credential failure")

    credential_worker = SaaSMailboxWorker(
        store=store,
        scan_mailbox=credential_failure,
        worker_id="worker-credential",
    )
    credential_stats = await credential_worker.run_once()
    after_credential = store.get_mail_account(org_id=context.org_id, mail_account_id=mailbox.id)
    assert credential_stats.failed == 1
    assert credential_stats.disabled == 1
    assert after_credential is not None
    assert after_credential.automation_enabled is False
    assert after_credential.status == "error"
    assert after_credential.last_error_code == "credential_error"


@pytest.mark.asyncio
async def test_worker_backs_off_without_disabling_when_scan_quota_is_exhausted(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context, mailbox = _paid_mailbox(
        store,
        email="owner@example.com",
        external_id="inbox@example.com",
    )

    async def quota_limited_scan(**_kwargs):
        return {"status": "ok", "quota_exhausted": True}

    worker = SaaSMailboxWorker(
        store=store,
        scan_mailbox=quota_limited_scan,
        worker_id="worker-quota",
    )
    stats = await worker.run_once()
    updated = store.get_mail_account(org_id=context.org_id, mail_account_id=mailbox.id)

    assert stats.skipped == 1
    assert stats.failed == 0
    assert updated is not None
    assert updated.automation_enabled is True
    assert updated.failure_count == 1
    assert updated.last_error_code == "scan_quota_exhausted"


def test_mailbox_receipts_and_scan_jobs_reject_cross_tenant_links(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    first_context, first_mailbox = _paid_mailbox(
        store,
        email="first@example.com",
        external_id="first-inbox@example.com",
    )
    second_context, _second_mailbox = _paid_mailbox(
        store,
        email="second@example.com",
        external_id="second-inbox@example.com",
    )

    assert store.record_mailbox_message_receipt(
        org_id=first_context.org_id,
        mail_account_id=first_mailbox.id,
        provider_message_id="uid-123",
        outcome="skipped",
    ) is True
    assert store.record_mailbox_message_receipt(
        org_id=first_context.org_id,
        mail_account_id=first_mailbox.id,
        provider_message_id="uid-123",
        outcome="skipped",
    ) is False
    assert store.has_mailbox_message_receipt(
        org_id=first_context.org_id,
        mail_account_id=first_mailbox.id,
        provider_message_id="uid-123",
    ) is True
    assert store.has_mailbox_message_receipt(
        org_id=second_context.org_id,
        mail_account_id=first_mailbox.id,
        provider_message_id="uid-123",
    ) is False
    with pytest.raises(ValueError, match="mail account not found for organization"):
        store.create_scan_job(
            org_id=second_context.org_id,
            user_id=second_context.user_id,
            source="mailbox_poll",
            mail_account_id=first_mailbox.id,
        )
