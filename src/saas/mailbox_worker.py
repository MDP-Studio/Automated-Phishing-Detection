"""Lease-based continuous mailbox worker with explicit tenant revalidation."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import socket
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class WorkerRunStats:
    claimed: int = 0
    completed: int = 0
    failed: int = 0
    disabled: int = 0
    skipped: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def default_worker_id() -> str:
    host = socket.gethostname().split(".", 1)[0][:32]
    return f"{host}:{os.getpid()}:{secrets.token_urlsafe(6)}"


def _worker_error(exc: Exception) -> tuple[str, bool]:
    status_code = getattr(exc, "status_code", None)
    if status_code == 402:
        return "scan_quota_exhausted", False
    if status_code in {409, 502, 503}:
        return "credential_error", True
    if status_code == 429:
        return "provider_rate_limited", False
    if isinstance(exc, TimeoutError):
        return "scan_timeout", False
    return "scan_failed", False


class SaaSMailboxWorker:
    """Claim due mailbox rows and process each one under its stored tenant."""

    def __init__(
        self,
        *,
        store,
        scan_mailbox: Callable[..., Awaitable[dict]],
        worker_id: str | None = None,
        lease_seconds: int = 300,
        batch_size: int = 5,
        max_results: int = 10,
    ) -> None:
        self.store = store
        self.scan_mailbox = scan_mailbox
        self.worker_id = worker_id or default_worker_id()
        self.lease_seconds = max(60, int(lease_seconds))
        self.batch_size = max(1, min(int(batch_size), 100))
        self.max_results = max(1, min(int(max_results), 50))

    async def run_once(self) -> WorkerRunStats:
        stats = WorkerRunStats()
        mailboxes = self.store.claim_due_mailboxes(
            lease_owner=self.worker_id,
            limit=self.batch_size,
            lease_seconds=self.lease_seconds,
        )
        stats.claimed = len(mailboxes)
        for claimed in mailboxes:
            context = self.store.get_account_context_for_org(
                user_id=claimed.user_id,
                org_id=claimed.org_id,
            )
            if context is None:
                self.store.complete_mailbox_poll(
                    org_id=claimed.org_id,
                    mail_account_id=claimed.id,
                    lease_owner=self.worker_id,
                    success=False,
                    error_code="membership_missing",
                    disable_automation=True,
                )
                stats.disabled += 1
                continue
            entitlement = self.store.check_entitlement(
                org_id=context.org_id,
                user_id=context.user_id,
                feature_slug="continuous_mailbox_monitoring",
                audit_lock=False,
            )
            if not entitlement.available:
                self.store.complete_mailbox_poll(
                    org_id=claimed.org_id,
                    mail_account_id=claimed.id,
                    lease_owner=self.worker_id,
                    success=False,
                    error_code="entitlement_revoked",
                    disable_automation=True,
                )
                stats.disabled += 1
                continue
            mailbox = self.store.get_mail_account(
                org_id=claimed.org_id,
                mail_account_id=claimed.id,
            )
            if mailbox is None:
                stats.skipped += 1
                continue
            if not mailbox.automation_enabled:
                self.store.release_mailbox_lease(
                    org_id=claimed.org_id,
                    mail_account_id=claimed.id,
                    lease_owner=self.worker_id,
                )
                stats.skipped += 1
                continue
            try:
                outcome = await self.scan_mailbox(
                    context=context,
                    mailbox=mailbox,
                    max_results=self.max_results,
                )
            except asyncio.CancelledError:
                self.store.release_mailbox_lease(
                    org_id=claimed.org_id,
                    mail_account_id=claimed.id,
                    lease_owner=self.worker_id,
                )
                raise
            except Exception as exc:
                error_code, credential_error = _worker_error(exc)
                logger.error(
                    "Tenant mailbox poll failed safely (code=%s, type=%s)",
                    error_code,
                    type(exc).__name__,
                )
                self.store.complete_mailbox_poll(
                    org_id=claimed.org_id,
                    mail_account_id=claimed.id,
                    lease_owner=self.worker_id,
                    success=False,
                    error_code=error_code,
                    disable_automation=credential_error,
                    mark_mailbox_error=credential_error,
                )
                if error_code == "scan_quota_exhausted":
                    stats.skipped += 1
                else:
                    stats.failed += 1
                if credential_error:
                    stats.disabled += 1
                continue
            if outcome.get("quota_exhausted"):
                self.store.complete_mailbox_poll(
                    org_id=claimed.org_id,
                    mail_account_id=claimed.id,
                    lease_owner=self.worker_id,
                    success=False,
                    error_code="scan_quota_exhausted",
                )
                stats.skipped += 1
                continue
            completed = self.store.complete_mailbox_poll(
                org_id=claimed.org_id,
                mail_account_id=claimed.id,
                lease_owner=self.worker_id,
                success=True,
            )
            if completed:
                stats.completed += 1
            else:
                logger.warning("Mailbox poll completed after its lease was lost")
                stats.failed += 1
        return stats


async def run_worker_loop(
    worker: SaaSMailboxWorker,
    *,
    idle_seconds: int,
    heartbeat: Callable[[WorkerRunStats], Any],
    stop_event: asyncio.Event | None = None,
) -> None:
    stop = stop_event or asyncio.Event()
    delay = max(1, int(idle_seconds))
    while not stop.is_set():
        stats = await worker.run_once()
        heartbeat(stats)
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
        except TimeoutError:
            logger.debug("Mailbox worker idle interval completed")
            continue
