"""Shared tenant-scoped mailbox scan service for API and worker execution."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from src.analyzers.payment_relevance import PaymentRelevanceAnalyzer
from src.config import IMAPConfig, _coerce_bool
from src.extractors.eml_parser import EMLParser
from src.ingestion import imap_provider as imap_provider_module
from src.llm_evidence_summarizer import LLMEvidenceSummarizer, create_evidence_summary_client
from src.security.credentials import decrypt_password
from src.support.mailbox_guides import mailbox_provider_host_default

logger = logging.getLogger(__name__)


def mailbox_imap_config(mailbox) -> IMAPConfig:
    """Build an IMAP configuration from one encrypted tenant mailbox record."""
    if not mailbox.encrypted_token_ref:
        raise HTTPException(status_code=409, detail="Mailbox credential is missing")
    try:
        bundle = json.loads(decrypt_password(mailbox.encrypted_token_ref))
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail="Mailbox credential could not be decrypted. Reconnect this mailbox.",
        ) from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=409, detail="Mailbox credential is invalid") from exc

    provider = str(bundle.get("provider") or mailbox.provider or "").lower()
    host = str(bundle.get("host") or mailbox_provider_host_default(provider)).strip()
    user = str(bundle.get("email") or mailbox.external_account_id or "").strip()
    password = str(bundle.get("app_password") or "").strip()
    try:
        port = int(bundle.get("port") or 993)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail="Mailbox IMAP port is invalid") from exc
    if not host or not user or not password:
        raise HTTPException(
            status_code=409,
            detail="Mailbox needs host, email, and app password before scanning",
        )
    return IMAPConfig(host=host, port=port, user=user, password=password)


async def add_llm_evidence_summary(
    store,
    context,
    response_payload: dict,
    *,
    api_config: Any,
) -> None:
    summary = response_payload.setdefault("evidence_summary", {})
    entitlement = store.check_entitlement(
        org_id=context.org_id,
        user_id=context.user_id,
        feature_slug="llm_intent",
        audit_lock=False,
    )
    if not entitlement.available:
        summary["llm_status"] = "feature_locked"
        summary["llm_reason"] = entitlement.reason
        return
    if not _coerce_bool(os.getenv("LLM_EVIDENCE_SUMMARY_ENABLED"), False):
        summary["llm_status"] = "disabled"
        summary["llm_reason"] = (
            "Set LLM_EVIDENCE_SUMMARY_ENABLED=true to call the configured LLM summarizer."
        )
        return
    client = create_evidence_summary_client(api_config)
    if client is None:
        summary["llm_status"] = "not_configured"
        summary["llm_reason"] = "No configured LLM API key is available for evidence summaries."
        return
    try:
        llm_summary = await LLMEvidenceSummarizer(client).summarize(response_payload)
    except Exception as exc:
        logger.warning("LLM evidence summary failed: %s", exc)
        summary["llm_status"] = "failed"
        summary["llm_reason"] = str(exc)
        return
    finally:
        if hasattr(client, "close"):
            await client.close()
    response_payload["evidence_summary"] = {**summary, **llm_summary}


async def alert_stored_scan(
    store,
    context,
    *,
    result_id: str,
    payment_decision: str | None,
    operational_alerts,
) -> None:
    """Emit privacy-minimized repeated-campaign and payment-risk alerts."""
    related = store.list_related_scan_results(
        org_id=context.org_id,
        result_id=result_id,
        limit=25,
    )
    concrete_related = []
    fingerprint_parts: list[str] = []
    signal_types: set[str] = set()
    for item in related["related"]:
        concrete_matches = [
            match
            for match in item.get("matched_signals", [])
            if match.get("type") != "payment_decision"
        ]
        if not concrete_matches:
            continue
        concrete_related.append(item)
        for match in concrete_matches:
            signal_type = str(match.get("type") or "")
            signal_value = str(match.get("value") or "")
            if signal_type:
                signal_types.add(signal_type)
            if signal_type and signal_value:
                fingerprint_parts.append(f"{signal_type}:{signal_value}")

    normalized_decision = str(payment_decision or "").strip().upper()
    high_payment_risk = normalized_decision in {
        "DO_NOT_PAY",
        "DO_NOT_PAY_UNTIL_VERIFIED",
    }
    if concrete_related:
        campaign_fingerprint = hashlib.sha256(
            "\n".join(sorted(set(fingerprint_parts))).encode("utf-8")
        ).hexdigest()[:24]
        await operational_alerts.dispatch(
            "tenant_campaign_repeated",
            details={
                "related_count": len(concrete_related),
                "signal_types": sorted(signal_types),
                "payment_risk": high_payment_risk,
            },
            tenant_id=context.org_id,
            dedupe_key=f"tenant-campaign:{context.org_id}:{campaign_fingerprint}",
        )
    if high_payment_risk:
        await operational_alerts.dispatch(
            "payment_risk_escalation",
            details={
                "decision": normalized_decision,
                "related_count": len(concrete_related),
            },
            tenant_id=context.org_id,
            dedupe_key=f"payment-risk:{context.org_id}:{normalized_decision}",
        )


async def _mark_processed(provider: Any, provider_id: str) -> None:
    marked = await asyncio.to_thread(provider.mark_as_read, provider_id)
    if not marked:
        logger.warning("Processed mailbox message could not be marked as read")


async def scan_mailbox(
    *,
    store,
    context,
    mailbox,
    max_results: int,
    pipeline,
    payload_builder: Callable[[Any, Any, str], dict],
    api_config: Any,
    operational_alerts,
    source: str,
) -> dict:
    """Scan one leased mailbox without crossing its authenticated tenant boundary."""
    if source not in {"mailbox_scan", "mailbox_poll"}:
        raise ValueError("unsupported mailbox scan source")
    initial_quota = store.check_entitlement(
        org_id=context.org_id,
        user_id=context.user_id,
        feature_slug="manual_scan",
        enforce_scan_quota=True,
        audit_lock=source == "mailbox_scan",
    )
    if not initial_quota.available:
        raise HTTPException(status_code=402, detail=initial_quota.reason)
    config = mailbox_imap_config(mailbox)
    provider = imap_provider_module.IMAPProvider(config)
    authenticated = await asyncio.to_thread(provider.authenticate)
    if not authenticated:
        store.set_mail_account_status(
            org_id=context.org_id,
            mail_account_id=mailbox.id,
            status="error",
            actor_user_id=context.user_id,
        )
        raise HTTPException(status_code=502, detail="Mailbox authentication failed")

    try:
        fetched = await asyncio.to_thread(provider.fetch_new_emails, max_results)
        store.set_mail_account_status(
            org_id=context.org_id,
            mail_account_id=mailbox.id,
            status="active",
            actor_user_id=context.user_id,
        )
        parser = EMLParser()
        relevance_analyzer = PaymentRelevanceAnalyzer()
        analyzed = []
        skipped = []
        duplicate_count = 0
        quota_exhausted = False

        def feature_gate(feature_slug: str) -> dict:
            return store.check_entitlement(
                org_id=context.org_id,
                user_id=context.user_id,
                feature_slug=feature_slug,
                enforce_scan_quota=False,
            ).to_dict()

        for item in fetched:
            provider_id = str(item.provider_id)
            if store.has_mailbox_message_receipt(
                org_id=context.org_id,
                mail_account_id=mailbox.id,
                provider_message_id=provider_id,
            ):
                duplicate_count += 1
                await _mark_processed(provider, provider_id)
                continue
            email = parser.parse_bytes(item.raw_bytes)
            if email is None:
                store.record_mailbox_message_receipt(
                    org_id=context.org_id,
                    mail_account_id=mailbox.id,
                    provider_message_id=provider_id,
                    outcome="parse_failed",
                )
                await _mark_processed(provider, provider_id)
                continue
            relevance_result = await relevance_analyzer.analyze(email)
            relevance_details = relevance_result.details or {}
            if relevance_details.get("should_scan") is False:
                store.record_mailbox_message_receipt(
                    org_id=context.org_id,
                    mail_account_id=mailbox.id,
                    provider_message_id=provider_id,
                    outcome="skipped",
                )
                await _mark_processed(provider, provider_id)
                skipped.append(
                    {
                        "provider_id": provider_id,
                        "subject": email.subject or "",
                        "payment_relevance": {
                            "label": relevance_details.get("label"),
                            "confidence": relevance_details.get("confidence"),
                            "summary": relevance_details.get("summary"),
                        },
                    }
                )
                continue
            scan_job_id = store.create_scan_job(
                org_id=context.org_id,
                user_id=context.user_id,
                source=source,
                mail_account_id=mailbox.id,
            )
            reservation = store.reserve_scan_quota(
                org_id=context.org_id,
                user_id=context.user_id,
                idempotency_key=scan_job_id,
                audit_lock=source == "mailbox_scan",
            )
            if not reservation.available:
                store.complete_scan_job(
                    org_id=context.org_id,
                    scan_job_id=scan_job_id,
                    status="failed",
                )
                quota_exhausted = True
                break
            try:
                result = await pipeline.analyze(email, feature_gate=feature_gate)
                timestamp = datetime.now(timezone.utc).isoformat()
                response_payload = payload_builder(email, result, timestamp)
                await add_llm_evidence_summary(
                    store,
                    context,
                    response_payload,
                    api_config=api_config,
                )
                response_payload["source"] = source
                response_payload["mail_account_id"] = mailbox.id
                payment = response_payload.get("payment_protection") or {}
                payment_decision = payment.get("decision") if isinstance(payment, dict) else None
                result_id = store.record_mailbox_scan_completion(
                    org_id=context.org_id,
                    user_id=context.user_id,
                    scan_job_id=scan_job_id,
                    mail_account_id=mailbox.id,
                    provider_message_id=provider_id,
                    email_id=result.email_id,
                    verdict=result.verdict.value,
                    payment_decision=payment_decision,
                    result=response_payload,
                )
            except Exception:
                store.release_scan_quota_reservation(
                    org_id=context.org_id,
                    user_id=context.user_id,
                    idempotency_key=scan_job_id,
                )
                store.complete_scan_job(
                    org_id=context.org_id,
                    scan_job_id=scan_job_id,
                    status="failed",
                )
                raise
            try:
                await alert_stored_scan(
                    store,
                    context,
                    result_id=result_id,
                    payment_decision=payment_decision,
                    operational_alerts=operational_alerts,
                )
            except Exception:
                logger.error(
                    "Operational alert failed after durable mailbox scan completion",
                    exc_info=True,
                )
            await _mark_processed(provider, provider_id)
            analyzed.append(
                {
                    "email_id": result.email_id,
                    "verdict": result.verdict.value,
                    "payment_decision": payment.get("display_decision")
                    or payment.get("decision"),
                    "provider_id": provider_id,
                    "subject": email.subject or "",
                }
            )
        updated_context = store.get_account_context_for_org(
            user_id=context.user_id,
            org_id=context.org_id,
        ) or context
        current_mailbox = store.get_mail_account(
            org_id=context.org_id,
            mail_account_id=mailbox.id,
        ) or mailbox
        return {
            "status": "ok",
            "account": updated_context.to_dict(),
            "mailbox": current_mailbox.to_public_dict(),
            "fetched": len(fetched),
            "analyzed": len(analyzed),
            "skipped": len(skipped),
            "skipped_non_payment": len(skipped),
            "duplicates": duplicate_count,
            "quota_exhausted": quota_exhausted,
            "skipped_results": skipped,
            "results": analyzed,
        }
    finally:
        try:
            await asyncio.to_thread(provider.disconnect)
        except Exception:
            logger.warning("Mailbox disconnect failed after scan", exc_info=True)
