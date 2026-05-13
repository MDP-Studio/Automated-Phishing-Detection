"""Normalize analyzer output for customer-facing scan reports."""

from __future__ import annotations

from typing import Any

from src.billing.entitlements import ANALYZER_FEATURES
from src.billing.plans import get_feature, minimum_plan_for_feature
from src.models import AnalyzerResult


VALID_ANALYZER_STATUSES = {
    "success",
    "failed",
    "timeout",
    "skipped",
    "feature_locked",
    "not_configured",
    "quota_exceeded",
    "cached",
}

VALID_COST_TIERS = {
    "free_local",
    "paid_low",
    "paid_medium",
    "paid_high",
}

LEGACY_COST_TIER_MAP = {
    "local": "free_local",
    "paid_api": "paid_low",
    "llm": "paid_medium",
    "sandbox": "paid_high",
}

ANALYZER_DISPLAY_NAMES = {
    "agent_prompt_injection": "AI instruction safety",
    "attachment_analysis": "Attachment analysis",
    "attachment_sandbox": "Attachment sandbox",
    "brand_impersonation": "Brand impersonation",
    "domain_intelligence": "Domain intelligence",
    "domain_intel": "Domain intelligence",
    "header_analysis": "Header authentication",
    "nlp_intent": "Intent analysis",
    "payment_fraud": "Business email compromise signals",
    "payment_relevance": "Payment relevance",
    "rmm_lure": "Remote access lure detection",
    "sender_profiling": "Sender profiling",
    "url_detonation": "Browser URL detonation",
    "url_reputation": "URL reputation",
}

SKIPPED_MESSAGES = {
    "cold_start",
    "no_attachments",
    "no_email_content",
    "no_email_data",
    "no_sender_information",
    "no_urls_to_analyze",
    "no_urls_to_detonate",
    "not_payment_related",
}

NOT_CONFIGURED_MESSAGES = {
    "no_clients_configured",
    "not_configured",
    "not_implemented",
    "playwright_not_installed",
}


def normalize_analyzer_result(
    analyzer_id: str,
    result: AnalyzerResult,
) -> dict:
    """Return the stable analyzer result contract used by API consumers."""
    details = _safe_details(result.details or {})
    status = _status_for(result, details)
    feature = _feature_metadata(analyzer_id)
    failure_reason = _failure_reason(result, details, status)
    evidence = _evidence_items(
        analyzer_id,
        result,
        details,
        status,
        failure_reason,
    )
    risk_score = _safe_float(result.risk_score)
    confidence = _safe_float(result.confidence)
    risk_contribution = (
        _safe_float(result.risk_contribution)
        if result.risk_contribution is not None
        else round(risk_score * confidence, 4)
    )
    started_at = _safe_timestamp(getattr(result, "started_at", None))
    completed_at = _safe_timestamp(getattr(result, "completed_at", None))
    duration_ms = _duration_ms(result, details)
    cached = (
        status == "cached"
        or bool(getattr(result, "cached", False))
        or _contains_cached_marker(details)
    )

    plan_required = (
        result.plan_required
        if result.plan_required and result.plan_required != "free"
        else feature["plan_required"]
    )
    cost_tier = _normalized_cost_tier(
        getattr(result, "cost_tier", None),
        feature["cost_tier"],
    )

    return {
        "analyzer_id": analyzer_id,
        "display_name": ANALYZER_DISPLAY_NAMES.get(
            analyzer_id,
            _label(analyzer_id),
        ),
        "status": status,
        "plan_required": plan_required,
        "plan_required_name": feature["plan_required_name"],
        "cost_tier": cost_tier,
        "evidence": evidence,
        "risk_contribution": risk_contribution,
        "failure_reason": failure_reason,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_ms": duration_ms,
        "cached": cached,
        "timing": {
            "duration_ms": duration_ms,
        },
        "risk_score": risk_score,
        "confidence": confidence,
        "details": details,
        "errors": result.errors if result.errors else None,
    }


def not_configured_analyzer_result(
    analyzer_id: str,
    reason: str,
) -> AnalyzerResult:
    """Represent an analyzer that could not be loaded or configured."""
    feature = _feature_metadata(analyzer_id)
    return AnalyzerResult(
        analyzer_name=analyzer_id,
        risk_score=0.0,
        confidence=0.0,
        details={"message": "not_configured", "reason": reason},
        errors=[reason],
        status="not_configured",
        plan_required=feature["plan_required"],
        cost_tier=feature["cost_tier"],
        risk_contribution=0.0,
        failure_reason=reason,
        started_at=_utc_iso(),
        completed_at=_utc_iso(),
        timing_ms=0.0,
    )


def failed_analyzer_result(
    analyzer_id: str,
    reason: str,
    *,
    status: str = "failed",
    risk_score: float = 0.5,
    timing_ms: float | None = None,
) -> AnalyzerResult:
    """Represent analyzer failure without letting it vote on the verdict."""
    feature = _feature_metadata(analyzer_id)
    normalized_status = (
        status
        if status in VALID_ANALYZER_STATUSES
        else "failed"
    )
    message = "timeout" if normalized_status == "timeout" else "failed"
    return AnalyzerResult(
        analyzer_name=analyzer_id,
        risk_score=risk_score,
        confidence=0.0,
        details={"message": message, "error": reason},
        errors=[reason],
        status=normalized_status,
        plan_required=feature["plan_required"],
        cost_tier=feature["cost_tier"],
        risk_contribution=0.0,
        failure_reason=reason,
        timing_ms=timing_ms,
        started_at=_utc_iso(),
        completed_at=_utc_iso(),
    )


def skipped_analyzer_result(
    analyzer_id: str,
    reason: str,
    *,
    details: dict | None = None,
) -> AnalyzerResult:
    """Represent an analyzer intentionally skipped by a preflight gate."""
    feature = _feature_metadata(analyzer_id)
    payload = {
        "message": "not_payment_related",
        "reason": reason,
        **(details or {}),
    }
    return AnalyzerResult(
        analyzer_name=analyzer_id,
        risk_score=0.0,
        confidence=0.0,
        details=payload,
        status="skipped",
        plan_required=feature["plan_required"],
        cost_tier=feature["cost_tier"],
        risk_contribution=0.0,
        failure_reason=None,
        timing_ms=0.0,
        started_at=_utc_iso(),
        completed_at=_utc_iso(),
        evidence=[{"type": "summary", "text": reason}],
    )


def _feature_metadata(analyzer_id: str) -> dict:
    feature_slug = ANALYZER_FEATURES.get(analyzer_id, "")
    if not feature_slug:
        return {
            "feature_slug": "",
            "plan_required": "free",
            "plan_required_name": "Free",
            "cost_tier": "free_local",
        }
    try:
        feature = get_feature(feature_slug)
        plan = minimum_plan_for_feature(feature_slug)
    except KeyError:
        return {
            "feature_slug": feature_slug,
            "plan_required": "free",
            "plan_required_name": "Free",
            "cost_tier": "free_local",
        }
    return {
        "feature_slug": feature_slug,
        "plan_required": feature.minimum_plan,
        "plan_required_name": plan.name,
        "cost_tier": _cost_tier(feature_slug, feature.expensive),
    }


def _cost_tier(feature_slug: str, expensive: bool) -> str:
    if feature_slug == "llm_intent":
        return "paid_medium"
    if feature_slug in {"url_detonation", "attachment_sandbox"}:
        return "paid_high"
    if expensive:
        return "paid_low"
    return "free_local"


def _normalized_cost_tier(value: Any, fallback: str) -> str:
    candidate = str(value or "").strip().lower()
    if candidate in VALID_COST_TIERS and candidate != "free_local":
        return candidate
    if candidate == "free_local":
        return fallback if fallback in VALID_COST_TIERS else "free_local"
    if candidate == "local":
        return fallback if fallback in VALID_COST_TIERS else "free_local"
    if candidate in LEGACY_COST_TIER_MAP:
        return LEGACY_COST_TIER_MAP[candidate]
    return fallback if fallback in VALID_COST_TIERS else "free_local"


def _status_for(result: AnalyzerResult, details: dict) -> str:
    message = str(
        details.get("message") or details.get("status") or "",
    ).strip().lower()
    errors = _errors(result)
    explicit = str(getattr(result, "status", "") or "").strip().lower()

    if explicit in VALID_ANALYZER_STATUSES and explicit != "success":
        return explicit
    if getattr(result, "cached", False):
        return "cached"
    if message == "feature_locked":
        return "feature_locked"
    if message in NOT_CONFIGURED_MESSAGES:
        return "not_configured"
    if message in SKIPPED_MESSAGES:
        return "skipped"
    if "quota" in message and "exceed" in message:
        return "quota_exceeded"
    if details.get("cached") is True or _contains_cached_marker(details):
        return "cached"
    if "timeout" in message or any(
        "timeout" in error.lower() or "timed out" in error.lower()
        for error in errors
    ):
        return "timeout"
    if errors or details.get("error") or message == "error":
        return "failed"
    return "success"


def _failure_reason(
    result: AnalyzerResult,
    details: dict,
    status: str,
) -> str | None:
    if status in {"success", "cached", "skipped"}:
        return None
    if result.failure_reason:
        return result.failure_reason
    errors = _errors(result)
    if errors:
        return errors[0]
    if details.get("reason"):
        return str(details["reason"])
    if details.get("error"):
        return str(details["error"])
    if status == "feature_locked":
        return str(details.get("reason") or "Feature is locked for this plan.")
    return None


def _evidence_items(
    analyzer_id: str,
    result: AnalyzerResult,
    details: dict,
    status: str,
    failure_reason: str | None,
) -> list[dict]:
    evidence: list[dict] = []
    for item in result.evidence or []:
        if isinstance(item, dict):
            text = str(item.get("text") or item.get("value") or "").strip()
            if text:
                evidence.append({
                    "type": str(item.get("type") or "evidence"),
                    "text": text,
                })
        elif item:
            evidence.append({"type": "evidence", "text": str(item)})

    if status == "feature_locked":
        evidence.append({
            "type": "plan",
            "text": str(
                details.get("reason")
                or "This check is available on a higher plan.",
            ),
        })
    if failure_reason and status in {
        "failed",
        "timeout",
        "not_configured",
        "quota_exceeded",
    }:
        evidence.append({"type": status, "text": failure_reason})

    _append_message_evidence(evidence, details)
    if analyzer_id == "header_analysis":
        _append_header_evidence(evidence, details)
    if analyzer_id == "payment_fraud" and details.get("decision"):
        evidence.append({
            "type": "decision",
            "text": f"Decision signal: {_payment_decision_label(details['decision'])}",
        })
    if isinstance(details.get("red_flags"), list):
        for flag in details["red_flags"][:3]:
            evidence.append({"type": "red_flag", "text": str(flag)})
    if isinstance(details.get("signals"), list):
        for signal in details["signals"][:3]:
            if isinstance(signal, dict):
                text = signal.get("evidence") or signal.get("name")
            else:
                text = str(signal)
            if text:
                evidence.append({"type": "signal", "text": str(text)})
    if isinstance(details.get("urls_analyzed"), dict):
        evidence.append({
            "type": "url_count",
            "text": f"{len(details['urls_analyzed'])} URL(s) analyzed.",
        })

    if not evidence:
        if status == "success":
            evidence.append({
                "type": "summary",
                "text": (
                    "Analyzer completed and returned no notable risk "
                    "signal."
                ),
            })
        elif status == "skipped":
            evidence.append({
                "type": "summary",
                "text": (
                    "Analyzer skipped because this email did not contain "
                    "the required input."
                ),
            })
    return evidence[:8]


def _append_message_evidence(evidence: list[dict], details: dict) -> None:
    for key in ("summary", "reason"):
        value = details.get(key)
        if value:
            evidence.append({"type": key, "text": str(value)})
    message = str(details.get("message") or "").strip()
    if message and message not in {"feature_locked", "failed"}:
        evidence.append({"type": "message", "text": _label(message)})


def _append_header_evidence(evidence: list[dict], details: dict) -> None:
    for key, label in (
        ("spf_pass", "SPF"),
        ("dkim_pass", "DKIM"),
        ("dmarc_pass", "DMARC"),
    ):
        value = details.get(key)
        if value is True:
            evidence.append({"type": "auth", "text": f"{label} passed."})
        elif value is False:
            evidence.append({"type": "auth", "text": f"{label} failed."})
    if details.get("from_reply_to_mismatch"):
        evidence.append({
            "type": "sender",
            "text": "Reply-to does not match the visible sender.",
        })
    if details.get("display_name_spoofing"):
        evidence.append({
            "type": "sender",
            "text": "Display name appears to imitate a known brand.",
        })


def _safe_details(details: dict[str, Any]) -> dict:
    safe_details = {}
    for key, value in details.items():
        normalized_key = str(key).lower()
        if any(secret in normalized_key for secret in (
            "api_key",
            "authorization",
            "credential",
            "password",
            "secret",
            "token",
        )):
            safe_details[key] = "(redacted)"
            continue
        if key == "screenshots":
            safe_details[key] = {
                url: "(base64 image)"
                for url in (value or {})
            }
        elif isinstance(value, bytes):
            safe_details[key] = "(binary data)"
        else:
            safe_details[key] = value
    return safe_details


def _contains_cached_marker(value: Any) -> bool:
    if isinstance(value, dict):
        if value.get("cached") is True:
            return True
        return any(_contains_cached_marker(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_cached_marker(item) for item in value)
    return False


def _errors(result: AnalyzerResult) -> list[str]:
    if not result.errors:
        return []
    if isinstance(result.errors, list):
        return [str(item) for item in result.errors if item]
    return [str(result.errors)]


def _safe_float(value: Any) -> float:
    try:
        return round(float(value or 0.0), 4)
    except (TypeError, ValueError):
        return 0.0


def _duration_ms(result: AnalyzerResult, details: dict) -> float | None:
    for value in (
        getattr(result, "timing_ms", None),
        getattr(result, "duration_ms", None),
        details.get("duration_ms"),
        details.get("timing_ms"),
    ):
        if value is not None:
            return _safe_float(value)
    timing = details.get("timing")
    if isinstance(timing, dict) and timing.get("duration_ms") is not None:
        return _safe_float(timing.get("duration_ms"))
    return None


def _safe_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    text = str(value).strip()
    return text or None


def _utc_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _payment_decision_label(value: Any) -> str:
    decision = str(value or "").upper()
    if decision in {"DO_NOT_PAY", "DO_NOT_PAY_UNTIL_VERIFIED"}:
        return "Do not pay until independently confirmed"
    if decision == "VERIFY":
        return "Verify out of band"
    if decision == "SAFE":
        return "Safe to continue normal checks"
    return _label(str(value or "Payment risk"))


def _label(value: str) -> str:
    return str(value or "").replace("_", " ").replace("-", " ").strip().title()
