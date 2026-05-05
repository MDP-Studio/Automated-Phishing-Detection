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

ANALYZER_DISPLAY_NAMES = {
    "attachment_analysis": "Attachment analysis",
    "attachment_sandbox": "Attachment sandbox",
    "brand_impersonation": "Brand impersonation",
    "domain_intelligence": "Domain intelligence",
    "domain_intel": "Domain intelligence",
    "header_analysis": "Header authentication",
    "nlp_intent": "Intent analysis",
    "payment_fraud": "BEC and payment-language signals",
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

    plan_required = (
        result.plan_required
        if result.plan_required and result.plan_required != "free"
        else feature["plan_required"]
    )
    cost_tier = (
        result.cost_tier
        if result.cost_tier and result.cost_tier != "local"
        else feature["cost_tier"]
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
        "timing": {
            "duration_ms": _safe_float(result.timing_ms)
            if result.timing_ms is not None
            else None,
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
    )


def _feature_metadata(analyzer_id: str) -> dict:
    feature_slug = ANALYZER_FEATURES.get(analyzer_id, "")
    if not feature_slug:
        return {
            "feature_slug": "",
            "plan_required": "free",
            "plan_required_name": "Free",
            "cost_tier": "local",
        }
    try:
        feature = get_feature(feature_slug)
        plan = minimum_plan_for_feature(feature_slug)
    except KeyError:
        return {
            "feature_slug": feature_slug,
            "plan_required": "free",
            "plan_required_name": "Free",
            "cost_tier": "local",
        }
    return {
        "feature_slug": feature_slug,
        "plan_required": feature.minimum_plan,
        "plan_required_name": plan.name,
        "cost_tier": _cost_tier(feature_slug, feature.expensive),
    }


def _cost_tier(feature_slug: str, expensive: bool) -> str:
    if feature_slug == "llm_intent":
        return "llm"
    if feature_slug in {"url_detonation", "attachment_sandbox"}:
        return "sandbox"
    if expensive:
        return "paid_api"
    return "local"


def _status_for(result: AnalyzerResult, details: dict) -> str:
    message = str(
        details.get("message") or details.get("status") or "",
    ).strip().lower()
    errors = _errors(result)
    explicit = str(getattr(result, "status", "") or "").strip().lower()

    if explicit in VALID_ANALYZER_STATUSES and explicit != "success":
        return explicit
    if message == "feature_locked":
        return "feature_locked"
    if message in NOT_CONFIGURED_MESSAGES:
        return "not_configured"
    if message in SKIPPED_MESSAGES:
        return "skipped"
    if "quota" in message and "exceed" in message:
        return "quota_exceeded"
    if details.get("cached") is True:
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
            "text": f"Decision signal: {details['decision']}",
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


def _label(value: str) -> str:
    return str(value or "").replace("_", " ").replace("-", " ").strip().title()
