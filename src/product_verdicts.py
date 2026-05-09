"""Product-facing verdict and explanation helpers.

The analyzer pipeline produces evidence. These helpers translate that evidence
into customer-facing PhishAnalyze and PayShield language without changing the
stored backend enums that tests and datasets already depend on.
"""

from __future__ import annotations

from typing import Any


PHISHANALYZE_NEXT_STEPS = {
    "CLEAN": [
        "Continue normal security hygiene before opening links or attachments.",
        "Keep the scan result in history if this email needs later review.",
    ],
    "SUSPICIOUS": [
        "Do not click links or open attachments until the sender is verified.",
        "Check the sender domain, reply-to address, and URL evidence below.",
    ],
    "LIKELY_PHISHING": [
        "Do not interact with links, attachments, or reply requests.",
        "Report this email through your normal security channel.",
    ],
    "CONFIRMED_PHISHING": [
        "Do not interact with the email.",
        "Report, quarantine, and rotate any exposed credentials if interaction already happened.",
    ],
}

PAYSHIELD_NEXT_STEPS = {
    "NOT_PAYMENT_SPECIFIC": [
        "No payment workflow is needed for this email.",
        "Use the general phishing evidence if the message still looks suspicious.",
    ],
    "SAFE": [
        "Continue normal internal payment checks.",
        "Keep the scan result with the supplier record if the request is material.",
    ],
    "VERIFY": [
        "Pause payment release until the request is verified outside email.",
        "Use a known supplier phone number or previously trusted contact path.",
    ],
    "DO_NOT_PAY_UNTIL_VERIFIED": [
        "Do not pay until independently confirmed.",
        "Escalate the request and verify supplier, invoice, and bank details through a trusted channel.",
    ],
}


def build_product_verdicts(
    *,
    phishing_verdict: str,
    overall_score: float,
    analyzer_results: dict[str, dict],
) -> dict[str, dict]:
    """Return product-specific decisions from normalized analyzer evidence."""
    payment = (analyzer_results.get("payment_fraud") or {}).get("details") or {}
    return {
        "phishanalyze": phishanalyze_verdict(
            phishing_verdict,
            overall_score=overall_score,
            analyzer_results=analyzer_results,
        ),
        "payshield": payshield_verdict(
            payment,
            phishing_verdict=phishing_verdict,
            overall_score=overall_score,
        ),
    }


def phishanalyze_verdict(
    verdict: str,
    *,
    overall_score: float,
    analyzer_results: dict[str, dict],
) -> dict:
    normalized = str(verdict or "SUSPICIOUS").upper()
    if normalized not in PHISHANALYZE_NEXT_STEPS:
        normalized = "SUSPICIOUS"
    return {
        "product": "phishanalyze",
        "verdict": normalized,
        "label": _phishing_label(normalized),
        "summary": _phishing_summary(normalized, analyzer_results),
        "next_steps": PHISHANALYZE_NEXT_STEPS[normalized],
        "score": _safe_score(overall_score),
    }


def payshield_verdict(
    payment_protection: dict | None,
    *,
    phishing_verdict: str,
    overall_score: float,
) -> dict:
    payment_protection = payment_protection or {}
    if _is_non_payment_specific(payment_protection):
        backend_decision = ""
        display_decision = "NOT_PAYMENT_SPECIFIC"
    else:
        backend_decision = str(payment_protection.get("decision") or "").upper()
        display_decision = _payment_display_decision(backend_decision, phishing_verdict)
    return {
        "product": "payshield",
        "backend_decision": backend_decision or None,
        "display_decision": display_decision,
        "label": payment_decision_label(display_decision),
        "summary": _payment_summary(
            display_decision,
            payment_protection.get("summary"),
            phishing_verdict,
        ),
        "next_steps": PAYSHIELD_NEXT_STEPS[display_decision],
        "score": _safe_score(payment_protection.get("risk_score", overall_score)),
    }


def enrich_payment_protection(payment_protection: dict | None, product_verdict: dict) -> dict | None:
    """Add display-safe PayShield fields while preserving raw backend details."""
    if payment_protection is None:
        return None
    enriched = dict(payment_protection)
    enriched["backend_decision"] = enriched.get("decision")
    enriched["display_decision"] = product_verdict["display_decision"]
    enriched["display_label"] = product_verdict["label"]
    enriched["next_steps"] = product_verdict["next_steps"]
    return enriched


def build_evidence_summary(
    *,
    product_verdicts: dict[str, dict],
    analyzer_results: dict[str, dict],
) -> dict:
    """Summarize structured analyzer evidence without deciding the verdict."""
    completed = []
    locked = []
    failures = []
    cached = []
    evidence_lines: list[str] = []

    for analyzer in analyzer_results.values():
        status = str(analyzer.get("status") or "").lower()
        name = analyzer.get("display_name") or analyzer.get("analyzer_id") or "Analyzer"
        if status in {"success", "cached"}:
            completed.append(name)
        if status == "cached":
            cached.append(name)
        elif status == "feature_locked":
            locked.append(name)
        elif status in {"failed", "timeout", "not_configured", "quota_exceeded"}:
            failures.append(name)
        for item in analyzer.get("evidence") or []:
            text = item.get("text") if isinstance(item, dict) else str(item)
            if text:
                evidence_lines.append(str(text))

    phish = product_verdicts.get("phishanalyze", {})
    pay = product_verdicts.get("payshield", {})
    return {
        "source": "structured_analyzer_evidence",
        "llm_backed": _llm_summary_available(analyzer_results),
        "summary": _summary_sentence(phish, pay, completed, locked, failures),
        "supporting_evidence": evidence_lines[:5],
        "completed_checks": completed,
        "locked_checks": locked,
        "failed_checks": failures,
        "cached_checks": cached,
    }


def payment_decision_label(value: Any) -> str:
    decision = str(value or "").upper()
    if decision == "NOT_PAYMENT_SPECIFIC":
        return "Not payment-specific"
    if decision in {"DO_NOT_PAY", "DO_NOT_PAY_UNTIL_VERIFIED"}:
        return "Do not pay until independently confirmed"
    if decision == "VERIFY":
        return "Verify out of band"
    if decision == "SAFE":
        return "Safe to continue normal checks"
    return _label(value or "Review payment request")


def _payment_display_decision(backend_decision: str, phishing_verdict: str) -> str:
    if backend_decision == "DO_NOT_PAY":
        return "DO_NOT_PAY_UNTIL_VERIFIED"
    if backend_decision in {"SAFE", "VERIFY", "DO_NOT_PAY_UNTIL_VERIFIED"}:
        return backend_decision
    if str(phishing_verdict or "").upper() in {"LIKELY_PHISHING", "CONFIRMED_PHISHING"}:
        return "VERIFY"
    return "SAFE"


def _payment_summary(display_decision: str, summary: Any, phishing_verdict: str) -> str:
    if display_decision == "NOT_PAYMENT_SPECIFIC":
        return (
            "This email did not look like an invoice, billing notice, receipt, "
            "bank-detail change, or payment request."
        )
    if summary:
        return str(summary)
    if display_decision == "DO_NOT_PAY_UNTIL_VERIFIED":
        return "High-risk payment indicators were found. Treat this as decision support and verify independently."
    if display_decision == "VERIFY":
        return "Some payment-risk indicators were found. Verify outside email before acting."
    return f"No strong payment-risk signal was found. Pipeline verdict: {_label(phishing_verdict)}."


def _is_non_payment_specific(payment_protection: dict) -> bool:
    message = str(payment_protection.get("message") or "").lower()
    if message == "not_payment_related":
        return True
    relevance = payment_protection.get("payment_relevance")
    if isinstance(relevance, dict):
        return str(relevance.get("label") or "").lower() == "non_payment"
    return False


def _phishing_label(verdict: str) -> str:
    labels = {
        "CLEAN": "Clean",
        "SUSPICIOUS": "Suspicious",
        "LIKELY_PHISHING": "Likely phishing",
        "CONFIRMED_PHISHING": "Confirmed phishing",
    }
    return labels.get(verdict, "Review evidence")


def _phishing_summary(verdict: str, analyzer_results: dict[str, dict]) -> str:
    locked_count = sum(1 for item in analyzer_results.values() if item.get("status") == "feature_locked")
    failed_count = sum(1 for item in analyzer_results.values() if item.get("status") in {"failed", "timeout"})
    if verdict == "CLEAN":
        base = "The available checks did not find strong phishing indicators."
    elif verdict == "SUSPICIOUS":
        base = "The email has suspicious indicators that need review."
    elif verdict == "LIKELY_PHISHING":
        base = "Multiple signals point to a likely phishing attempt."
    else:
        base = "The scan found high-confidence phishing indicators."
    extras = []
    if locked_count:
        extras.append(f"{locked_count} check(s) were locked by plan.")
    if failed_count:
        extras.append(f"{failed_count} check(s) failed or timed out.")
    return " ".join([base, *extras]).strip()


def _summary_sentence(phish: dict, pay: dict, completed: list, locked: list, failures: list) -> str:
    parts = [
        f"PhishAnalyze verdict: {phish.get('label', 'Review evidence')}.",
        f"PayShield decision support: {pay.get('label', 'Review payment request')}.",
        f"{len(completed)} analyzer check(s) completed.",
    ]
    if locked:
        parts.append(f"{len(locked)} check(s) were locked by plan.")
    if failures:
        parts.append(f"{len(failures)} check(s) need admin attention.")
    return " ".join(parts)


def _llm_summary_available(analyzer_results: dict[str, dict]) -> bool:
    result = analyzer_results.get("nlp_intent") or {}
    return result.get("status") in {"success", "cached"} and result.get("cost_tier") == "paid_medium"


def _safe_score(value: Any) -> float:
    try:
        score = float(value or 0.0)
    except (TypeError, ValueError):
        score = 0.0
    return max(0.0, min(round(score, 4), 1.0))


def _label(value: Any) -> str:
    return str(value or "").replace("_", " ").replace("-", " ").strip().title()
