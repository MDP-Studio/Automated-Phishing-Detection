"""
Cross-analyzer calibration pass for the decision engine.

Pass-2 calibration runs after pass-1 analyzer aggregation but before final
threshold mapping. It does NOT re-run analyzers, does NOT call external
APIs, does NOT touch the network. It is pure data manipulation over the
already-computed `AnalyzerResult` dict.

The motivating bug: legitimate LinkedIn engagement notifications score
high on `nlp_intent` (correct in isolation: the language IS what phishing
uses) and low on every other signal (correct in isolation: the email is
auth-passing from linkedin.com). Single-pass scoring averages these into
a SUSPICIOUS verdict that's the wrong answer.

The fix: a calibration rule that fires when `header_analysis` confirms
SPF+DKIM+DMARC pass from a known social platform domain, AND `nlp_intent`
is the only analyzer above its risk threshold. The rule caps the verdict
at SUSPICIOUS (it does NOT reduce the score), so a reviewer reading the
JSON can still see why the analyzer was alarmed. As soon as ANY non-NLP
analyzer reports independent risk, the cap is lifted (corroboration
rule — see ADR 0001 §"The corroboration formulation").

This module implements the rule, the registry, and the entry point. New
rules go here as additional callable instances appended to `REGISTRY`.

See `docs/adr/0001-cross-analyzer-context-passing.md` for the full design
decisions, the failure modes, and the explicit ban on:
  - calling the network from a calibration rule
  - having more than 10 rules in the registry
  - shipping a rule without a positive AND a negative test row

The 10-rule cap is enforced in `tests/unit/test_calibration.py`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from src.models import AnalyzerResult, Verdict
from src.scoring.social_platform_domains import is_social_platform_domain

logger = logging.getLogger(__name__)


# Hard cap from ADR 0001 §FM1. Enforced by test, not by the runtime.
MAX_CALIBRATION_RULES = 10


# Verdict order so we can compute "min" between two verdicts. CLEAN < ...
_VERDICT_RANK = {
    Verdict.CLEAN: 0,
    Verdict.SUSPICIOUS: 1,
    Verdict.LIKELY_PHISHING: 2,
    Verdict.CONFIRMED_PHISHING: 3,
}


def _min_verdict(a: Verdict, b: Verdict) -> Verdict:
    """Return the lower-severity of two verdicts (used for verdict caps)."""
    return a if _VERDICT_RANK[a] <= _VERDICT_RANK[b] else b


@dataclass
class CalibrationOutcome:
    """
    Result of running the full calibration registry against pass-1 results.

    Recorded on `PipelineResult.details["calibration"]` so reviewers can
    see exactly why a verdict was capped, and so the eval harness can
    plot calibrated-vs-uncalibrated for drift detection.
    """

    rules_fired: list[str] = field(default_factory=list)
    verdict_cap: Optional[Verdict] = None
    score_adjustments: list[tuple[str, float]] = field(default_factory=list)
    reasoning_lines: list[str] = field(default_factory=list)

    @property
    def fired(self) -> bool:
        return bool(self.rules_fired)

    def to_dict(self) -> dict:
        """Serializable form for embedding in PipelineResult.details."""
        return {
            "rules_fired": list(self.rules_fired),
            "verdict_cap": self.verdict_cap.value if self.verdict_cap else None,
            "score_adjustments": [
                {"rule_id": rid, "delta": delta}
                for rid, delta in self.score_adjustments
            ],
            "reasoning_lines": list(self.reasoning_lines),
        }


# A calibration rule is a callable that takes the analyzer results dict
# (and optional email metadata) and mutates a CalibrationOutcome in place.
# Returning None is fine — the outcome is the side-effect carrier.
CalibrationRule = Callable[[dict, "CalibrationOutcome", Optional[dict]], None]


# ─── Helpers used by rules ───────────────────────────────────────────────────


def _result(results: dict, name: str) -> Optional[AnalyzerResult]:
    """Get an analyzer result by name, returning None for missing or zero-conf."""
    r = results.get(name)
    if r is None:
        return None
    if r.confidence == 0.0:
        return None
    return r


def _all_auth_pass(header_result: AnalyzerResult) -> bool:
    """True iff SPF, DKIM, AND DMARC all report pass."""
    if header_result is None:
        return False
    detail = (header_result.details or {}).get("header_analysis_detail", {})
    return bool(
        detail.get("spf_pass") is True
        and detail.get("dkim_pass") is True
        and detail.get("dmarc_pass") is True
    )


def _from_domain(results: dict, email_data: Optional[dict]) -> str:
    """
    Best-effort extraction of the From: domain.

    Looks first in email_data (passed by DecisionEngine.score), then in
    the header_analysis result details. Returns "" if neither has it.
    """
    if email_data:
        addr = email_data.get("from_address") or email_data.get("from") or ""
        if "@" in addr:
            return addr.rsplit("@", 1)[1].strip().lower()

    header_result = results.get("header_analysis")
    if header_result and header_result.details:
        addr = header_result.details.get("from_address", "")
        if "@" in addr:
            return addr.rsplit("@", 1)[1].strip().lower()

    return ""


def _has_independent_corroboration(
    results: dict,
    excluded_analyzer: str,
    risk_threshold: float = 0.5,
    confidence_threshold: float = 0.5,
) -> bool:
    """
    Return True if any analyzer OTHER than `excluded_analyzer` reports
    risk_score >= risk_threshold and confidence >= confidence_threshold.

    This is the corroboration check from ADR 0001. If even one analyzer
    independent of the excluded one says "this is risky", the calibration
    rule's verdict cap is NOT applied, because we have an independent
    signal that doesn't depend on the analyzer the rule is dampening.
    """
    for name, r in results.items():
        if name == excluded_analyzer:
            continue
        if r is None or r.confidence == 0.0:
            continue
        if r.risk_score >= risk_threshold and r.confidence >= confidence_threshold:
            return True
    return False


# ─── Rules ───────────────────────────────────────────────────────────────────


def linkedin_social_platform_corroboration(
    results: dict,
    outcome: CalibrationOutcome,
    email_data: Optional[dict] = None,
) -> None:
    """
    Rule ID: linkedin_social_platform_corroboration

    FIRES WHEN:
      - header_analysis reports SPF+DKIM+DMARC all pass
      - From: domain is on the social-platform allowlist
      - nlp_intent reports risk_score >= 0.7 with confidence >= 0.5
      - NO other analyzer independently reports risk_score >= 0.5 / conf >= 0.5

    EFFECT:
      Caps verdict at SUSPICIOUS. The underlying weighted score is NOT
      modified — a reviewer can still see "yes, NLP said this looks like
      phishing language" in the JSON.

    DOES NOT FIRE WHEN:
      - The From: domain is a typo squat (linkedln-mail.com etc.)
      - Auth checks failed (so a spoof can't bypass)
      - Any non-NLP analyzer has independent risk evidence (corroboration met)

    Test rows in tests/unit/test_calibration.py — row 1 (positive), row 2
    (typo squat negative), row 3 (corroboration lifts cap).
    """
    rule_id = "linkedin_social_platform_corroboration"

    header = _result(results, "header_analysis")
    if not _all_auth_pass(header):
        return

    domain = _from_domain(results, email_data)
    if not is_social_platform_domain(domain):
        return

    nlp = _result(results, "nlp_intent")
    if nlp is None:
        return
    if nlp.risk_score < 0.7 or nlp.confidence < 0.5:
        return

    # Corroboration check — if anything else flagged risk, the cap is NOT
    # applied. This is the central design choice from the ADR.
    if _has_independent_corroboration(results, excluded_analyzer="nlp_intent"):
        logger.info(
            "[calibration] %s: domain %s is on allowlist and auth passes, "
            "but independent corroboration found — cap NOT applied",
            rule_id, domain,
        )
        return

    # All preconditions met: cap the verdict at SUSPICIOUS.
    outcome.rules_fired.append(rule_id)
    outcome.verdict_cap = (
        _min_verdict(outcome.verdict_cap, Verdict.SUSPICIOUS)
        if outcome.verdict_cap is not None
        else Verdict.SUSPICIOUS
    )
    outcome.reasoning_lines.append(
        f"Calibration: {rule_id} fired — auth-passing mail from {domain} "
        f"(allowlisted social platform), nlp_intent risk={nlp.risk_score:.2f} "
        f"with no independent corroboration; verdict capped at SUSPICIOUS."
    )
    logger.info(
        "[calibration] %s fired for domain %s (nlp=%.2f, no corroboration)",
        rule_id, domain, nlp.risk_score,
    )


# ─── Registry ────────────────────────────────────────────────────────────────


# Order matters only insofar as later rules see the outcome of earlier rules
# (e.g. a stricter cap is applied via _min_verdict).
REGISTRY: list[CalibrationRule] = [
    linkedin_social_platform_corroboration,
]


def apply_calibration_rules(
    results: dict,
    email_data: Optional[dict] = None,
) -> CalibrationOutcome:
    """
    Run every registered calibration rule against the pass-1 results.

    Args:
        results: dict of {analyzer_name: AnalyzerResult} from pass 1.
        email_data: optional metadata (from_address, subject, etc.) the
            decision engine passes through. Rules that need the From:
            domain look here first.

    Returns:
        CalibrationOutcome aggregating fires from every rule.
    """
    outcome = CalibrationOutcome()
    for rule in REGISTRY:
        try:
            rule(results, outcome, email_data)
        except Exception:
            # A buggy rule must not break the pipeline. Log and continue.
            logger.exception(
                "[calibration] rule %s raised an exception",
                getattr(rule, "__name__", repr(rule)),
            )
    return outcome
