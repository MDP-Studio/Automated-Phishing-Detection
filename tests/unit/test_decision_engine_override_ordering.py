"""
Regression tests for the override-rule ordering in decision_engine.

Cycle 6 discovered that `_check_override_rules` evaluated `_is_clean_email`
BEFORE `_is_bec_threat`. A pure-text BEC email — the highest-risk variant
where an attacker uses a compromised legitimate account to send a wire
request with NO URLs and NO attachments — exactly matches `_is_clean_email`:

    - SPF + DKIM + DMARC all pass (legit compromised account)
    - url_count == 0 (pure text)
    - attachment_count == 0 (pure text)
    - sender_profiling risk low (legit sender)

Under the old ordering, `_is_clean_email` force-marked the email CLEAN
before the BEC override ever ran. Real BEC samples in
`tests/real_world_samples/` slipped through this hole only because they
happened to carry at least one URL, making the failure a load-bearing
accident rather than a visible bug.

Cycle 7 reorders: `_is_bec_threat` (Rule 3) now runs BEFORE
`_is_clean_email` (Rule 4). This file locks the new ordering with the
explicit test case that exercises the fix — the test that SHOULD have
caught the bug if it had existed before cycle 6.

Every test in this file uses a synthetic pure-text BEC shape (no URLs,
no attachments, passing auth) so the regression is visible in isolation
and does not depend on any real sample continuing to contain URLs.
"""
from __future__ import annotations

import pytest

from src.config import ScoringConfig
from src.models import AnalyzerResult, Verdict
from src.scoring.decision_engine import DecisionEngine


# ─── Fixture helpers ─────────────────────────────────────────────────────────


def _engine() -> DecisionEngine:
    """Engine with the default weight/threshold shape used everywhere."""
    return DecisionEngine(ScoringConfig(
        weights={
            "header_analysis": 0.20,
            "url_reputation": 0.15,
            "domain_intelligence": 0.10,
            "url_detonation": 0.10,
            "brand_impersonation": 0.10,
            "nlp_intent": 0.20,
            "attachment_analysis": 0.10,
            "sender_profiling": 0.05,
        },
        thresholds={
            "CLEAN": (0.0, 0.30),
            "SUSPICIOUS": (0.30, 0.60),
            "LIKELY_PHISHING": (0.60, 0.85),
            "CONFIRMED_PHISHING": (0.85, 1.00),
        },
    ))


def _pure_text_bec_results() -> dict:
    """
    A BEC email that would have been misclassified under the old ordering.

    Conditions:
      - SPF+DKIM+DMARC all pass (legit compromised account)
      - url_count == 0 (pure text, no links)
      - attachment_count == 0 (pure text, no files)
      - nlp_intent: bec_wire_fraud with confidence > 0.8 (the override trigger)
      - sender_profiling: low risk (legit sender)
    """
    return {
        "header_analysis": AnalyzerResult(
            analyzer_name="header_analysis",
            risk_score=0.0,
            confidence=0.9,
            details={
                "header_analysis_detail": {
                    "spf_pass": True, "dkim_pass": True, "dmarc_pass": True,
                },
                "from_address": "ceo@real-company.example",
            },
        ),
        "url_reputation": AnalyzerResult(
            analyzer_name="url_reputation",
            risk_score=0.0, confidence=0.8,
            # url_count == 0 — the critical property for the bug
            details={"url_count": 0, "urls_analyzed": {}},
        ),
        "attachment_analysis": AnalyzerResult(
            analyzer_name="attachment_analysis",
            risk_score=0.0, confidence=0.8,
            details={"attachment_count": 0},
        ),
        "nlp_intent": AnalyzerResult(
            analyzer_name="nlp_intent",
            risk_score=0.95,
            confidence=0.9,
            details={
                "intent_classification": {
                    "category": "bec_wire_fraud",
                    "confidence": 0.9,
                },
            },
        ),
        "domain_intelligence": AnalyzerResult(
            analyzer_name="domain_intelligence", risk_score=0.0, confidence=0.8, details={},
        ),
        "brand_impersonation": AnalyzerResult(
            analyzer_name="brand_impersonation", risk_score=0.0, confidence=0.8, details={},
        ),
        "sender_profiling": AnalyzerResult(
            analyzer_name="sender_profiling", risk_score=0.0, confidence=0.8, details={},
        ),
    }


# ─── The regression test ────────────────────────────────────────────────────


class TestPureTextBecNotMisclassifiedAsClean:
    """
    The test that should have caught NEW-1 before it existed.

    Under the old ordering, this exact input returns CLEAN because
    _is_clean_email matches all its preconditions. Under the new
    ordering, _is_bec_threat matches first and returns LIKELY_PHISHING.
    """

    def test_pure_text_bec_becomes_likely_phishing(self):
        engine = _engine()
        results = _pure_text_bec_results()
        email_data = {"from_address": "ceo@real-company.example"}

        result = engine.score(
            results, email_id="bec-pure-text-test", email_data=email_data,
        )

        assert result.verdict == Verdict.LIKELY_PHISHING, (
            f"pure-text BEC with auth pass should override to LIKELY_PHISHING, "
            f"got {result.verdict}. If this test fails, the override ordering "
            f"has regressed — see decision_engine.py::_check_override_rules "
            f"and docs/adr/0001 §'Cycle 7 NEW-1 fix'."
        )
        assert "Business Email Compromise" in result.reasoning

    def test_clean_email_path_still_works_for_truly_clean_mail(self):
        """The reorder must not break legitimate CLEAN classification.

        A legitimate text-only email with passing auth and no URLs must
        still return CLEAN — the only difference from the BEC case is
        that nlp_intent reports 'legitimate' instead of 'bec_wire_fraud'.
        """
        engine = _engine()
        results = _pure_text_bec_results()
        # Flip the intent — same email shape but legitimate content
        results["nlp_intent"] = AnalyzerResult(
            analyzer_name="nlp_intent",
            risk_score=0.1,
            confidence=0.9,
            details={
                "intent_classification": {
                    "category": "legitimate",
                    "confidence": 0.9,
                },
            },
        )
        email_data = {"from_address": "alice@real-company.example"}

        result = engine.score(
            results, email_id="clean-test", email_data=email_data,
        )

        assert result.verdict == Verdict.CLEAN, (
            f"Legitimate pure-text email should still return CLEAN, "
            f"got {result.verdict}."
        )

    def test_bec_with_low_confidence_falls_through_to_clean(self):
        """
        BEC override requires confidence > 0.8. An email that LOOKS like
        BEC but the NLP isn't sure (confidence 0.5) should not match the
        override — and with no other signals, should fall to the CLEAN
        path. This documents the boundary of the override.
        """
        engine = _engine()
        results = _pure_text_bec_results()
        results["nlp_intent"] = AnalyzerResult(
            analyzer_name="nlp_intent",
            risk_score=0.7,
            confidence=0.5,  # below 0.8 BEC override threshold
            details={
                "intent_classification": {
                    "category": "bec_wire_fraud",
                    "confidence": 0.5,
                },
            },
        )
        email_data = {"from_address": "ceo@real-company.example"}

        result = engine.score(
            results, email_id="bec-low-conf-test", email_data=email_data,
        )

        # BEC override did NOT fire (confidence too low), so the clean
        # override is the next check — and it should match. This is
        # arguably a hole (a low-confidence BEC signal against an
        # otherwise-clean email still returns CLEAN), but the cap on BEC
        # confidence is intentional and documented in the override rule.
        # Locking this behaviour so a future tightening is a deliberate
        # decision, not an accidental regression.
        assert result.verdict == Verdict.CLEAN


class TestOverrideRuleOrderingExplicit:
    """
    Explicit sanity test that the BEC check runs before _is_clean_email.
    Doesn't just check the output verdict — looks at the reasoning string
    to confirm which rule fired. This catches the case where a refactor
    moves the check but produces the same verdict by accident.
    """

    def test_bec_override_reasoning_not_clean_reasoning(self):
        engine = _engine()
        result = engine.score(
            _pure_text_bec_results(),
            email_id="bec-ordering-test",
            email_data={"from_address": "ceo@real-company.example"},
        )
        # The reasoning string comes from the override that fired.
        assert "Business Email Compromise" in result.reasoning
        assert "All authentication checks passed" not in result.reasoning
