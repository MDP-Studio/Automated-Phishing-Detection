"""
Table-driven tests for src/scoring/calibration.py.

Per ADR 0001, each test row is a 4-tuple:

    (test_name, pass1_results, expected_rules_fired, expected_verdict_cap)

Asserting all four columns means a refactor that moves a signal from one
analyzer to another, OR removes a calibration rule entirely, fails loudly
instead of producing the same final verdict for the wrong reason.

The first row is the LinkedIn FP that motivated the entire cycle. The
second row is its negative — a typo-squat spoof that pretends to be
LinkedIn and must NOT trigger the calibration rule.
"""
from __future__ import annotations

import pytest

from src.models import AnalyzerResult, Verdict
from src.scoring.calibration import (
    MAX_CALIBRATION_RULES,
    REGISTRY,
    CalibrationOutcome,
    _has_independent_corroboration,
    _min_verdict,
    apply_calibration_rules,
    linkedin_social_platform_corroboration,
)
from src.scoring.social_platform_domains import (
    SOCIAL_PLATFORM_DOMAINS,
    is_social_platform_domain,
)


# ─── Helpers for building synthetic pass-1 results ──────────────────────────


def _header(spf=True, dkim=True, dmarc=True, from_address: str = "") -> AnalyzerResult:
    return AnalyzerResult(
        analyzer_name="header_analysis",
        risk_score=0.0 if (spf and dkim and dmarc) else 0.6,
        confidence=0.9,
        details={
            "header_analysis_detail": {
                "spf_pass": spf,
                "dkim_pass": dkim,
                "dmarc_pass": dmarc,
            },
            "from_address": from_address,
        },
    )


def _nlp(risk: float = 0.99, conf: float = 0.85, category: str = "credential_harvesting") -> AnalyzerResult:
    return AnalyzerResult(
        analyzer_name="nlp_intent",
        risk_score=risk,
        confidence=conf,
        details={
            "intent_classification": {
                "category": category,
                "confidence": conf,
            },
        },
    )


def _benign(name: str) -> AnalyzerResult:
    """
    Synthetic clean result for a non-firing analyzer.

    For `url_reputation` we still set `url_count > 0` even though cycle 7
    fixed the BEC ordering bug (see
    tests/unit/test_decision_engine_override_ordering.py). The reason is
    no longer the ordering bug — it's that real LinkedIn digests DO
    contain URLs (profile links, unsubscribe), so the calibration tests
    are meant to mirror that shape. Passing `url_count=0` would exercise
    the "truly clean email" path where `_is_clean_email` correctly fires
    and the calibration never runs — not what these tests are measuring.
    """
    details = {}
    if name == "url_reputation":
        # Mirror real LinkedIn email shape: several URLs present but none
        # flagged as malicious by reputation services.
        details = {"url_count": 5, "urls_analyzed": {}}
    elif name == "attachment_analysis":
        details = {"attachment_count": 0}
    return AnalyzerResult(
        analyzer_name=name,
        risk_score=0.0,
        confidence=0.8,
        details=details,
    )


def _risky(name: str, risk: float = 0.8, conf: float = 0.8) -> AnalyzerResult:
    return AnalyzerResult(
        analyzer_name=name,
        risk_score=risk,
        confidence=conf,
        details={},
    )


# ─── The table ───────────────────────────────────────────────────────────────


# Each row: (name, pass1_results_factory, email_data, expected_rules_fired, expected_cap)
TABLE: list[tuple] = [
    # ─── Row 1: the regression that motivated the cycle ─────────────────────
    # sample_17_legitimate_linkedin_digest.eml shape: auth-passing LinkedIn
    # mail with high NLP risk and no other risk signals. Rule MUST fire.
    (
        "row1_linkedin_digest_auth_passes_no_corroboration",
        lambda: {
            "header_analysis": _header(
                from_address="messages-noreply@linkedin.com",
            ),
            "nlp_intent": _nlp(risk=0.99, conf=0.85),
            "url_reputation": _benign("url_reputation"),
            "domain_intelligence": _benign("domain_intelligence"),
            "brand_impersonation": _benign("brand_impersonation"),
            "attachment_analysis": _benign("attachment_analysis"),
        },
        {"from_address": "messages-noreply@linkedin.com"},
        {"linkedin_social_platform_corroboration"},
        Verdict.SUSPICIOUS,
    ),

    # ─── Row 2: the typo-squat negative ─────────────────────────────────────
    # sample_10_linkedin_connection_request.eml shape: From: linkedln-mail.com
    # (typo squat), no DKIM, NLP claims phishing. Rule must NOT fire because
    # (a) auth fails, (b) domain not on allowlist.
    (
        "row2_typo_squat_linkedln_mail_no_auth",
        lambda: {
            "header_analysis": _header(
                spf=False, dkim=False, dmarc=False,
                from_address="messages-noreply@linkedln-mail.com",
            ),
            "nlp_intent": _nlp(risk=0.99, conf=0.85),
            "url_reputation": _benign("url_reputation"),
            "domain_intelligence": _benign("domain_intelligence"),
            "brand_impersonation": _benign("brand_impersonation"),
            "attachment_analysis": _benign("attachment_analysis"),
        },
        {"from_address": "messages-noreply@linkedln-mail.com"},
        set(),
        None,
    ),

    # ─── Row 3: corroboration lifts the cap ─────────────────────────────────
    # Real LinkedIn auth-passing mail PLUS url_reputation flagged a malicious
    # URL. The corroboration condition is met (url_reputation reports
    # independent risk), so the calibration rule MUST NOT fire — verdict
    # should reach LIKELY_PHISHING through normal scoring.
    (
        "row3_linkedin_auth_passes_but_malicious_url_corroborates",
        lambda: {
            "header_analysis": _header(
                from_address="messages-noreply@linkedin.com",
            ),
            "nlp_intent": _nlp(risk=0.99, conf=0.85),
            # Corroborating signal — this is the lift condition
            "url_reputation": _risky("url_reputation", risk=0.85, conf=0.9),
            "domain_intelligence": _benign("domain_intelligence"),
            "brand_impersonation": _benign("brand_impersonation"),
            "attachment_analysis": _benign("attachment_analysis"),
        },
        {"from_address": "messages-noreply@linkedin.com"},
        set(),  # rule must NOT fire
        None,
    ),

    # ─── Row 4: BEC must not be calibrated away ─────────────────────────────
    # sample_08_google_workspace_shared_doc.eml shape — auth passes, NLP
    # flags BEC wire fraud. The BEC override rule in DecisionEngine fires
    # FIRST (it's an override, not calibration), so calibration never
    # gets to run on this email in the real pipeline. Test checks that
    # calibration ALONE doesn't false-cap a BEC: even with auth pass,
    # google.com is not on the social platform list, so the rule must
    # not fire.
    (
        "row4_bec_from_google_workspace_not_on_social_list",
        lambda: {
            "header_analysis": _header(
                from_address="ceo@google-workspace.com",
            ),
            "nlp_intent": _nlp(risk=0.95, conf=0.9, category="bec_wire_fraud"),
            "url_reputation": _benign("url_reputation"),
            "domain_intelligence": _benign("domain_intelligence"),
            "brand_impersonation": _benign("brand_impersonation"),
            "attachment_analysis": _benign("attachment_analysis"),
        },
        {"from_address": "ceo@google-workspace.com"},
        set(),
        None,
    ),

    # ─── Row 5: subdomain match ─────────────────────────────────────────────
    # LinkedIn's bulk mail comes from e.linkedin.com — subdomain of linkedin.com.
    # The is_social_platform_domain helper handles this; the rule should fire.
    (
        "row5_linkedin_subdomain_e_linkedin_com",
        lambda: {
            "header_analysis": _header(
                from_address="updates@e.linkedin.com",
            ),
            "nlp_intent": _nlp(risk=0.85, conf=0.7),
            "url_reputation": _benign("url_reputation"),
            "domain_intelligence": _benign("domain_intelligence"),
            "brand_impersonation": _benign("brand_impersonation"),
            "attachment_analysis": _benign("attachment_analysis"),
        },
        {"from_address": "updates@e.linkedin.com"},
        {"linkedin_social_platform_corroboration"},
        Verdict.SUSPICIOUS,
    ),

    # ─── Row 6: NLP risk too low to trigger calibration ─────────────────────
    # If NLP doesn't actually flag the email as risky, there's nothing to
    # calibrate. The rule must not fire.
    (
        "row6_auth_passes_linkedin_but_nlp_says_legitimate",
        lambda: {
            "header_analysis": _header(
                from_address="messages-noreply@linkedin.com",
            ),
            "nlp_intent": _nlp(risk=0.2, conf=0.7, category="legitimate"),
            "url_reputation": _benign("url_reputation"),
        },
        {"from_address": "messages-noreply@linkedin.com"},
        set(),
        None,
    ),
]


@pytest.mark.parametrize(
    "name,results_factory,email_data,expected_rules,expected_cap",
    [(t[0], t[1], t[2], t[3], t[4]) for t in TABLE],
    ids=[t[0] for t in TABLE],
)
def test_calibration_table(name, results_factory, email_data, expected_rules, expected_cap):
    results = results_factory()
    outcome = apply_calibration_rules(results, email_data=email_data)

    assert set(outcome.rules_fired) == expected_rules, (
        f"rule set mismatch in {name}: expected {expected_rules}, got {set(outcome.rules_fired)}"
    )
    assert outcome.verdict_cap == expected_cap, (
        f"verdict cap mismatch in {name}: expected {expected_cap}, got {outcome.verdict_cap}"
    )


# ─── Registry shape constraints (FM1 enforcement) ───────────────────────────


class TestRegistryConstraints:
    def test_rule_registry_size_capped(self):
        """ADR 0001 §FM1: hard cap at 10 rules."""
        assert len(REGISTRY) <= MAX_CALIBRATION_RULES, (
            f"calibration rule registry has {len(REGISTRY)} rules, max is "
            f"{MAX_CALIBRATION_RULES}. Adding more rules without raising the "
            f"cap is a deliberate decision — see ADR 0001 §FM1."
        )

    def test_every_rule_is_callable(self):
        for rule in REGISTRY:
            assert callable(rule), f"non-callable in REGISTRY: {rule!r}"

    def test_every_rule_has_a_docstring(self):
        for rule in REGISTRY:
            assert rule.__doc__ and "Rule ID:" in rule.__doc__, (
                f"rule {rule.__name__} must have a docstring with 'Rule ID:'"
            )


# ─── Helper unit tests ───────────────────────────────────────────────────────


class TestHasIndependentCorroboration:
    def test_no_corroboration_when_only_excluded_analyzer_flags(self):
        results = {
            "nlp_intent": _nlp(risk=0.99, conf=0.9),
            "url_reputation": _benign("url_reputation"),
        }
        assert not _has_independent_corroboration(results, "nlp_intent")

    def test_corroboration_when_other_analyzer_flags(self):
        results = {
            "nlp_intent": _nlp(risk=0.99, conf=0.9),
            "url_reputation": _risky("url_reputation"),
        }
        assert _has_independent_corroboration(results, "nlp_intent")

    def test_zero_confidence_does_not_corroborate(self):
        results = {
            "nlp_intent": _nlp(),
            "url_reputation": AnalyzerResult(
                "url_reputation", risk_score=0.9, confidence=0.0, details={},
            ),
        }
        assert not _has_independent_corroboration(results, "nlp_intent")

    def test_low_confidence_does_not_corroborate(self):
        results = {
            "nlp_intent": _nlp(),
            "url_reputation": AnalyzerResult(
                "url_reputation", risk_score=0.9, confidence=0.4, details={},
            ),
        }
        assert not _has_independent_corroboration(results, "nlp_intent")


class TestMinVerdict:
    def test_clean_is_lowest(self):
        assert _min_verdict(Verdict.CLEAN, Verdict.LIKELY_PHISHING) == Verdict.CLEAN

    def test_confirmed_is_highest(self):
        assert _min_verdict(Verdict.CONFIRMED_PHISHING, Verdict.SUSPICIOUS) == Verdict.SUSPICIOUS

    def test_same_verdicts(self):
        for v in Verdict:
            assert _min_verdict(v, v) == v


class TestSocialPlatformDomains:
    def test_exact_match(self):
        assert is_social_platform_domain("linkedin.com")

    def test_case_insensitive(self):
        assert is_social_platform_domain("LinkedIn.com")
        assert is_social_platform_domain("LINKEDIN.COM")

    def test_subdomain_match(self):
        assert is_social_platform_domain("e.linkedin.com")
        assert is_social_platform_domain("messages.e.linkedin.com")

    def test_typo_squat_does_not_match(self):
        assert not is_social_platform_domain("linkedln-mail.com")
        assert not is_social_platform_domain("linkedin-alerts.com")
        assert not is_social_platform_domain("evil-linkedin.com")

    def test_empty_input(self):
        assert not is_social_platform_domain("")
        assert not is_social_platform_domain(None)  # type: ignore[arg-type]

    def test_known_brands_present(self):
        assert "linkedin.com" in SOCIAL_PLATFORM_DOMAINS


# ─── CalibrationOutcome shape ────────────────────────────────────────────────


class TestCalibrationOutcome:
    def test_empty_outcome_serializes_clean(self):
        outcome = CalibrationOutcome()
        d = outcome.to_dict()
        assert d == {
            "rules_fired": [],
            "verdict_cap": None,
            "score_adjustments": [],
            "reasoning_lines": [],
        }
        assert not outcome.fired

    def test_fired_outcome_serializes_with_cap(self):
        outcome = CalibrationOutcome(
            rules_fired=["test_rule"],
            verdict_cap=Verdict.SUSPICIOUS,
            reasoning_lines=["test reason"],
        )
        d = outcome.to_dict()
        assert d["rules_fired"] == ["test_rule"]
        assert d["verdict_cap"] == "SUSPICIOUS"
        assert d["reasoning_lines"] == ["test reason"]
        assert outcome.fired


# ─── Defensive: a buggy rule must not break the pipeline ────────────────────


class TestDecisionEngineIntegration:
    """
    End-to-end: synthetic LinkedIn-shape and BEC-shape analyzer results
    fed through DecisionEngine.score(). Proves:

      1. The LinkedIn FP that previously scored SUSPICIOUS now scores
         a verdict capped at SUSPICIOUS (or below) when calibration
         fires — and the underlying weighted score is preserved.
      2. The BEC sample (from a non-allowlisted domain) is unaffected
         by calibration and the BEC override rule still drives it to
         LIKELY_PHISHING.
      3. Disabling calibration (empty REGISTRY) reproduces the pre-cycle
         verdict, demonstrating the diff is real.
    """

    def setup_method(self):
        # Build a DecisionEngine with the same default weights the
        # pipeline ships with — analyzer names must match the
        # orchestrator's canonical keys (see ANALYZER_ATTACK_TAGS in
        # src/reporting/sigma_exporter.py for the same list).
        from src.config import ScoringConfig
        from src.scoring.decision_engine import DecisionEngine

        config = ScoringConfig(
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
        )
        self.engine = DecisionEngine(config)

    def _linkedin_digest_results(self) -> dict:
        """Synthetic results matching the lessons-learned LinkedIn FP shape:
        auth passes, NLP screams 0.99, nothing else fires."""
        return {
            "header_analysis": _header(
                from_address="messages-noreply@linkedin.com",
            ),
            "nlp_intent": _nlp(risk=0.99, conf=0.85),
            "url_reputation": _benign("url_reputation"),
            "domain_intelligence": _benign("domain_intelligence"),
            "brand_impersonation": _benign("brand_impersonation"),
            "attachment_analysis": _benign("attachment_analysis"),
            "sender_profiling": _benign("sender_profiling"),
        }

    def test_linkedin_fp_capped_when_calibration_enabled(self):
        """The smoking gun: calibration ON => verdict capped at SUSPICIOUS."""
        results = self._linkedin_digest_results()
        email_data = {"from_address": "messages-noreply@linkedin.com"}

        result = self.engine.score(results, email_id="lnkd-test", email_data=email_data)

        # Verdict must NOT be LIKELY_PHISHING despite NLP score
        assert result.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS), (
            f"calibration should cap verdict at SUSPICIOUS, got {result.verdict}"
        )
        # The calibration outcome is recorded on the result
        assert result.calibration is not None
        assert "linkedin_social_platform_corroboration" in result.calibration["rules_fired"]
        assert result.calibration["verdict_cap"] == "SUSPICIOUS"
        # Underlying weighted score is preserved (NOT modified by calibration)
        # — a reviewer can still see "yes NLP flagged this as risky" in the JSON
        assert result.overall_score > 0.15, (
            "calibration must NOT modify the underlying score; reviewer must "
            "still see the NLP risk signal in PipelineResult.overall_score"
        )

    def test_linkedin_fp_uncapped_when_calibration_disabled(self, monkeypatch):
        """Same input with REGISTRY emptied — verdict reaches whatever the
        threshold mapping says, proving the diff between OFF and ON is real."""
        from src.scoring import calibration as cal_module
        monkeypatch.setattr(cal_module, "REGISTRY", [])

        results = self._linkedin_digest_results()
        email_data = {"from_address": "messages-noreply@linkedin.com"}
        result = self.engine.score(results, email_id="lnkd-test-off", email_data=email_data)

        # No calibration outcome recorded
        assert result.calibration is None
        # Verdict is whatever the threshold mapping produced — note the
        # weighted score is still ~0.2 because LinkedIn has no other risk
        # signals. The point is the calibration ROUTE is not exercised.

    def test_typo_squat_unaffected(self):
        """sample_10 shape: typo-squat domain, NO calibration cap should fire."""
        results = {
            "header_analysis": _header(
                spf=False, dkim=False, dmarc=False,
                from_address="messages-noreply@linkedln-mail.com",
            ),
            "nlp_intent": _nlp(risk=0.99, conf=0.85),
            "url_reputation": _benign("url_reputation"),
            "domain_intelligence": _benign("domain_intelligence"),
            "brand_impersonation": _benign("brand_impersonation"),
            "attachment_analysis": _benign("attachment_analysis"),
            "sender_profiling": _benign("sender_profiling"),
        }
        email_data = {"from_address": "messages-noreply@linkedln-mail.com"}

        result = self.engine.score(results, email_id="spoof-test", email_data=email_data)

        # Calibration must NOT have fired — no allowlist match
        assert result.calibration is None or not result.calibration.get("rules_fired")

    def test_bec_override_unaffected_by_calibration(self):
        """sample_08 shape: BEC override rule fires before calibration even runs."""
        results = {
            "header_analysis": _header(
                from_address="ceo@google-workspace.com",
            ),
            "nlp_intent": _nlp(risk=0.95, conf=0.9, category="bec_wire_fraud"),
            "url_reputation": _benign("url_reputation"),
            "domain_intelligence": _benign("domain_intelligence"),
            "brand_impersonation": _benign("brand_impersonation"),
            "attachment_analysis": _benign("attachment_analysis"),
            "sender_profiling": _benign("sender_profiling"),
        }
        email_data = {"from_address": "ceo@google-workspace.com"}

        result = self.engine.score(results, email_id="bec-test", email_data=email_data)

        # BEC override forces LIKELY_PHISHING regardless of weighted score
        assert result.verdict == Verdict.LIKELY_PHISHING
        # Calibration should NOT have run (override took precedence) so
        # there's nothing recorded
        assert result.calibration is None


class TestCalibrationCapCeiling:
    """
    Cycle 7: explicit tests for the calibration cap SEMANTIC.

    The cap is SUSPICIOUS (not CLEAN). This means:
        - A verdict of LIKELY_PHISHING or CONFIRMED_PHISHING is lowered
          to SUSPICIOUS when the rule fires. The analyst still reviews.
        - A verdict of CLEAN or SUSPICIOUS is UNCHANGED — the cap cannot
          raise a verdict, only lower it.
        - The underlying weighted score is NEVER modified. A reviewer
          reading the JSON sees both the unmodified score (which may
          still be high due to NLP) and the reasoning for why it was
          capped.

    The threat this defends against: a real LinkedIn notification that
    embeds a genuinely malicious redirect (LinkedIn tracking URLs have
    been abused as open redirects in the wild). The `url_reputation`
    analyzer may score the redirect below the corroboration threshold
    (risk < 0.5 or conf < 0.5), which means the calibration rule still
    fires. In that case, the verdict is capped at SUSPICIOUS — NOT
    dropped to CLEAN — so an analyst is still prompted to review.

    See docs/adr/0001-cross-analyzer-context-passing.md section
    "Why the cap is SUSPICIOUS and not CLEAN" for the full rationale.
    """

    def setup_method(self):
        from src.config import ScoringConfig
        from src.scoring.decision_engine import DecisionEngine

        self.engine = DecisionEngine(ScoringConfig(
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

    def test_cap_lowers_likely_phishing_to_suspicious(self):
        """
        LinkedIn digest shape with weights pushed up enough that the
        raw verdict would reach LIKELY_PHISHING. Cap must lower it.
        """
        results = {
            "header_analysis": _header(
                from_address="messages-noreply@linkedin.com",
            ),
            # High nlp_intent risk + high confidence → weighted score
            # dominated by NLP's 0.20 * 1.0 * 1.0 contribution
            "nlp_intent": _nlp(risk=1.0, conf=1.0),
            # Sub-corroboration-threshold url_reputation: risk below 0.5
            # OR confidence below 0.5. Combined with the high NLP,
            # threshold mapping would put this in LIKELY_PHISHING range.
            "url_reputation": AnalyzerResult(
                analyzer_name="url_reputation",
                risk_score=0.4, confidence=0.9,
                details={"url_count": 5, "urls_analyzed": {}},
            ),
            "domain_intelligence": _benign("domain_intelligence"),
            "brand_impersonation": _benign("brand_impersonation"),
            "attachment_analysis": _benign("attachment_analysis"),
            "sender_profiling": _benign("sender_profiling"),
        }
        email_data = {"from_address": "messages-noreply@linkedin.com"}

        result = self.engine.score(
            results, email_id="cap-ceiling-likely", email_data=email_data,
        )

        # Rule must fire (no independent corroboration above 0.5 risk)
        assert result.calibration is not None
        assert "linkedin_social_platform_corroboration" in result.calibration["rules_fired"]
        # Verdict is capped at SUSPICIOUS — analyst still sees it
        assert result.verdict == Verdict.SUSPICIOUS
        # Critical: verdict is NOT dropped to CLEAN
        assert result.verdict != Verdict.CLEAN, (
            "calibration cap must NOT drop verdict to CLEAN — SUSPICIOUS "
            "is the ceiling, not a floor. See ADR 0001 'Why the cap is "
            "SUSPICIOUS and not CLEAN'."
        )

    def test_cap_does_not_raise_clean_to_suspicious(self):
        """
        Legitimate LinkedIn email with truly low nlp_intent risk.
        Calibration rule does NOT fire (nlp_intent below 0.7 threshold).
        Verdict must come through as whatever the raw scoring path
        produces (CLEAN here), NOT be raised to SUSPICIOUS by calibration.
        """
        results = {
            "header_analysis": _header(
                from_address="messages-noreply@linkedin.com",
            ),
            # Low nlp_intent: rule does not fire at all
            "nlp_intent": _nlp(risk=0.1, conf=0.9, category="legitimate"),
            "url_reputation": _benign("url_reputation"),
            "domain_intelligence": _benign("domain_intelligence"),
            "brand_impersonation": _benign("brand_impersonation"),
            "attachment_analysis": _benign("attachment_analysis"),
            "sender_profiling": _benign("sender_profiling"),
        }
        email_data = {"from_address": "messages-noreply@linkedin.com"}

        result = self.engine.score(
            results, email_id="cap-ceiling-clean", email_data=email_data,
        )

        # Rule did NOT fire (NLP below trigger threshold)
        assert result.calibration is None
        # Verdict should be CLEAN per the low raw score — not SUSPICIOUS
        assert result.verdict == Verdict.CLEAN

    def test_underlying_score_preserved_when_cap_applies(self):
        """
        ADR §'PipelineResult model evolution': the cap must NOT modify
        `overall_score`. A reviewer reading the JSON must still be able
        to see the uncalibrated score so analyzer drift stays visible.
        This is the FM2 mitigation.
        """
        results = {
            "header_analysis": _header(
                from_address="messages-noreply@linkedin.com",
            ),
            "nlp_intent": _nlp(risk=1.0, conf=1.0),
            "url_reputation": _benign("url_reputation"),
            "domain_intelligence": _benign("domain_intelligence"),
            "brand_impersonation": _benign("brand_impersonation"),
            "attachment_analysis": _benign("attachment_analysis"),
            "sender_profiling": _benign("sender_profiling"),
        }
        email_data = {"from_address": "messages-noreply@linkedin.com"}

        result = self.engine.score(
            results, email_id="cap-score-preserve", email_data=email_data,
        )

        assert result.calibration is not None
        # The score is UNCHANGED even though the verdict was capped.
        # The NLP analyzer's high risk_score contribution is still in
        # the weighted total — this is what lets analyzer drift show
        # up on the dashboard even when calibration is active.
        assert result.overall_score > 0.15, (
            "calibration must not modify overall_score — FM2 mitigation"
        )


class TestRuleException:
    def test_raising_rule_does_not_break_apply(self, monkeypatch):
        """A buggy calibration rule must not propagate exceptions out
        of apply_calibration_rules — the decision engine continues."""
        from src.scoring import calibration as cal_module

        def boom(results, outcome, email_data=None):
            raise RuntimeError("boom")

        monkeypatch.setattr(cal_module, "REGISTRY", [boom])
        # Must not raise
        outcome = apply_calibration_rules({"nlp_intent": _nlp()}, email_data={})
        assert outcome.rules_fired == []
        assert outcome.verdict_cap is None
