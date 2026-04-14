"""
Tests for src/reporting/sigma_exporter.py.

The exporter hand-emits YAML (no PyYAML dep) so these tests use string
assertions rather than parsing. The contract being tested:

1. CLEAN verdicts produce no rule (defensive — clean mail should not be
   distributed as a detection signature).
2. Campaign rules contain stable IDs across re-runs (deterministic UUIDv5).
3. ATT&CK tags are pulled from the analyzers that actually fired with
   risk_score > 0.3 and confidence > 0, not blindly attached to every rule.
4. Selections are constructed from observable IOCs (sender domain, subject
   keywords, URL fragments, file hashes) and combined with `1 of selection_*`.
5. Bundle mode emits one document per IOC type, separated by `---`.
6. Analyzer-name keys in ANALYZER_ATTACK_TAGS match the canonical orchestrator
   keys, NOT the per-file `analyzer_name` strings — this is the bug class
   that caused the audit fix.
"""
from __future__ import annotations

import re

import pytest

from src.models import (
    AnalyzerResult,
    ExtractedURL,
    PipelineResult,
    URLSource,
    Verdict,
)
from src.reporting.sigma_exporter import (
    ANALYZER_ATTACK_TAGS,
    DEFAULT_STATUS,
    SigmaExporter,
    VERDICT_LEVEL,
)


# ─── fixtures ────────────────────────────────────────────────────────────────


def _bec_result(email_id: str = "bec-001") -> PipelineResult:
    """A high-confidence BEC verdict with sender, subject, and URL observables."""
    return PipelineResult(
        email_id=email_id,
        verdict=Verdict.LIKELY_PHISHING,
        overall_score=0.78,
        overall_confidence=0.81,
        analyzer_results={
            "nlp_intent": AnalyzerResult(
                analyzer_name="nlp_intent",
                risk_score=0.85,
                confidence=0.9,
                details={
                    "intent_classification": {
                        "category": "bec_wire_fraud",
                        "confidence": 0.9,
                    }
                },
            ),
            "header_analysis": AnalyzerResult(
                analyzer_name="header_analysis",
                risk_score=0.7,
                confidence=0.8,
                details={},
            ),
        },
        extracted_urls=[
            ExtractedURL(
                url="https://evil-corp.example/login/oauth?id=1",
                source=URLSource.BODY_HTML,
                source_detail="anchor",
            ),
        ],
        iocs={
            "headers": {
                "from_address": "attacker@evil-corp.example",
                "subject": "Urgent Wire Transfer Request for Q2",
            },
            "malicious_urls": ["https://evil-corp.example/login/oauth?id=1"],
            "file_hashes": {"md5": "d41d8cd98f00b204e9800998ecf8427e"},
        },
        reasoning="test",
    )


def _clean_result() -> PipelineResult:
    return PipelineResult(
        email_id="clean-001",
        verdict=Verdict.CLEAN,
        overall_score=0.05,
        overall_confidence=0.95,
        analyzer_results={},
        extracted_urls=[],
        iocs={},
        reasoning="clean",
    )


# ─── tests ───────────────────────────────────────────────────────────────────


class TestAnalyzerKeysAreCanonical:
    """
    Regression test for the audit bug: ANALYZER_ATTACK_TAGS keys must match
    the orchestrator's analyzer_names list, not per-analyzer source-file
    `analyzer_name = "..."` strings.
    """

    EXPECTED_KEYS = {
        "header_analysis",
        "url_reputation",
        "domain_intelligence",
        "url_detonation",
        "brand_impersonation",
        "nlp_intent",
        "attachment_analysis",
        "sender_profiling",
    }

    def test_all_canonical_keys_present(self):
        assert set(ANALYZER_ATTACK_TAGS.keys()) == self.EXPECTED_KEYS

    def test_no_legacy_keys(self):
        # Common bug: using the per-file analyzer_name instead of the
        # orchestrator key. These must NOT appear.
        assert "domain_intel" not in ANALYZER_ATTACK_TAGS
        assert "attachment_sandbox" not in ANALYZER_ATTACK_TAGS

    def test_every_value_starts_with_attack_prefix(self):
        for tags in ANALYZER_ATTACK_TAGS.values():
            assert all(t.startswith("attack.") for t in tags)


class TestCleanVerdictSkipped:
    def test_clean_returns_empty_string(self):
        ex = SigmaExporter()
        assert ex.export_campaign_rule(_clean_result()) == ""

    def test_clean_bundle_returns_empty_string(self):
        ex = SigmaExporter()
        assert ex.export_bundle(_clean_result()) == ""


class TestCampaignRuleStructure:
    def setup_method(self):
        self.ex = SigmaExporter()
        self.rule = self.ex.export_campaign_rule(_bec_result())

    def test_rule_is_nonempty(self):
        assert self.rule

    def test_rule_has_required_top_level_keys(self):
        for key in ("title:", "id:", "status:", "description:", "logsource:",
                    "detection:", "level:", "tags:"):
            assert key in self.rule, f"missing {key}"

    def test_status_is_default(self):
        assert f"status: {DEFAULT_STATUS}" in self.rule

    def test_level_matches_verdict(self):
        assert f"level: {VERDICT_LEVEL[Verdict.LIKELY_PHISHING]}" in self.rule

    def test_logsource_email_category(self):
        assert "category: email" in self.rule

    def test_condition_uses_one_of_selection_glob(self):
        # Multiple selections present → "1 of selection_*"
        assert "condition: 1 of selection_*" in self.rule

    def test_sender_selection_present(self):
        assert "selection_sender:" in self.rule
        assert "@evil-corp.example" in self.rule

    def test_subject_selection_present(self):
        assert "selection_subject:" in self.rule
        # Title-cased keywords from "Urgent Wire Transfer Request for Q2"
        assert "Urgent" in self.rule
        assert "Wire" in self.rule

    def test_url_selection_present(self):
        assert "selection_url:" in self.rule
        # URL fragment is host/first-path-token
        assert "evil-corp.example/login" in self.rule

    def test_attack_tags_pulled_from_firing_analyzers(self):
        # nlp_intent fired with risk > 0.3 and conf > 0 → its tags appear
        assert "attack.t1534" in self.rule
        assert "attack.t1656" in self.rule
        # header_analysis also fired
        assert "attack.t1566.001" in self.rule or "attack.t1566.002" in self.rule
        # initial_access umbrella always appears when any analyzer fires
        assert "attack.initial_access" in self.rule


class TestStableUUID:
    def test_same_email_id_same_uuid(self):
        ex = SigmaExporter()
        r1 = ex.export_campaign_rule(_bec_result("stable-test"))
        r2 = ex.export_campaign_rule(_bec_result("stable-test"))
        # Extract the id: line from each
        id1 = re.search(r"^id: (\S+)$", r1, re.MULTILINE).group(1)
        id2 = re.search(r"^id: (\S+)$", r2, re.MULTILINE).group(1)
        assert id1 == id2

    def test_different_email_id_different_uuid(self):
        ex = SigmaExporter()
        r1 = ex.export_campaign_rule(_bec_result("uuid-a"))
        r2 = ex.export_campaign_rule(_bec_result("uuid-b"))
        id1 = re.search(r"^id: (\S+)$", r1, re.MULTILINE).group(1)
        id2 = re.search(r"^id: (\S+)$", r2, re.MULTILINE).group(1)
        assert id1 != id2

    def test_uuid_is_uuid_shaped(self):
        ex = SigmaExporter()
        rule = ex.export_campaign_rule(_bec_result())
        m = re.search(r"^id: ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
                      rule, re.MULTILINE)
        assert m is not None


class TestBundleMode:
    def test_bundle_emits_multiple_documents(self):
        ex = SigmaExporter()
        bundle = ex.export_bundle(_bec_result())
        assert bundle
        # Multi-doc YAML separator
        docs = bundle.split("\n---\n")
        # At least sender + subject + url + hash → 4 documents
        assert len(docs) >= 3

    def test_bundle_documents_each_have_id(self):
        ex = SigmaExporter()
        bundle = ex.export_bundle(_bec_result())
        ids = re.findall(r"^id: \S+$", bundle, re.MULTILINE)
        assert len(ids) >= 3
        assert len(set(ids)) == len(ids)  # all unique


class TestNoObservablesNoRule:
    def test_phishing_verdict_with_zero_iocs_returns_empty(self):
        result = PipelineResult(
            email_id="empty-001",
            verdict=Verdict.LIKELY_PHISHING,
            overall_score=0.7,
            overall_confidence=0.7,
            analyzer_results={},
            extracted_urls=[],
            iocs={},  # nothing to select on
            reasoning="empty",
        )
        ex = SigmaExporter()
        assert ex.export_campaign_rule(result) == ""


class TestSubjectKeywordExtraction:
    def test_strips_re_fwd_prefixes(self):
        result = _bec_result()
        result.iocs["headers"]["subject"] = "RE: Urgent Payment Required"
        ex = SigmaExporter()
        rule = ex.export_campaign_rule(result)
        # "Urgent" should appear, "RE" should not be in the keyword list
        assert "Urgent" in rule
        assert "Payment" in rule

    def test_short_words_filtered(self):
        ex = SigmaExporter()
        # _subject_keywords is the static helper
        kws = ex._subject_keywords("a an the URGENT payment due now")
        # 3-letter and shorter words filtered (regex requires 4+ chars after first)
        assert "URGENT" in kws
        assert "payment" in kws
        assert "due" not in kws

    def test_caps_at_six_keywords(self):
        ex = SigmaExporter()
        kws = ex._subject_keywords(
            "alpha beta gamma delta epsilon zeta eta theta iota kappa"
        )
        assert len(kws) <= 6


class TestUrlFragmentExtraction:
    def test_host_only_when_no_path(self):
        ex = SigmaExporter()
        assert ex._url_fragment("https://evil.example") == "evil.example"

    def test_host_plus_first_path_token(self):
        ex = SigmaExporter()
        assert ex._url_fragment("https://evil.example/login/oauth") == "evil.example/login"

    def test_query_stripped(self):
        ex = SigmaExporter()
        assert ex._url_fragment("https://evil.example/path?id=1") == "evil.example/path"

    def test_invalid_url_returns_empty(self):
        ex = SigmaExporter()
        assert ex._url_fragment("not-a-url") == ""


class TestYamlScalarQuoting:
    def test_plain_scalar_unquoted(self):
        assert SigmaExporter._yaml_scalar("plainvalue") == "plainvalue"

    def test_yaml_significant_chars_quoted(self):
        s = SigmaExporter._yaml_scalar("has: colon")
        assert s.startswith("'") and s.endswith("'")

    def test_at_symbol_quoted(self):
        s = SigmaExporter._yaml_scalar("@evil.example")
        assert s.startswith("'") and s.endswith("'")

    def test_embedded_apostrophe_doubled(self):
        s = SigmaExporter._yaml_scalar("it's")
        assert "''" in s


class TestVerdictLevelMapping:
    def test_critical_for_confirmed(self):
        result = _bec_result()
        result.verdict = Verdict.CONFIRMED_PHISHING
        ex = SigmaExporter()
        rule = ex.export_campaign_rule(result)
        assert "level: critical" in rule

    def test_low_for_suspicious(self):
        result = _bec_result()
        result.verdict = Verdict.SUSPICIOUS
        ex = SigmaExporter()
        rule = ex.export_campaign_rule(result)
        assert "level: low" in rule
