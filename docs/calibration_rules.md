# Calibration Rule Registry

This is the canonical list of cross-analyzer calibration rules used by the decision engine pass-2 step. The rules themselves live in `src/scoring/calibration.py`; this document is the registry that ADR 0001 §FM1 requires every rule to be in.

**Cap:** 10 rules total (enforced by `tests/unit/test_calibration.py::TestRegistryConstraints::test_rule_registry_size_capped`). If you're hitting the cap, retire a rule before adding a new one — that's the whole point of the cap.

**Adding a rule requires:**
1. A new function in `src/scoring/calibration.py` ending in the `REGISTRY` list
2. At least one positive test row and one negative test row in `tests/unit/test_calibration.py::TABLE`
3. A new row in this table below
4. Sample reference (the `.eml` that motivated the rule) committed to `tests/real_world_samples/` if it doesn't already exist
5. Updated entries in `src/scoring/social_platform_domains.py` (or whatever shared lookup table the rule uses) with a comment

## Active rules

| Rule ID | Added | Motivating sample | What FP/FN it addresses | Predicate (plain English) | Test rows | Quarterly review |
|---|---|---|---|---|---|---|
| `linkedin_social_platform_corroboration` | 2026-04-14 | `sample_17_legitimate_linkedin_digest.eml` | Legitimate auth-passing LinkedIn engagement notifications scoring SUSPICIOUS due to NLP intent flagging "viewed your profile" / "expand your network" as social engineering | If `header_analysis` reports SPF + DKIM + DMARC all pass AND the From: domain is on `SOCIAL_PLATFORM_DOMAINS` AND `nlp_intent` reports risk ≥ 0.7 with confidence ≥ 0.5 AND no other analyzer reports independent risk ≥ 0.5 / conf ≥ 0.5, then cap verdict at SUSPICIOUS | row1 (positive — LinkedIn digest), row2 (negative — typo squat), row3 (negative — corroboration lifts cap), row4 (negative — BEC from non-allowlisted domain), row5 (positive — subdomain match), row6 (negative — NLP risk too low) | due 2026-07-14 |

## Retired rules

*(none yet — this section will hold rules that were retired so the rationale isn't lost when they're removed from the registry)*

## How to read this table

- **Rule ID** matches the function name and is the string written to `CalibrationOutcome.rules_fired`.
- **Motivating sample** is the `.eml` that proved the rule was needed. Each entry should be reproducible — clone the repo, run the sample through the pipeline, see the rule fire.
- **What FP/FN it addresses** is the *plain* description. If you can't write this in one sentence, the rule is too vague.
- **Predicate** is the English summary of the boolean condition. The authoritative version is the function in `calibration.py`.
- **Test rows** lists the row IDs in `TABLE` that exercise this rule.
- **Quarterly review** is when the rule's continued relevance should be re-checked. Calendar reminder, not automation.

## Why a registry exists

ADR 0001 §FM1 lays out the failure mode: without a registry, calibration becomes a dumping ground. Every weird FP turns into "add a rule" and in a year there are 40 of them with no documentation, no tests, and unclear interaction. The registry forces the discipline by making rule additions visible during code review.

The auditor of cycle 5 was explicit on this point: "Without discipline, every weird FP turns into 'add a rule to pass 2', and in a year you have 40 rules with no test coverage and unclear interaction." The cap, the test requirement, and this registry are the three controls that make it not happen.
