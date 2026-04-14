# ADR 0001 — Cross-analyzer context passing via two-pass calibration

- **Status:** accepted
- **Date:** 2026-04-14
- **Cycle:** 6 (audit item #12 from the cycle 2 review)
- **Supersedes:** none
- **Superseded by:** none

## Context

The pipeline currently runs all analyzers concurrently in pass 1 and aggregates their independent risk scores in `DecisionEngine.score()`. Each analyzer sees only the email; it cannot read what other analyzers concluded. That single-pass design is fast and easy to reason about, and it's why the orchestrator at `src/orchestrator/pipeline.py` is small.

It also has a known persistent failure that has survived four cycles of cleanup: legitimate LinkedIn engagement notifications (`sample_17_legitimate_linkedin_digest.eml`) score ~36% with the NLP intent analyzer flagging risk at 99% confidence on every run. The NLP analyzer pattern-matches phrases like "viewed your profile" and "expand your network" as social engineering — which is the **correct** behavior on identical content from a phishing sender, and the **wrong** behavior on the real LinkedIn. The content is genuinely ambiguous without the authentication context that `header_analysis` already produces in pass 1 but cannot communicate back to `nlp_intent`.

`lessons-learned.md` documents this as the LinkedIn FP. Three fixes were considered and rejected in earlier cycles:

1. **Allowlist in NLP** — fragile; LinkedIn alone sends from at least four domains and they change.
2. **Raise SUSPICIOUS threshold from 30% → 40%** — would fix `sample_17` (36%) but let `sample_08` (BEC at 31%) escape as CLEAN. Trades one error for another.
3. **Retrain NLP** — the content is *genuinely* ambiguous in isolation; no amount of training fixes that.

The remaining option is the one this ADR adopts: a second pass that has access to *all* pass-1 outputs and can combine them.

## Decision

Add a **calibration pass** to the decision engine, between override rules (which force verdicts) and threshold mapping (which derives verdicts from the weighted score). Pass 2 is rule-based, runs in `O(rules)` time, and crucially **only modulates** what pass 1 produced. It does NOT re-run analyzers, does NOT call external APIs, does NOT consume LLM tokens, does NOT touch the network.

### Architectural shape

```
Pass 1 (existing, unchanged):
  orchestrator runs N analyzers concurrently
  ↓
Decision engine:
  Step 1+2: weighted score, overall confidence
  Step 3:   override rules         (force verdict)
  Step 3.5: calibration rules ◄── NEW
  Step 4:   threshold mapping with confidence capping
  Step 5:   reasoning
```

Calibration rules are evaluated in declaration order and produce a `CalibrationOutcome`:

```python
@dataclass
class CalibrationOutcome:
    rules_fired: list[str]              # rule IDs that matched
    verdict_cap: Optional[Verdict]      # if set, final verdict cannot exceed this
    score_adjustments: list[tuple[str, float]]  # (rule_id, delta) for transparency
    reasoning_lines: list[str]          # appended to PipelineResult.reasoning
```

The outcome is recorded on `PipelineResult.details` so a reviewer can see *why* a verdict was capped, and the eval harness can report calibrated vs uncalibrated scores side by side.

### The corroboration formulation (resolves the dampen-vs-corroborate question)

The reviewer of cycle 5 pushed back on "dampen by 50%" as a magic number with no calibration data behind it. **Adopted formulation:** corroboration, not multiplication.

> **Rule LinkedinSocialPlatformCorroboration:**
> If `header_analysis` reports SPF + DKIM + DMARC all `pass` AND the `From:` domain is in the maintained social-platform allowlist, AND `nlp_intent` is the only analyzer above its risk threshold, THEN cap the verdict at `SUSPICIOUS` regardless of the weighted score.
>
> The cap is lifted as soon as **any non-`nlp_intent` analyzer** reports `risk_score >= 0.5` with `confidence >= 0.5`, because that's an independent signal of risk that doesn't depend on the ambiguous content classification.

Why corroboration is better than multiplication:

| Aspect | Multiply by 0.5 | Require corroboration |
|---|---|---|
| Defensible in interview | "why 50%?" | "I require independent corroborating evidence" |
| Behavior under unrelated risk signal | dampens the *whole* score, can hide real threats | passes through unchanged |
| Implementation testability | depends on numerical fixture | boolean predicate, table-testable |
| Failure mode if rule fires wrong | false negative on phishing | false positive on legitimate (preferred trade) |
| Calibration data needed | yes (where does 0.5 come from?) | no (predicate is binary) |

The corroboration formulation also has the property that it **does not change the underlying score**. The score still says "this looks risky"; the verdict is just capped. A reviewer reading the JSON output sees both the unmodified score and the cap, and the calibration rule's `reasoning_lines` explain why.

### Pass-2 rules ship with these constraints

These constraints exist so the rule set doesn't become a dumping ground (failure mode 1 below):

1. **Pass 2 is capped at 10 rules.** Hard limit enforced by a unit test on the rule registry length.
2. **Every rule MUST ship with at least one positive test (rule fires) AND one negative test (rule doesn't fire when conditions miss).** Enforced by code review, not automation.
3. **Every rule MUST be documented in `docs/calibration_rules.md`** with: rule ID, the FP/FN it addresses, the predicate in plain English, the test row that proves it works, and the date added.
4. **No rule may invoke the network, an LLM, or a sandbox.** Pass 2 is pure data manipulation over pass-1 results. Enforceable by a code review checklist; long term, enforceable by lint.
5. **Every rule fire MUST be logged.** Calibration rule activity is the canary for analyzer regressions (failure mode 2 below).

## Failure modes (acknowledged upfront)

### FM1 — Pass 2 becomes a dumping ground

**Risk:** Without discipline, every weird FP turns into "add a rule to pass 2", and in a year the project has 40 rules with no test coverage and unclear interaction.

**Mitigation:**
- Hard cap at 10 rules, enforced by `tests/unit/test_calibration.py::test_rule_registry_size_capped`.
- New rule PRs must include the FP/FN test row that motivates the rule, plus one negative test.
- `docs/calibration_rules.md` is the registry — adding a rule without adding a row is detectable in code review.
- Annual review (calendar reminder, not automation) to retire stale rules.

### FM2 — Pass 2 rules mask analyzer regressions

**Risk:** If `nlp_intent` starts producing high-confidence risk on legitimate emails because of an upstream LLM model change, the calibration rule that suppresses the verdict will hide the failure. The pipeline keeps shipping CLEAN verdicts on a broken analyzer.

**Mitigation:**
- Every calibration rule fire is logged at INFO level with the rule ID, the email_id, and the analyzer scores that triggered it.
- The eval harness reports BOTH the calibrated final verdict AND the uncalibrated weighted score per email. A drift in the uncalibrated score on previously-stable samples is the early warning.
- A rule that fires on >5% of analyzed mail is itself a regression signal — the pipeline already has the per-rule fire counter via `CalibrationOutcome.rules_fired`; the eval harness should plot it.

### FM3 — The "known social platform" allowlist is a maintenance burden

**Risk:** LinkedIn alone sends from `linkedin.com`, `e.linkedin.com`, `linkedinmail.com`, and at least three other domains depending on notification type. Hardcoding the list is exactly the fragile pattern this ADR is trying to avoid.

**Mitigation:**
- Source the allowlist from a single file: `src/scoring/social_platform_domains.py`, a flat list with comments documenting *why* each entry is on the list.
- Each entry has a comment with the date added and the sample (`tests/real_world_samples/sample_NN_*.eml`) that motivated it.
- The list is **only used in conjunction with passing SPF/DKIM/DMARC**. A spoofed `From: linkedln-mail.com` cannot benefit from the list because (a) it's not on the list and (b) it doesn't have valid auth from `linkedin.com` either. This is what makes the list *augmentation* and not a *security boundary*. Operators can therefore extend the list without auditing for spoof bypasses.
- Quarterly cadence to update the list (calendar reminder), tracked in ROADMAP.

## Test strategy

Table-driven tests in `tests/unit/test_calibration.py`. Each row is a 4-tuple:

```python
(
    test_name,                    # human-readable
    pass1_results,                # dict of {analyzer_name: AnalyzerResult}
    expected_rules_fired,         # set of rule IDs
    expected_verdict_cap,         # Verdict or None
)
```

Asserting all four columns means a refactor that moves a signal from one analyzer to another — or removes a calibration rule entirely — fails loudly instead of producing the same final verdict for the wrong reason. Asserting only `expected_verdict_cap` would let "tests pass for the wrong reason" — the most insidious failure.

**Row 1 (the regression motivating the cycle):** the LinkedIn digest from `sample_17_legitimate_linkedin_digest.eml`. SPF+DKIM+DMARC all pass, From: messages-noreply@linkedin.com, NLP intent at 0.99 risk. Expected: `LinkedinSocialPlatformCorroboration` fires, verdict cap = SUSPICIOUS, no other analyzer above 0.5.

**Row 2 (the negative test that proves spoofs aren't covered):** synthetic — display name "LinkedIn", From: `messages-noreply@linkedln-mail.com` (typo squat), no DKIM, NLP intent at 0.99. Expected: rule does NOT fire, no verdict cap, normal scoring path.

**Row 3 (corroboration lifts the cap):** real LinkedIn auth-passing mail PLUS a malicious URL flagged by `url_reputation`. Expected: rule does not fire (corroboration condition met), verdict reaches LIKELY_PHISHING normally.

**Row 4 (BEC stays detectable):** an email matching the `sample_08_google_workspace_shared_doc.eml` shape — auth passes, NLP intent flags BEC wire fraud. Expected: BEC override rule fires (already exists in `decision_engine._is_bec_threat`), calibration rule never gets a chance because override runs first.

## Integration point in `decision_engine.py`

Calibration is inserted between the existing override-rule check and `_apply_confidence_capping`. The diff is intentionally small:

```python
# Step 3: Check override rules (existing)
override_verdict, override_reasoning = self._check_override_rules(...)
if override_verdict is not None:
    # ... existing override path ...

else:
    # Step 3.5: Apply calibration rules (NEW)
    calibration = apply_calibration_rules(results)

    # Step 4: Apply threshold mapping (existing)
    final_verdict = self._apply_confidence_capping(weighted_score, overall_confidence)

    # NEW: enforce calibration verdict cap
    if calibration.verdict_cap is not None:
        final_verdict = _min_verdict(final_verdict, calibration.verdict_cap)

    # Step 5: Reasoning (existing, plus calibration lines)
    reasoning = self._generate_reasoning(...) + "\n" + "\n".join(calibration.reasoning_lines)
```

The PipelineResult records the calibration outcome under `details["calibration"]` so eval and downstream reporting can see what fired.

## Migration path

- The current single-pass behavior is recovered by configuring zero calibration rules.
- The change is opt-in via `ScoringConfig.calibration_enabled` (default `True`). Tests can disable it to exercise pre-calibration logic.
- No analyzer code changes. No orchestrator code changes. The diff is contained to `src/scoring/`.

## Consequences

**Positive:**
- LinkedIn FP closed without a magic number.
- Every future cross-analyzer rule has a defined home.
- Eval harness gains a "calibrated vs uncalibrated" view that doubles as a regression detector for analyzers.
- The corroboration formulation is the right shape for the next several rules I can imagine needing (banking notifications, GitHub, etc.).

**Negative:**
- One more layer in the decision path. New developers have to learn about pass 2.
- The 10-rule cap is tight. If we hit it, we have to consciously decide what to retire.
- The allowlist is a maintenance burden, mitigated but not eliminated.

**Neutral:**
- Performance impact is zero in practice — pass 2 runs O(10) boolean predicates over an in-memory dict.
- Backward compatibility: the JSON output gains a `calibration` field but no existing field changes shape.

## Open questions

- **Should the allowlist be operator-configurable via YAML?** Probably yes long-term, hardcoded for now. Tracked as a follow-up in ROADMAP.
- **Should pass 2 also support score adjustments (not just caps)?** The dataclass exposes `score_adjustments` for forward compat but no rule uses it yet. Adding score adjustments later doesn't require a new ADR; removing them would.
- **Should calibration outcomes feed the eval harness directly?** Yes — covered by the eval-diff step in the implementing cycle.
