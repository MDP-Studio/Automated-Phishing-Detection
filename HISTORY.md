# Project History

This file is the 90-second skim of the project's evolution. If you are a reviewer, hiring manager, or future-me coming back after a long pause, read this first.

## Arc summary

The project began as a working phishing detection pipeline with a foundation problem: an external audit identified 21 findings including 7 P0 security items, and the project's detection metrics rested on code that didn't actually do what the docs claimed. Over **12 cycles** following a strict TEST → AUDIT → UPDATE → COMMIT → FINAL TEST → PUSH → AUDIT loop, every original P0 and P1 was closed, non-obvious design decisions were captured in ADRs written before any code, CI was added and verified to bite via a deliberately-red sanity branch, the threat model was made honest, and detection content (MITRE ATT&CK mapping, Sigma rules, STIX exports) was added to make the project legible as detection engineering rather than a Python classifier.

The arc is not a clean success story. **Cycle 10 shipped an eval harness whose first baseline showed recall 0.20 permissive / 0.00 strict — a broken detector — and cycle 10's "harness is the deliverable, numbers are data" framing buried the finding as a future-analysis artifact instead of escalating it as a P0.** Cycle 11 was a writeup-polish session in the window where a P0 investigation should have happened. Cycle 12's audit caught both and traced the dominant cause to five stacked discipline gaps going back to cycle 4 — but cycle 12's own diagnosis was *also* wrong, framing the remaining gap as "rented APIs" when it was actually a second dilution bug from cycle 1 that cycle 12 hadn't found. Cycle 13's audit caught that in turn, via a manual trace against the existing eval JSONL, and the fix moved **permissive recall from 0.20 → 0.80 and strict recall from 0.00 → 0.20** with no changes to API availability — empirically invalidating the "rented APIs" diagnosis and demonstrating that the load-bearing problem across both cycles was dilution, not absence.

The structural defense the arc now ships against its documented failure mode (narrative absorption): two discipline rules in `CONTRIBUTING.md` (Rule 1 = read outcomes before narrative, Rule 2 = if cycle N reveals a P0, cycle N+1 IS that P0), **a mechanical pre-cycle gate script (`scripts/pre_cycle_check.py`) that enforces Rule 1 by printing the most recent eval data and tripwire warnings BEFORE reminding the reader to open HISTORY**, and a willingness to rewrite earlier HISTORY entries when an audit reveals they were framing-absorbing. The gate exists specifically because the cycle 13 discovery revealed that even two layers of external review can miss the same-shaped bug, and "I know I don't follow rules that aren't mechanically enforced" is the load-bearing self-knowledge.

The cycle 12/13 audit meta-observation: **outcome discipline and causal discipline are two different muscles.** Cycle 12 exercised the first (forcing a README rewrite when the numbers were bad) and failed the second (picking a clean-sounding diagnosis the data didn't support). Cycle 13 fixed the causal diagnosis and the fix produced the numbers. The honest version of the arc is: the project is a working detector on its own corpus with measurable (if narrow) numbers, AND it shipped through six stacked discipline gaps that took three audits to surface, AND the mechanical gate now exists so the seventh gap has a better chance of being caught earlier. Both halves are true. The portfolio value is in the arc being honest about both, not in either half alone.

This file is the index. Each cycle has a one-paragraph summary, the commit hash, the audit items closed, the test delta, and any findings discovered-and-deferred.

## How to read the cycles

Every cycle followed the same workflow:

1. **TEST** — baseline pytest run before any change
2. **AUDIT** — sweep for outdated docs, test-vs-code drift, missing coverage on the changed surface area, related items the change should bring in
3. **UPDATE** — the actual code, docs, and test changes for the cycle
4. **COMMIT** — single focused commit with a detailed message that explains both what landed and what was discovered-and-deferred
5. **FINAL TEST** — full pytest after the changes
6. **PUSH** — to `origin/main`
7. **POST-PUSH AUDIT** — verify CI green, sweep for anything the cycle's writeup missed

Discovered-and-deferred findings are deliberately not silently fixed in scope creep. They go to ROADMAP and become their own future cycle. This is how cycle 6 produced the BEC ordering bug that became cycle 7's headline fix.

ADRs (`docs/adr/`) are written **before any code** for any cycle whose design has a non-obvious decision. The ADR's job is to surface the hard call to the front where it's cheap to change. Two ADRs exist as of cycle 8: ADR 0001 (cross-analyzer calibration, cycle 6) and ADR 0002 (persistent email_id lookup, cycle 8).

---

## Cycle 1 — Reframe as detection engineering

- **Commit:** [`adcd9db`](https://github.com/meidielo/Automated-Phishing-Detection/commit/adcd9db) (2026-04-14)
- **Tests:** 676 → 710 (+34)
- **Audit items closed:** none directly (this was the framing cycle)

The project shipped working code but lacked the artifacts that make a phishing detector legible as **detection engineering**. Cycle 1 added the missing layer: per-analyzer ATT&CK technique mapping with explicit gaps (`docs/MITRE_ATTACK_MAPPING.md`), a STRIDE-per-trust-boundary threat model (`THREAT_MODEL.md`), security disclosure policy (`SECURITY.md`), and a hand-emitted Sigma rule exporter (`src/reporting/sigma_exporter.py`) plus a static rule library covering visual brand impersonation, quishing, newly registered domains, BEC, HTML smuggling, and auth-fail-with-attachment. Wired `--format sigma` and `--format all` into `main.py`.

Cycle 1 also fixed a pre-existing test failure in `test_attachment_sandbox` (the test was the spec; the code had drifted) and an analyzer-key drift caught during the audit pass — `ANALYZER_ATTACK_TAGS` was using per-file `analyzer_name` strings instead of the orchestrator's canonical dict keys.

**Discovered-and-deferred:** none.

---

## Cycle 2 — Harden the web perimeter (P0 wave)

- **Commit:** [`9b5fa65`](https://github.com/meidielo/Automated-Phishing-Detection/commit/9b5fa65) (2026-04-14)
- **Tests:** 710 → 753 (+43)
- **Audit items closed:** P0 #1 (unauth dashboard), P0 #2 (SSRF in `/api/detonate-url`), P0 #3 (model poisoning via `/api/feedback`), P0 #7 (no security headers), #16 (`analyst_api_token` wired)

The audit found that every state-changing and info-disclosing `/api/*` route in `main.py` was unauthenticated, that `/api/detonate-url` had a textbook Capital-One-class SSRF, and that the security headers were missing entirely. Cycle 2 shipped `src/security/web_security.py` with three independent pieces:

1. **`TokenVerifier`** as a FastAPI dependency, bearer-token-checked against `ANALYST_API_TOKEN`. Mirrored the existing enforcement in `src/feedback/feedback_api.py` so one token protects both code paths.
2. **`SSRFGuard`** that DNS-resolves URLs and refuses any IP in 17 deny networks (RFC1918, loopback v4/v6, link-local incl. cloud metadata 169.254.169.254, CGNAT, IETF reserved, multicast). Catches the textbook `localhost → 127.0.0.1` hostname trick.
3. **`SecurityHeadersMiddleware`** attaching CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy, HSTS, Permissions-Policy.

Plus: `run_server()` defaults to 127.0.0.1 and **refuses to start** if bound to a non-loopback address without `ANALYST_API_TOKEN` set. THREAT_MODEL R1 marked MITIGATED, R3 updated with SSRF coverage. The bearer auth pattern includes a CSRF trigger checklist as a durable contract in the auth module's docstring — any future cookie/session auth PR is blocked until CSRF protection ships in the same commit.

**Discovered-and-deferred:** none.

---

## Cycle 3 — Session leak + docker docs honesty

- **Commit:** [`c1ef962`](https://github.com/meidielo/Automated-Phishing-Detection/commit/c1ef962) (2026-04-14)
- **Tests:** 753 (no delta — both fixes were observed-vs-documented corrections)
- **Audit items closed:** P1 #8 (session leak in CLI analyze), P1 #17 (docker-compose docs lied)

`PhishingPipeline.close()` existed but `analyze_email_file()` never called it, leaking aiohttp sessions on every single-shot CLI run. Wrapped the analyze call in try/finally. README and THREAT_MODEL claimed `docker-compose` ran three services (orchestrator + browser-sandbox + redis) but `docker-compose.yml` only defined `orchestrator`. Fixed both docs to describe the actual single-container layout, added the multi-container split as a tracked ROADMAP item.

**Discovered-and-deferred:** none.

---

## Cycle 4 — Detection correctness + LLM determinism

- **Commit:** [`8c1c3d2`](https://github.com/meidielo/Automated-Phishing-Detection/commit/8c1c3d2) (2026-04-14)
- **Tests:** 753 → 826 (+73: 11 url_reputation + 40 html_sanitizer + 12 multi_account_monitor + 10 anthropic_client)
- **Audit items closed:** #11 (dead-domain confidence inflation), #5 (stored XSS via `body_html`), #4 ALREADY-DONE (credential encryption was already AES-256-GCM + Argon2id; the audit was wrong but the migration path needed regression coverage), #13 (LLM determinism completion)

Four detection-correctness fixes in one cycle:

- **#11**: `url_reputation` was inflating "no threats found from a non-resolving domain" as 0.8-confidence evidence of safety, suppressing phishing scores by ~15 points across the corpus. Added `_hostname_resolves` and a confidence downgrade to 0.3 when the URL hostname doesn't resolve AND no service flagged it. **Verified the fix is in code, not just documented.**
- **#5**: `body_html` was rendered in an iframe with `sandbox="allow-same-origin"` (the worst possible flag combination). Switched to `<iframe sandbox srcdoc>` with **no allow flags** — the iframe is now its own opaque origin. Server-side bleach sanitization in `src/security/html_sanitizer.py` strips `<script>`/`<style>` content (not just tags), `on*` handlers, `javascript:`/`data:`/`vbscript:` URLs. 40 hostile-payload tests cover script tag, event handlers, SVG-namespace JS, javascript: URLs, data: URIs, meta refresh, style expression(), HTML5 parser quirks.
- **#4 verified**: `src/security/credentials.py` already implemented AES-256-GCM + Argon2id with auto-migration of legacy plaintext on every load. The audit was wrong on this — added 12 regression tests including the strongest property: no plaintext value remains grep-able from the file after migration.
- **#13**: `top_p=1` pinned alongside `temperature=0` in `AnthropicLLMClient`. Return type evolved to `LLMResponse(text, model_id)` NamedTuple. `model_id` captured from the API's actual response (not the configured request) and threaded into `AnalyzerResult.details["llm_model_version"]` so a future Haiku point release that shifts verdict distributions becomes detectable from JSON output.

**Discovered-and-deferred:** none.

---

## Cycle 5 — Supply-chain + privacy + Docker hygiene

- **Commit:** [`36b1a83`](https://github.com/meidielo/Automated-Phishing-Detection/commit/36b1a83) (2026-04-14)
- **Tests:** 826 → 843 (+17 retention)
- **Audit items closed:** #14 (unpinned dependencies), #15 (no retention/purge for `data/results.jsonl`), #18 (curl in Dockerfile healthcheck), #19 (bind-mount UID mismatch)

Four hygiene items, one of which (#14) was reframed from P2 to P1 mid-audit because pinning dependencies in a security tool is a P1 control, not hygiene.

- **#14**: Generated `requirements.lock` (2423 lines, hash-pinned) via `uv pip compile --generate-hashes`. Dockerfile installs with `pip install --require-hashes -r requirements.lock`. New `.github/workflows/ci.yml` with three jobs: full pytest on fresh Ubuntu checkout (the cycle-4-meta "test on a fresh box" gate), flake8 lint, daily `pip-audit` against the lock file. **CI green on first run** — no test was depending on a local environment quirk.
- **#15**: `src/automation/retention.py` with atomic-swap purge primitive (17 tests including the post-purge invariant that no row remains older than the cutoff). New `python main.py purge --older-than N --strict --dry-run` subcommand. New `PipelineConfig.data_retention_days` (default 30). THREAT_MODEL §6a "Privacy exposure" added as a separate risk class from security with a per-risk table covering Privacy Act / GDPR exposure, lawful basis, and right to erasure.
- **#18**: HEALTHCHECK switched from `curl -sf` to `python -c "import urllib.request..."`. Dropped curl from apt-get install.
- **#19**: New `docker-entrypoint.sh` runs as root briefly, chowns `/app/data` and `/app/logs` to UID 1000, then `gosu phishing` exec's CMD. `ENTRYPOINT_SKIP_CHOWN=1` escape hatch for Docker Desktop on Mac/Windows. Closes the silent-fail-on-Linux bind-mount issue.

**Discovered-and-deferred:** none.

---

## Cycle 6 — Cross-analyzer calibration (LinkedIn FP closed)

- **Commit:** [`695621f`](https://github.com/meidielo/Automated-Phishing-Detection/commit/695621f) (2026-04-14)
- **Tests:** 843 → 872 (+29 calibration)
- **Audit items closed:** #12 (LinkedIn FP that survived 4 cycles)
- **ADR:** [`0001-cross-analyzer-context-passing.md`](docs/adr/0001-cross-analyzer-context-passing.md)

The most important architectural change in the project. The motivating bug from `lessons-learned.md`: legitimate LinkedIn engagement notifications scored high on `nlp_intent` (correct in isolation — the language is ambiguous) and low on every other signal (correct in isolation — the email is auth-passing). Single-pass scoring averaged these into a SUSPICIOUS verdict that was the wrong answer. Three earlier fixes (NLP allowlist, threshold raise, NLP retrain) had been considered and rejected.

**ADR 0001 was written before any code.** It resolved the dampen-vs-corroborate question explicitly: corroboration, not multiplication. "Why 50%?" is undefendable; "I require an independent corroborating signal" is. The ADR documented three failure modes upfront (FM1: dumping ground → 10-rule cap enforced by test; FM2: masks analyzer regressions → calibrated/uncalibrated visibility; FM3: allowlist maintenance burden → date-stamped single file with quarterly review).

Implementation: `src/scoring/calibration.py` with `CalibrationOutcome`, `apply_calibration_rules()`, and one rule (`linkedin_social_platform_corroboration`) that fires only when ALL FIVE conditions hold: SPF+DKIM+DMARC pass, From: domain on allowlist, NLP risk ≥ 0.7 with conf ≥ 0.5, AND no other analyzer reports independent risk ≥ 0.5/0.5. The cap is SUSPICIOUS — the underlying weighted score is preserved so a reviewer can still see the NLP signal in `PipelineResult.overall_score`.

29 new tests including 6 table-driven rows (LinkedIn digest positive, typo-squat negative, corroboration-lifts-cap negative, BEC-from-non-allowlisted negative, subdomain-match positive, NLP-too-low negative), 4 end-to-end DecisionEngine integration tests, registry constraint tests (10-rule cap enforced by test), and a defensive "buggy rule must not break apply" test.

**Discovered-and-deferred:** **NEW-1** — `_check_override_rules` evaluated `_is_clean_email` BEFORE `_is_bec_threat`. A pure-text BEC email with passing auth, no URLs, no attachments matches `_is_clean_email`'s preconditions and gets force-marked CLEAN before the BEC override runs. Real BEC samples in `tests/real_world_samples/` slipped through this hole only because they happened to carry at least one URL. Load-bearing accident. **Deferred to cycle 7** rather than swallowed into cycle 6 scope.

---

## Cycle 7 — NEW-1 + cap ceiling lock + CI bites verify

- **Commit:** [`e6a0a3f`](https://github.com/meidielo/Automated-Phishing-Detection/commit/e6a0a3f) (2026-04-15)
- **Tests:** 872 → 879 (+4 NEW-1 regression + 3 cap ceiling)
- **Audit items closed:** NEW-1 (BEC ordering bug from cycle 6 discovery), cap-ceiling lock, CI-bites verification

Three small focused items. The cycle 6 review correctly elevated NEW-1 to P0-adjacent because it invalidated the BEC detection claim — any future pure-text BEC would be silently marked CLEAN.

- **NEW-1 fix**: `_check_override_rules` reordered so `_is_bec_threat` runs **before** `_is_clean_email`. The simpler of two options (the alternative was excluding `bec_wire_fraud` intent from `_is_clean_email`). Smoking-gun regression test in `tests/unit/test_decision_engine_override_ordering.py::test_pure_text_bec_becomes_likely_phishing` — explicitly uses `url_count=0` and `attachment_count=0`. The 24 existing decision_engine tests passed unchanged, proving no test was depending on the buggy ordering.
- **Cap ceiling lock**: 3 tests under `TestCalibrationCapCeiling` lock the SUSPICIOUS-not-CLEAN semantic. The defensible scenario: a real LinkedIn notification with an embedded malicious redirect (LinkedIn tracking URLs have been abused as open redirects in the wild) where `url_reputation` is below the corroboration threshold — calibration still fires but the verdict caps at SUSPICIOUS so the analyst still reviews. ADR 0001 gained a "Why the cap is SUSPICIOUS and not CLEAN" section that cites the locking tests by name.
- **CI bites verification**: pushed a throwaway branch `ci-sanity-check-delete-me` with `assert False` in a new test, opened draft PR #1 (workflow only triggers on `pull_request` to main), watched CI fail loudly. Run id `24403600695` shows the test job FAILED while lint and pip-audit independently SUCCEEDED — proving each gate is independent and bites on its own. PR closed without merge, branch deleted. The "two cycles green = converging or blind spot" concern is now resolved with positive signal.

**Discovered-and-deferred:** none.

---

## Cycle 13 — Sixth stacked gap: attachment_analysis (invalidates cycle 12's "rented APIs" diagnosis)

- **Commits:**
  - [`eef4b5e`](https://github.com/meidielo/Automated-Phishing-Detection/commit/eef4b5e) — gate first (pre-cycle check script, Rule 1 enforcement)
  - (this commit) — the fix, new baseline, HISTORY updates
- **Tests:** 947 (unchanged in number; cycle 1's `test_analyze_no_attachments` assertion unwound)
- **Eval delta (cycle 12 → cycle 13):** permissive recall **0.20 → 0.80** (+0.60), strict recall **0.00 → 0.20** (+0.20). 8 verdict flips across 22 samples, all in the correct direction. Zero false positives.

**What was wrong with the cycle 12 diagnosis.** Cycle 12 closed the sender_profiling cold-start bug and measured the new baseline at the same 0.20 permissive recall as cycle 10. I framed the unmoved recall as "the detection gap is about external API dependencies the eval environment doesn't have" — the "rented vs intrinsic" framing. The cycle 12 reviewer pushed back: that framing was plausible but not measured, and three alternative causes hadn't been ruled out. The reviewer's cheap diagnostic: trace one phishing sample manually through the per-analyzer data before scoping cycle 13.

**I ran the trace against the existing eval JSONL before writing the response** (the caveat at the end of the reviewer's note pointed directly at it). The data contained the answer. `attachment_analysis` was returning `risk_score=0.0, confidence=1.0` on **every one of the 22 samples** — because none of the .eml samples had attachments, and the cycle 1 "fix" for `test_analyze_no_attachments` was wrong in the wrong direction. I had changed the code to match a test that encoded the wrong behavior ("no attachments means vote clean with full confidence"), introducing the exact dead-domain-confidence bug class that cycle 4 would be named for three cycles later — and the cycle 4 lesson was scoped to `url_reputation` only, so it never migrated to `attachment_analysis` in the nine subsequent cycles.

**The math the reviewer made me do.** Every sample's weighted-score denominator included `0.15 * 1.0 = 0.15` for attachment_analysis (the weight times the full confidence), while the numerator got `0.15 * 0.0 * 1.0 = 0` (because risk was 0). A contribution of 0-to-numerator, 0.15-to-denominator is the mathematical definition of "drag the average toward zero". On sample_06 (BoA wire confirm, cycle 12's biggest mover at 0.499), the observed weighted score was 0.499; with attachment_analysis correctly skipped the predicted score was roughly 0.183 / 0.275 ≈ 0.665 — crossing the 0.60 LIKELY_PHISHING threshold by 0.065. The prediction was right: sample_06 measured at **0.665** in the cycle 13 re-run.

**Five stacked gaps from cycle 12, plus one more from cycle 1 = six.** The cycle 12 commit named four gaps verbatim (cycle 4's lesson applied incompletely + doc/config drift + no end-to-end eval until cycle 10 + cycle 10 framing absorbing the result). The cycle 12 audit added a fifth (`_is_clean_email` L437 dead-block). Cycle 13 adds the sixth and it's the oldest: **I introduced the dead-domain-confidence bug class in cycle 1 by "fixing" a test that was encoding the wrong direction of the spec.** The lesson had to exist (cycle 4 would name it three cycles later) because the bug I had just introduced was actively diluting every weighted score — but the cycle 4 fix never generalized to every analyzer that could return signal-without-data. `sender_profiling` had the same bug (cycle 12). `attachment_analysis` had it too (cycle 13). Two analyzers with the same bug class, both hidden behind the framing of cycles that thought they'd already fixed it.

**The structural defense that cycle 13 shipped before the fix.** Per the cycle 12 reviewer's explicit ordering ("build the gate, then do the work the gate is supposed to govern, then have the gate be the thing that makes you look at the result honestly"), cycle 13 committed `scripts/pre_cycle_check.py` as its own commit (`eef4b5e`) BEFORE the attachment_analysis fix. The script prints the most recent eval summary's permissive/strict recall, the open residual risks from THREAT_MODEL §6, and the planned items from ROADMAP — BEFORE reminding the reader to open HISTORY or commit messages. It exits non-zero if the eval is older than 14 days, and it prints a tripwire warning if permissive recall is below the pre-committed 0.50 "meaningfully working" floor (conscious-acknowledgment checkpoint, not unreviewable block). Rule 1 in CONTRIBUTING.md was updated to require running it at the start of every cycle. The rationale ships inline: "I know from cycle 10 that I don't follow rules that aren't mechanically enforced" is the sharpest self-knowledge in the whole arc, and the gate is the structural fix.

**Per-sample verdict flips (the thing the per-sample JSONL was designed to answer):**
- Cycle 12 CLEAN → cycle 13 SUSPICIOUS: samples 01, 03, 07, 08, 09, 10 (6 samples) — these are the 6 phishing samples the attachment_analysis dilution was suppressing below the 0.30 SUSPICIOUS threshold.
- Cycle 12 SUSPICIOUS → cycle 13 LIKELY_PHISHING: samples 05, 06 (2 samples) — the ones already closest to the 0.60 threshold in cycle 12.
- Cycle 12 CLEAN → cycle 13 CLEAN (remaining FNs): samples 02 (PayPal) at 0.276, 04 (Apple) at 0.237. Both below the 0.30 SUSPICIOUS threshold after the fix. These have weak header_analysis signals and the cycle 13 fix didn't boost them enough to cross. Cycle 14+ work.
- Zero false positives across all 12 legitimate samples (precision stayed at 1.000 in both projections).

**Applying the cycle 12 pre-committed thresholds.** Permissive recall 0.80 ≥ 0.70 → README TL;DR returns to the "working detector" framing (with corpus caveats intact). The reframe cycle 12 forced was correct at the time — recall was 0.20 and the project was not a working detector in that environment — and cycle 13 earns the un-reframe by producing the measured improvement. The TL;DR now states the numbers directly, flags the corpus as small and project-curated, and explicitly notes that strict recall (0.20) remains below the defensible floor. No softening on the corpus caveat, no overclaiming on the measured number.

**What the cycle 12 reviewer was specifically right about.** "Outcome honesty and causal honesty are two different muscles, and you exercised one of them this cycle and not yet the other." The cycle 12 README rewrite was outcome honesty. The "rented APIs" diagnosis was the causal-honesty failure — a clean-sounding story that didn't actually measure. Cycle 13's data invalidated it: url_reputation is still returning confidence=0 on 22/22 samples, nlp_intent is still in sklearn fallback, no LLM keys are configured, and recall still moved from 0.20 to 0.80. **The rented APIs are irrelevant to the cycle 12 → cycle 13 delta.** The load-bearing bug was the cycle 1 dilution, which had nothing to do with external dependencies.

**Discovered-and-deferred:**
- The remaining 2 phishing FNs (samples 02 PayPal, 04 Apple) need another pass. Their header_analysis signal is weaker than the other 8 phishing samples — worth investigating whether that's the eml content, a header_analyzer gap, or just the cost of the permissive threshold being at 0.30. Cycle 14+.
- Strict recall 0.20 is still below the 0.50 "meaningfully working" floor for the strict projection. This would benefit from the LLM being online (nlp_intent in LLM mode produces strong signals that would push sample_05/06-class emails well past 0.60) or from calibration rules that recognize auth-failing phishing and apply a positive cap.
- Cycle 10's nlp_intent fallback path is still invisible to reviewers (the `degraded_analyzers` field proposal from cycle 12). Still a cycle 14+ structural addition.

---

## Cycle 12 — Audit-forced sender_profiling fix + honest rebaseline

- **Commit:** (this commit)
- **Tests:** 944 → 947 (+3: sender_profiling cold-start regression tests)
- **Audit items closed:** audit #10 P0-1 (sender_profiling cold-start dilution), P0-2 (docker-compose curl healthcheck), P1-2 (sender_profiling doc/config drift), P2 test count drift in CONTRIBUTING
- **Pre-committed thresholds (written before the re-run):** permissive recall ≥ 0.70 → README unchanged; 0.50 ≤ recall < 0.70 → TL;DR softens; recall < 0.50 → TL;DR rewrites to drop the "detection pipeline" framing

An external audit of the project surfaced what the cycle 10 process had buried: the eval harness's first baseline run showed permissive recall 0.20 and strict recall 0.00 on the 22-sample real-world corpus, and cycle 10's "harness is the deliverable, numbers are data" framing had absorbed the result as a future-analysis artifact instead of escalating it as a P0 detection-correctness finding. The framing was rhetorical cover. The audit pushed on it and was correct.

Root cause the audit traced, which belongs in cycle 12's history verbatim: **four discipline gaps stacked.** Cycle 4's dead-domain-confidence lesson was applied to `url_reputation` only, not generalized across analyzers that could return signal-without-data. This was compounded by doc/config drift — `docs/MITRE_ATTACK_MAPPING.md` had always described `sender_profiling` as "not in the active scoring weights" while `config.yaml` had it at 0.10. Compounded by no end-to-end eval harness until cycle 10. Compounded by cycle 10 framing the bad baseline as data rather than escalating it. Each gap by itself was survivable; four stacked meant the project was shipping a pipeline where a cold-start analyzer was hardcoding `risk_score=0.45, confidence=0.5` on every never-seen sender, actively diluting real signals from `header_analysis` and `brand_impersonation` down from their natural magnitudes.

The audit also surfaced a fifth consequence I'd missed: `decision_engine._is_clean_email` at L437 blocks the CLEAN override when `sender_profiling.risk_score > 0.2`. With the cold-start hardcoded risk at 0.45, **the CLEAN override path was dead-blocked for every email on every fresh deployment**. Cycle 7's NEW-1 fix (BEC ordering before `_is_clean_email`) was correct on paper but was protecting a scenario that wasn't reachable at runtime — the scenario my cycle 7 regression test exercised used a synthetic `sender_profiling` with `risk_score=0.0`, a value the real analyzer never produced. Five stacked gaps, not four. Cycle 12 closes all five.

**The fix.** `src/analyzers/sender_profiling.py`: on cold start (email_count < 3) the analyzer returns `AnalyzerResult(risk_score=0.0, confidence=0.0)` with a `"cold_start"` marker in details. `confidence=0.0` makes `decision_engine.py:227` skip it from the weighted sum entirely; `risk_score=0.0` keeps `_is_clean_email` from blocking on a spurious absence-of-data reading. Three regression tests in `tests/unit/test_sender_profiling_cold_start.py` — `test_sender_profiling_cold_start_skips_from_scoring`, `test_three_prior_observations_unlocks_real_scoring`, `test_cold_start_does_not_block_clean_override` — lock the behavior with cycle-8-style names that encode the bug. `config.yaml` sets `sender_profiling: 0.00` to match the MITRE doc's long-standing claim that the analyzer is advisory-only. Total weights now sum to 0.90 (validator warns but accepts); the decision engine normalizes by actual weighted confidence so this is behavior-preserving for the other analyzers. Re-weighting is a tuning cycle, not a correctness cycle, and is deferred.

**Re-run results, committed unmodified.** New baseline `eval_runs/2026-04-15_0344_d077279.jsonl` alongside the old `eval_runs/2026-04-14_1600_9a7b245.jsonl`. Per-sample diff across 22 samples:

- **10/10 phishing samples moved in the right direction** (scores up by +0.003 to +0.094)
- **10/12 legitimate samples moved in the right direction** (scores down toward truly-clean)
- **Zero verdict flips.** Biggest phishing move was sample_06 (Bank of America) at 0.405 → 0.499, still below the 0.60 LIKELY_PHISHING threshold by 0.10.
- **Permissive recall 0.20, strict recall 0.00 — unchanged from cycle 10.**

The directional result validates the fix: the sender_profiling signal was indeed dragging scores in both directions, and removing it shifted all 20 of the directionally-responsive samples correctly. I framed the magnitude as "structurally insufficient" and diagnosed the remaining gap as "about external API dependencies the eval environment doesn't have — the project's detection capability is structurally dependent on API configuration."

**That diagnosis was wrong and cycle 13 invalidated it empirically.** The cycle 12 reviewer pushed back on the "rented APIs" framing as plausible-but-unmeasured. I did the cheap trace the reviewer suggested (against the existing eval JSONL, no new code) and it surfaced a sixth stacked gap: `attachment_analysis` was returning `confidence=1.0` on every one of the 22 samples because of a cycle 1 bug I'd introduced by making a pre-existing wrong test pass. Fixing THAT moved permissive recall from 0.20 → 0.80 with zero changes to API availability. The load-bearing bug for the unmoved recall was dilution, not absence — and the cycle 12 "rented APIs" framing was itself a framing-absorption event one level deeper than the cycle 10 one it was trying to fix. See cycle 13 for the invalidation, the sixth-gap framing, and the mechanical Rule 1 gate that shipped before the fix to prevent the next iteration of this pattern.

**Applying the locked threshold.** Permissive recall 0.20 is below the pre-committed 0.50 "meaningfully working" floor. Per the pre-commit, the README TL;DR rewrites to drop the "phishing detection pipeline" framing in favor of "detection engineering scaffold whose detection layer is currently underperforming on the test corpus". That rewrite is in this commit. The portfolio claim shifts: the value is in the arc, the discipline, the ADRs, the honest eval data — not in detection metrics the pipeline doesn't currently deliver in this environment. A future cycle with API keys configured will either move the baseline materially or confirm the gap is structural, and either finding is useful.

**Other cycle 12 fixes rolled in** (tight scope, all caught by the same audit):

- `docker-compose.yml` healthcheck switched from `curl` to `python -c "import urllib.request..."` matching the Dockerfile. Cycle 5 audit #18 claimed to have closed this but only touched the Dockerfile; the compose file kept the curl dependency and would have failed on every deployment. Credibility fix.
- `CONTRIBUTING.md` no longer hardcodes "676 → 899" — now references `HISTORY.md` as the single source of truth for test counters. The doc drift that the audit caught doesn't recur.
- `CONTRIBUTING.md` gains a new top-level discipline rule: **"Read outcomes before narrative."** When reviewing any audit, plan, or cycle, open `eval_runs/` and `THREAT_MODEL.md` §6 (residual risks) BEFORE reading `HISTORY.md` or commit messages. Narrative absorption is the documented failure mode of this project — cycle 10 demonstrated it in full. The rule is the structural defense.
- `docs/MITRE_ATTACK_MAPPING.md` updated to cite `config.yaml: sender_profiling: 0.00` explicitly and describe the cold-start behavior, so the drift that the audit caught can't recur quietly.

**Structural commit for future cycles:** **"If cycle N reveals a P0-class finding, cycle N+1's scope IS that finding. The previous plan for cycle N+1 becomes cycle N+2."** Cycle 10 should have become this cycle. Cycle 11 should not have been a writeup polish pass — it should have been the sender_profiling investigation. The writeup polish still landed as commit `d077279` and is preserved in git, but it was the wrong work in the wrong window. That's named honestly below.

**Discovered-and-deferred:**
- `nlp_intent` fallback mode produces no indicator in the JSON output (`model_id: ""` is the only signal and it's not surfaced anywhere). Adding a `degraded_analyzers` field to `PipelineResult` is the structural fix and is cycle 13+.
- The project's detection capability is structurally dependent on external API availability. The eval delta between "no keys" and "all keys configured" is the metric that tells you how much of the detection is rented vs intrinsic. Measuring that delta is cycle 13+ work.
- P0-3 R1 framing (HTML routes unauth) — the audit pushed back on "MITIGATED" as overstated. Accepted; will change the threat model to "partially mitigated" in its own cycle, not bundled into cycle 12.
- The bleach → nh3 migration (audit P1-6) is a real supply-chain concern but is a separate cycle with its own testing surface.

---

## Cycle 10 — eval harness + #10 refactor (REWRITTEN cycle 12, honest version)

- **Commit:** [`d54ba89`](https://github.com/meidielo/Automated-Phishing-Detection/commit/d54ba89) (2026-04-14)
- **Tests:** 899 → 944 (+45: 18 diagnostics + 27 eval harness)
- **Audit items closed:** P1 #10 (three duplicate diagnostic implementations)
- **Audit items revealed but not escalated (cycle 12 fix):** the first harness run produced a permissive recall of 0.20 and strict recall of 0.00 on the real-world sample corpus — evidence that the pipeline was broken end-to-end in the eval environment. Cycle 10's framing ("the harness is the deliverable, the numbers are data") absorbed the result as a future-analysis artifact rather than escalating it. Cycle 12's audit traced the dominant cause to `sender_profiling`'s cold-start dilution, which had been unfixed since cycle 4. The cycle 10 framing was wrong; the honest cycle-10 result was "harness shipped, and it immediately surfaced a five-discipline-gap root cause that the cycles preceding it had missed."

**What cycle 10 actually shipped, described correctly:**

Phase 1 was the #10 refactor — the three duplicate diagnostic implementations (`diagnose_apis.py`, `test_apis.py`, `/api/diagnose`) consolidated into `src/diagnostics/api_checks.py` with a `CheckResult` dataclass and registry-driven `run_all_checks()`. 18 unit tests. Phase 1 ran under a 90-minute hard stop with a pre-committed revert option and finished in ~32 minutes. That part of cycle 10 was clean.

Phase 2 was the eval harness: `src/eval/harness.py` with per-sample JSONL storage in `eval_runs/YYYY-MM-DD_HHMM_<sha>.jsonl`, two binary projections (permissive and strict), `scripts/run_eval.py` CLI. 27 unit tests covering the row schema, projection logic, aggregate arithmetic, and error-row exclusion from the confusion matrix. The per-sample row shape is genuinely the right design — it lets cycle 12's diff "which 12 samples flipped" work end-to-end, and the cycle 12 re-run validated the sender_profiling fix directionally via that diff. The harness design is not what cycle 10 got wrong.

**What cycle 10 got wrong, described correctly:**

The first run of the harness produced a disaster baseline and cycle 10's framing buried it. Every row had `model_id: ""` meaning the LLM never ran. `sender_profiling` returned literally identical `risk_score=0.45, confidence=0.5` on every one of 22 different senders — a hardcoded dilution signal, not behavioral profiling. `brand_impersonation` was firing strongly (0.75–0.85 risk at 0.8–1.0 confidence) on phishing samples and the weighted score was dragged down to 0.19–0.42 anyway. The math was in the JSONL. I reported the numbers in my cycle 10 close as "perfect precision, terrible recall" and then followed a pre-commit that prevented me from acting on the finding in cycle 10 — correctly, per the pre-commit — but I also should have rewritten cycle 11's scope to be the investigation. Instead I took the previous reviewer's "cycle 12 = eval analysis, internal doc, don't act on findings" framing as binding and ran cycle 11 as writeup polish in the window where a P0 investigation should have happened. The pre-commit was doing its job (preventing scope creep); my escalation path was not (missing a P0-class finding in the output).

The cycle 12 audit caught this. The pre-commit discipline this project needs now has a new rule: **"if cycle N reveals a P0-class finding, cycle N+1's scope IS that finding; the previous plan for N+1 becomes N+2."** That rule would have made cycle 11 be this cycle.

The original HISTORY entry for cycle 10 described Phase 1 and Phase 2 as clean deliverables and framed the numbers as "data for future analysis". That framing was wrong. The above is the honest version. The original wording is preserved in git history if anyone needs it; it is not duplicated here.

---

## (not a cycle) Writeup polish — commit `d077279`

Previously labeled "cycle 11". Demoted in cycle 12 per the audit push-back on the writeup polish happening in the window where a P0 sender_profiling investigation should have taken its place. The commit itself stands — both writeups in `docs/writeups/` were polished to shippable state against 11 pre-commits, the discipline was real, and the 11-minute execution was the result of the pre-commits binding the cycle. But it targeted the wrong work. The pre-commit discipline is load-bearing only when applied to the right target; applied to the wrong target it produces the feeling of rigor without the outcome benefit. That lesson is the important output of this window, not the polished writeups. See cycle 12 for the structural rule ("if cycle N reveals a P0, cycle N+1 IS that P0") that exists specifically to catch this failure mode.

The polished writeups remain available at `docs/writeups/nlp-nondeterminism.md` and `docs/writeups/calibration-rule-patterns.md`. The publish-the-NLP-post window from the previous reviewer's directive is still open but is subordinated to the detection-correctness work.

The first cycle I ran fully unsupervised: plan file written in plan mode, Explore agent surveyed both drafts, Plan agent designed the polish approach, plan approved, executed under explicit pre-commits. No plan check-in before or during execution.

**Pre-commits written before touching either file** (same discipline shape as cycle 10, domain shifted from code to writing):
1. Full pytest baseline before any edit. Writing cycles can damage test fixtures via stray IDE saves.
2. Force structural deletions first (status-line header, "What I'd write if this were a longer post" section, trailing scaffolding), without reading the delete-sections — they contained tempting content that would have pulled upward into the body.
3. Record post-deletion word counts to establish real budget before any content work.
4. NLP post first, then calibration. Not "easier win" — linearly-ordered line-level fixes first to confirm the polish pattern works, then structural surgery on the calibration post.
5. Time budgets: NLP 45 min, calibration 60 min. Blown budget → stop and ship current state.
6. One counted escape-clause pass per draft. Declared with the specific red criterion. Pass 4 is never allowed.
7. Every rough-passage rewrite starts with a one-sentence "this needs to change because X" reason written BEFORE the edit. Writing the reason after is rationalization, not discipline. If the reason can't be stated cleanly, skip the passage.
8. Read-aloud audit before committing each draft (30-second-to-first-concrete-claim, zero stumbles on rough passages, final word count).
9. No external publication attempts in this cycle — that's a separate decision.
10. Full pytest after both files saved, before the commit.
11. Post-edit encoding + line-ending check (pytest doesn't catch CRLF / BOM / trailing-whitespace damage).

**NLP post** (`docs/writeups/nlp-nondeterminism.md`): 1,262 → 1,148 words. Skipped one of the three rough-passage edits (L33 transition) per pre-commit #7 — couldn't state a content-quality reason for the edit before touching it, which is the pre-commit's exact signal to leave the passage alone. Made the L50-57 `top_p` rewrite net-negative on word count, cut L87-88 entirely (redundant with L90-91 meta-lesson). Used the counted escape clause for an additional tightening pass with red criterion "word count over 1,000-word target" — four additional redundancy trims made the post ~45 words shorter. Ships at 1,148, overshooting the 800-1,000 target by 148 words. The Plan agent's deletion-to-~895 estimate was wrong because the body was denser than predicted; I chose to honor the original target rather than raise it after the fact, ran the escape pass, and shipped at what the content actually supports.

**Calibration post** (`docs/writeups/calibration-rule-patterns.md`): 1,538 → 1,526 words. Three structural edits in a single dependency-chained pass per the Plan agent's warning about internal consistency: (1) promoted the "three things are simultaneously true" lever from the third paragraph to the second, slightly generalizing the list items so they stand without the LinkedIn example preceding them; (2) changed "There's a second, subtler problem" to "The more serious problem is" so the hides-real-risk argument — which is the strongest single objection to Pattern A — stops being demoted beneath the weaker magic-number argument; (3) added a single-sentence link in bullet 2 of "when dampening is actually correct" explaining why scoping the dampening to one analyzer makes the hides-real-risk objection not apply, closing the reasoning chain that was backwards-engineered from the conclusion. Read the polished post end-to-end and wrote a one-sentence summary from memory as the structural coherence check; the sentence led with "require an independent corroborating signal" rather than "avoid multiplicative dampening", confirming the reorder worked.

**Both drafts lost their "What I'd write if this were a longer post" sections**, the NLP draft lost its trailing "drafting notes for myself" paragraph, and both lost their "Status: not yet polished" header scaffolding. Both are shippable state now — a deliberate publish decision will be made in a future cycle.

**Unsupervised cycle notes:** ran plan-mode properly (Explore + Plan agents + plan file + ExitPlanMode), honored every pre-commit, used the escape clause exactly once on the NLP post with the red criterion declared before the pass started, skipped an edit when the pre-commit rule said to skip rather than force a rewrite I couldn't justify. Total execution time on both drafts: approximately 11 minutes of real polish work (well under the combined 105-minute budget). The "suspiciously fast" feeling midway through was itself a reflex worth naming — the structural deletions removed ~200 words of scaffolding that didn't need editorial judgment, and the drafts were already cleaner on voice, hedge density, and lineage than I expected. Speed was a consequence of discipline, not carelessness.

**Discovered-and-deferred:** none.

---

## Cycle 8 — Persistent email_id lookup (audit #9)

- **Commit:** [`eed7e98`](https://github.com/meidielo/Automated-Phishing-Detection/commit/eed7e98) (2026-04-15)
- **Tests:** 879 → 899 (+20 email_lookup)
- **Audit items closed:** #9 (`_upload_results` 200-cap + restart bug)
- **ADR:** [`0002-persistent-email-id-lookup-for-feedback.md`](docs/adr/0002-persistent-email-id-lookup-for-feedback.md)

The feedback endpoint resolved `email_id → sender` by walking `_upload_results` in reverse — an in-memory list capped at 200 and wiped on restart. Three lookup sites all silently no-op'd after restart or after the 200-cap roll. The endpoint returned HTTP 200 with `actions_taken: []` and the analyst had no way to tell the action was lost.

**ADR 0002 was written before any code.** It split the problem along the cycle-7-reviewer-suggested display-vs-lookup axis: display stays in-memory at 200 (right shape for "render the last 50 uploads"), lookup moves to a persistent index over the existing `data/results.jsonl` (right shape for "find any email since project start"). Three storage options compared with the sidecar JSONL pattern explicitly REJECTED in writing because it creates a drift surface, not because it duplicates data. Five failure modes documented (FM1 staleness window → stat-and-reload retry, FM2 partial-write → walker skips garbage, FM3 retention purge → index `invalidate()` after swap, FM4 concurrent writers → same stat-and-reload mechanism, FM5 memory growth → bounded by retention purge).

Implementation: `src/feedback/email_lookup.py` with thread-safe `EmailLookupIndex` storing `email_id → byte_offset` (~80 bytes per entry, memory bounded by entry count not record size). 20 tests including the smoking gun `test_blocklist_mutation_succeeds_on_pre_restart_email` and the 250-upload property test that proves all records are findable after restart. `purge_results_jsonl` gained an optional `index=` parameter that calls `invalidate()` after the atomic swap. `ci.yml` gained the cycle-7-reviewer-suggested comment explaining why no `push:` trigger for non-main branches, citing the cycle 7 sanity check run id for durability.

**No migration script needed.** Existing `data/results.jsonl` files from prior runs are valid input — the rebuild walker reads them at startup the same way it'd read a freshly-created file.

**Discovered-and-deferred:** none.

---

## What's open

| ID | Severity | Item | Plan |
|---|---|---|---|
| #20 | P2 | `templates/report.html` is a 600-line standalone Jinja report; check whether the dashboard modal in `monitor.html` has replaced it and delete if so. | Cycle 11+ |
| #21 | P2 | Legacy CLI flags `--analyze` and `--serve` with `argparse.SUPPRESS`. Pick a deprecation date; remove. | Cycle 11+ |
| #22 | P2 | Inline JS/CSS in `monitor.html` and `dashboard.html`. CSP would benefit from moving JS to `static/js/*.js` so `script-src 'self'` is enforceable. | Cycle 11+ |
| #23 | P2 | `.gitignore` patterns for `*_SUMMARY.md`, `*_GUIDE.md`, etc. suggest throwaway-doc accumulation. Periodic local cleanup. | Cycle 11+ |

Plus the next cycle's planned work (cycle 10):

- **Real eval harness** against Nazario, PhishTank, and Enron-ham corpora producing actual precision/recall/F1 numbers per verdict and per analyzer. The lightweight `scripts/compare_runs.py` from cycle 6 is an offline diff tool, not the harness `docs/EVALUATION.md` describes. Cycle 10's full-day swing.

## What's in the writeup queue

These are draft writeups in `docs/writeups/` whose context is freshest now:

- **`nlp-nondeterminism.md`** — why `temperature=1` silently destroyed test metrics for three cycles before being caught (cycle 4's #13 fix). Useful blog-post-shaped artifact.
- **`calibration-rule-patterns.md`** — the dampen-vs-corroborate decision from ADR 0001 as a pattern comparison. Useful for senior-engineer audiences thinking about the same design space.

## Counters

| Metric | Pre-cycle 1 | Cycle 13 |
|---|---|---|
| Tests | 676 (1 failing) | **947 (0 failing)** |
| Test modules | 22 | **35** |
| ADRs | 0 | **2** |
| Audit P0s open (original audit) | 7 | **0** |
| Audit P1s open (original audit) | 11 | **0** |
| Audit P2s open (original audit) | 4 | **4** |
| CI configured | no | **yes, verified to bite** |
| Threat model | implicit | **STRIDE per trust boundary, 9 residual risks documented, R1 = partially mitigated** |
| Detection content exports | none | **STIX 2.1 + Sigma rules + ATT&CK mapping** |
| Dependency lock file | none | **hash-pinned, daily `pip-audit`** |
| Privacy posture | implicit | **GDPR-aware retention purge with `--dry-run`** |
| Eval harness | none | **`src/eval/harness.py` with per-sample JSONL storage in `eval_runs/`** |
| **Mechanical discipline gates** | **none** | **`scripts/pre_cycle_check.py` enforces Rule 1 (read outcomes before narrative) at every cycle start** |
| **Measured detection recall (permissive, 22-sample project-curated corpus)** | **unknown** | **0.80 — above the "defensible" floor of 0.70; corpus is small, directional baseline only** |
| **Measured detection recall (strict, same corpus)** | **unknown** | **0.20 — below the "meaningfully working" floor of 0.50; strict-threshold work remains** |
| **Discipline failures traced and closed by external audits** | **unknown** | **six stacked gaps: cycle 4's incomplete lesson applied to url_reputation only, doc/config drift, no end-to-end eval until cycle 10, cycle 10 framing absorption, `_is_clean_email` dead-block, cycle 1's `attachment_analysis` wrong fix — all closed** |

## How to use this file

- **Reviewer / hiring manager / interviewer:** read the arc summary at the top, the `What's open` table at the bottom, and any one cycle that interests you. The cycle commits are linked.
- **Future-me coming back after a pause:** the audit-items-closed column tells you what each cycle was actually for. The discovered-and-deferred entries explain why the next cycle exists.
- **Anyone proposing a new cycle:** add a section here when the cycle ships. The pattern is one paragraph + one fixed table of (commit, tests, audit items, ADR if any, discovered-and-deferred). Don't break the template; the template is the artifact.
