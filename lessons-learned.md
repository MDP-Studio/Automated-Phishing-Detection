# Lessons Learned

Honest accounting of what broke, what was missed, and what the detection results actually mean.

## Test Results (22-sample mixed dataset)

**Stable results (reproducible):** Precision: 91% | Recall: 90-100% | 1 persistent false positive (LinkedIn)

**Unstable result:** Sample_08 (Google Workspace BEC) oscillates between CLEAN (26%) and SUSPICIOUS (31%) across runs. The NLP analyzer scored it 5% on one run and 30% on the next, with no code changes. This was caused by the Anthropic API defaulting to temperature=1.0 — now fixed to temperature=0. Until re-validated with the deterministic setting, treat recall as 90% (the stable floor), not 100%.

The test set includes 12 legitimate brand emails from the exact senders we're trying to detect phishing impersonation of (Amazon, PayPal, Google, Netflix, LinkedIn, Bank of America, DHL, Stripe, DocuSign, Substack). A naive keyword detector would fail badly on this set.

**Important caveat:** All 22 test samples are synthetic .eml files constructed for testing, not real captured phishing emails from the wild. Real phishing emails include obfuscated HTML, base64-encoded redirects, tracking pixels, internationalized domain abuse (IDN homographs), and other evasion techniques that these clean lab samples don't exercise. The 90% recall number applies to straightforward phishing templates. Against adversarial evasion techniques, expect lower performance.

## The Unstable Result: BEC via Google Workspace (sample_08)

**What happened across runs:**
- Run 1: NLP scored 5% at 85% confidence → overall 26% → verdict CLEAN (false negative)
- Run 2: NLP scored 30% at 35% confidence → overall 31% → verdict SUSPICIOUS (true positive)
- No code changes between runs. Same sample, same pipeline, different LLM output.

**Root cause:** The Anthropic API was called with default temperature=1.0 (now fixed to 0). The LLM's judgment on this email is genuinely ambiguous — it's a BEC (Business Email Compromise) using curiosity and authority rather than urgency and credential harvesting. The LLM wobbles on it because it's a borderline case, not because the LLM is broken.

**Why BEC is structurally hard:** BEC is responsible for the largest dollar losses in email-based attacks (FBI IC3 reports consistently put BEC losses in the billions). This sample uses a confidential salary document shared by a colleague — no urgency language, no "click here to verify," no credential forms. The entire analysis framework is oriented toward credential harvesting and brand impersonation. Detecting BEC requires organizational context (is this person really sharing salary data?) that a stateless email scanner cannot provide.

**Even with temperature=0, this is fragile.** The sample scores 31% against a 30% threshold. One point of drift from any analyzer and it flips. Don't count this as a reliable detection.

## Known Issue: LinkedIn False Positive (sample_17) — UNRESOLVED

**Status:** Persistent across all test runs. Not fixed.

**What happens:** Legitimate LinkedIn "12 people viewed your profile this week" email scores 36% → verdict SUSPICIOUS. NLP intent scores 99% risk at 85% confidence on every run.

**Root cause:** The NLP analyzer pattern-matches social engagement language ("viewed your profile," "connect with," "expand your network") as phishing intent. This is correct behavior in isolation — phishing emails use identical language. The problem is that the NLP has no access to authentication context (SPF/DKIM/DMARC pass from linkedin.com).

**Why this won't fix itself:** Social platform notifications are designed to drive engagement using the exact psychological triggers that phishing uses — curiosity, social proof, urgency of connection. Any content-only classifier will conflate legitimate LinkedIn notifications with LinkedIn phishing. The content is genuinely ambiguous without knowing the sender is authenticated.

**Possible fixes, in order of preference:**
1. **Cross-analyzer context sharing** (architectural change): Pass authentication results from header_analysis into NLP intent. When SPF/DKIM/DMARC all pass from a known social platform domain, dampen NLP phishing scores. Correct fix but requires refactoring the analyzer interface — currently all analyzers run independently.
2. **Known-sender allowlist in NLP** (fragile): Hardcode linkedin.com, facebook.com, etc. as domains where engagement language should not trigger. Doesn't scale, breaks when platforms change sending domains.
3. **Raise the SUSPICIOUS threshold from 30% to 40%** (blunt): Would fix this FP (36%) but would also let sample_08 BEC (31%) through as CLEAN. Trading one error for another.

## Bugs Fixed During Development

### NLP Non-Determinism (anthropic_client.py)

**Bug:** The Anthropic API call used default temperature=1.0, producing different scores on identical inputs across runs. Sample_08 scored 5% on one run and 30% on the next with no code changes, flipping the verdict between CLEAN and SUSPICIOUS.

**Impact:** Test results were not reproducible. A "100% recall" result on one run became "90% recall" on the next. The improvement on sample_08 between runs was luck, not a code fix.

**Fix:** Set `temperature=0` in the `messages.create()` call. Deterministic inputs now produce deterministic outputs.

**Lesson:** Any ML/LLM component in a detection pipeline must produce reproducible results, or your test metrics are meaningless. Pin temperature, set random seeds, and run multiple times to validate stability before reporting numbers.

### Confidence Scoring Dilution (3 analyzers)

**Bug:** `attachment_sandbox`, `url_reputation`, and `domain_intel` analyzers returned confidence=1.0 with risk=0.0 when they had no data to analyze (no attachments, no URLs). The weighted scoring formula `score = sum(weight * risk * confidence) / sum(weight * confidence)` treated this as "we are 100% confident the risk is 0%," which actively pulled the overall score down.

**Impact:** Recall dropped from ~90% to ~30%. Emails with phishing signals in headers, brand impersonation, and NLP were being suppressed by three analyzers confidently asserting zero risk based on no evidence.

**Fix:** Changed to confidence=0.0 for "no data" cases. The pipeline skips confidence=0 analyzers entirely, removing them from both numerator and denominator.

**Lesson:** In a weighted ensemble, "I have no opinion" (confidence=0) and "I checked and it's clean" (confidence=1, risk=0) are fundamentally different signals. Conflating them is a silent accuracy killer.

### UNIQUE Constraint on sender_emails (sender_profiling.py)

**Bug:** `INSERT INTO sender_emails` used a bare INSERT with `email_id` as PRIMARY KEY. Re-running the batch test on the same samples triggered `UNIQUE constraint failed: sender_emails.email_id` on every sample after the first run. The error was caught and logged but produced noisy output that made the tool look broken.

**Fix:** Changed to `INSERT OR IGNORE INTO sender_emails`. On re-runs, duplicate email_ids are silently skipped. The sender profile statistics (email_count, avg_recipients, etc.) are updated via the separate `senders` table UPDATE path, which already handles duplicates correctly.

**Lesson:** Test harnesses that write to persistent state need idempotent operations. This is obvious in retrospect but easy to miss when the happy path only runs once.

### Unclosed aiohttp Sessions

**Bug:** The `PhishingPipeline` class created API clients (VirusTotal, URLScan, AbuseIPDB, etc.) with long-lived `aiohttp.ClientSession` objects via `BaseAPIClient`, but never called `close()` on them. Python's garbage collector would eventually clean them up, but not before logging `Unclosed client session` warnings at shutdown.

**Fix:** Added `close()` method and async context manager (`__aenter__`/`__aexit__`) to `PhishingPipeline`. The batch test runner now calls `await pipeline.close()` in a `finally` block. This walks all loaded analyzers and their nested client objects, closing sessions cleanly.

**Lesson:** Any code that holds long-lived network sessions needs explicit lifecycle management. "It works" isn't the same as "it shuts down cleanly."

## Structural Issues Worth Knowing

### NLP Dominance With Real LLM

When running with the Anthropic API (vs. the sklearn TF-IDF fallback), the NLP intent analyzer produces scores of 95-100% risk at 85% confidence for most phishing samples. This is correct for credential-harvesting phishing but makes the other analyzers almost irrelevant in the weighted sum — NLP's contribution overwhelms everything else.

This isn't necessarily wrong (LLMs are genuinely good at reading phishing language), but it means the multi-analyzer architecture is effectively a single-classifier system when the LLM is available. The other analyzers add value primarily for edge cases and as fallbacks when the LLM is unavailable or wrong.

### url_reputation Returns "Clean" for Non-Existent Domains — Active Score Suppression

When VirusTotal scans a domain like `microsoftonline-verify.com` that doesn't resolve, it returns "no threats found" with 80% confidence. The pipeline includes this as evidence against phishing: 0% risk at 80% confidence with weight 0.15 adds 0.12 to the weighted denominator without adding anything to the numerator.

**Measured impact:** Removing url_reputation from the calculation for sample_01 (Microsoft credential harvest) raises the score from ~50% to ~65%. For sample_09 (IRS tax refund), from ~48% to ~64%. This is approximately **15 points of suppression** on every phishing sample that uses a non-resolving domain — which is 8 of the 10 phishing samples.

This means every phishing email using a fresh/dead domain (which is most real-world phishing) is being actively scored lower by the very analyzer designed to catch malicious URLs. The samples that "should" score in the LIKELY_PHISHING band (60%+) are being compressed into the SUSPICIOUS band (30-60%) by a service confidently saying "no threats" about domains with no history.

**Fix:** When url_reputation gets a "no results" or "no threats found" response for a domain that doesn't resolve in DNS, it should return confidence=0.3 instead of 0.8. The signal is "we checked and found nothing" which is not the same as "we checked and it's clean." The domain_intel analyzer partially covers new-domain risk detection, but url_reputation and domain_intel don't share context.

### Score Clustering

Phishing scores cluster in the 39-50% range on the real test set. The thresholds (SUSPICIOUS at 30%, LIKELY_PHISHING at 60%) mean most phishing lands in the SUSPICIOUS band rather than LIKELY_PHISHING. This is partly because legitimate analyzers (url_reputation, domain_intel) contributing moderate-confidence "clean" signals compress the score distribution toward the middle.

### Circuit Breaker Opens Mid-Batch

When an API (usually VirusTotal) hits rate limits, the circuit breaker opens and later samples run with degraded analyzers. This means test results aren't consistent across samples — early samples get full analysis while later ones run with fewer signals. For batch testing, either add delays between samples or accept that results reflect degraded-mode behavior for later samples.

## What Would Actually Improve Detection

In order of impact:

1. **Cross-analyzer context sharing:** Let the NLP analyzer see authentication results. "Engagement language from authenticated linkedin.com" is different from "engagement language from l1nked1n-alerts.com." This would fix the LinkedIn FP and similar social platform notifications.

2. **BEC detection module:** Purpose-built analyzer for authority manipulation, unusual internal sharing patterns, and financial language in contexts that don't match the sender's normal behavior. Requires organizational context (directory, communication graph) that this pipeline doesn't have.

3. **Confidence calibration for url_reputation:** Reduce confidence when external services return "no data" vs. "scanned and clean." A domain with no VirusTotal history is unknown, not safe.

4. **Per-sample API rate management:** Add configurable delays between samples in batch mode to prevent circuit breaker activation mid-run.
