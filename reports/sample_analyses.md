# Individual Sample Analysis Write-Ups

Each analysis below documents what the pipeline detected, what it missed, and what an analyst should look for.

> **Test environment:** Windows 11, all 4 API keys active (VirusTotal, URLScan, AbuseIPDB, Anthropic Claude Haiku 4.5). NLP intent uses LLM with temperature=0. Results from latest batch run (2026-04-03).
>
> **Important caveat:** All 22 samples are synthetic .eml files, not captured wild phishing. Real phishing includes obfuscation, IDN homographs, and evasion techniques these samples don't exercise.

---

## PHISHING SAMPLES (10)

---

### Sample 01: Microsoft 365 Credential Harvest

**Verdict:** SUSPICIOUS (50%) — TP

**Analyzers:**
- nlp_intent: 100% (conf 95%) — strong urgency/threat language
- brand_impersonation: 75% (conf 90%) — Microsoft impersonation from `microsoftonline-verify.com`
- domain_intelligence: 60% (conf 80%) — non-resolving domain, WHOIS failure
- sender_profiling: 45% (conf 50%) — unknown sender
- header_analysis: 20% (conf 50%) — reply-to mismatch
- url_reputation: 0% (conf 80%) — VirusTotal returned "no threats" for non-resolving domain (**active dilution: ~15 points of score suppression**)

**What the pipeline missed:**
- url_reputation confidently says "clean" for a domain that doesn't resolve in DNS — this should be suspicious, not clean
- Spoofed `X-MS-Exchange-Organization-SCL: -1` header not flagged
- Received headers show Eastern European IP, not Microsoft infrastructure

---

### Sample 02: PayPal Account Suspension

**Verdict:** SUSPICIOUS (41%) — TP

**Analyzers:**
- nlp_intent: 100% (conf 95%)
- brand_impersonation: 75% (conf 90%) — `paypal-accountreview.com`
- domain_intelligence: 60% (conf 80%)
- sender_profiling: 45% (conf 50%)
- header_analysis: 20% (conf 50%)
- url_reputation: 0% (conf 80%) — same "clean for non-resolving domain" dilution
- url_detonation: 0% (conf 40%) — URLScan blocked the scan

---

### Sample 03: DHL Delivery Notification

**Verdict:** SUSPICIOUS (48%) — TP

**Analyzers:**
- nlp_intent: 99% (conf 85%)
- brand_impersonation: 85% (conf 100%) — strongest brand signal in the set
- domain_intelligence: 60% (conf 80%)
- sender_profiling: 45% (conf 50%)
- url_reputation: 0% (conf 80%) — dilution
- header_analysis: 0% (conf 50%)

**Note:** Took 53.2s due to URLScan timeout on the non-resolving domain.

---

### Sample 04: Apple ID Disabled

**Verdict:** SUSPICIOUS (39%) — TP

**Analyzers:**
- nlp_intent: 100% (conf 95%)
- brand_impersonation: 75% (conf 90%)
- domain_intelligence: 60% (conf 80%)
- sender_profiling: 45% (conf 50%)
- url_reputation: 0% (conf 80%) — dilution
- url_detonation: 0% (conf 40%)

**Note:** Circuit breaker opened after this sample (5 URLScan failures). Later samples run with degraded url_detonation.

---

### Sample 05: Netflix Payment Failed

**Verdict:** SUSPICIOUS (53%) — TP (Highest phishing score)

**Analyzers:**
- nlp_intent: 100% (conf 95%)
- brand_impersonation: 75% (conf 80%)
- domain_intelligence: 60% (conf 80%)
- sender_profiling: 45% (conf 50%)
- url_reputation: 26% (conf 90%) — **only sample where VirusTotal returned actual risk**
- header_analysis: 0% (conf 50%)

**Why this scored highest:** The Netflix domain `netflix-billing-update.com` apparently has some VirusTotal history, so url_reputation contributed 26% instead of the usual 0%. This is the only phishing sample where url_reputation helped rather than hindered.

---

### Sample 06: Bank of America Wire Transfer

**Verdict:** SUSPICIOUS (50%) — TP

**Analyzers:**
- nlp_intent: 100% (conf 95%)
- brand_impersonation: 77% (conf 70%)
- domain_intelligence: 60% (conf 80%)
- sender_profiling: 45% (conf 50%)
- header_analysis: 20% (conf 50%)
- url_reputation: 0% (conf 80%) — dilution

---

### Sample 07: Amazon Order Confirmation

**Verdict:** SUSPICIOUS (50%) — TP

**Analyzers:**
- nlp_intent: 99% (conf 95%)
- brand_impersonation: 75% (conf 100%) — `email-amazn.com` typosquat detected
- domain_intelligence: 60% (conf 80%)
- sender_profiling: 45% (conf 50%)
- header_analysis: 20% (conf 50%)
- url_reputation: 0% (conf 80%) — dilution

---

### Sample 08: Google Workspace Shared Document (BEC)

**Verdict:** SUSPICIOUS (31%) — TP (UNSTABLE)

**Analyzers:**
- brand_impersonation: 70% (conf 80%)
- domain_intelligence: 60% (conf 80%)
- sender_profiling: 45% (conf 50%)
- nlp_intent: 30% (conf 35%) — **low confidence, correctly uncertain**
- header_analysis: 0% (conf 50%)
- url_reputation: 0% (conf 80%) — dilution

**Critical note:** This result is NOT reliable. On a previous run with temperature=1.0, NLP scored 5% and the overall was 26% (CLEAN — false negative). Even with temperature=0, the 31% score is 1 point above the 30% threshold. Any drift in any analyzer could flip this back to a miss. This is a BEC attack using authority/curiosity manipulation, not credential harvesting — a category this pipeline is not designed to detect.

---

### Sample 09: IRS Tax Refund

**Verdict:** SUSPICIOUS (48%) — TP

**Analyzers:**
- nlp_intent: 99% (conf 95%)
- brand_impersonation: 85% (conf 100%) — IRS brand + .gov domain validation firing
- domain_intelligence: 60% (conf 80%)
- sender_profiling: 45% (conf 50%)
- url_reputation: 0% (conf 80%) — dilution
- header_analysis: 0% (conf 50%)

**History:** This was previously a false negative (20%) before the IRS was added to the brand database and .gov domain validation was implemented. Now one of the stronger detections thanks to the .gov check giving brand_impersonation 85% at 100% confidence.

---

### Sample 10: LinkedIn Connection Request (Phishing)

**Verdict:** SUSPICIOUS (50%) — TP

**Analyzers:**
- nlp_intent: 99% (conf 85%)
- brand_impersonation: 75% (conf 80%) — `linkedln-mail.com` homoglyph detected (l vs i)
- domain_intelligence: 60% (conf 80%)
- sender_profiling: 45% (conf 50%)
- header_analysis: 20% (conf 50%)
- url_reputation: 0% (conf 80%) — dilution

---

## LEGITIMATE SAMPLES (12)

---

### Sample 11: GitHub Issue Notification

**Verdict:** CLEAN (23%) — TN

**Analyzers:**
- url_detonation: 60% (conf 80%) — flagged redirect behavior on legitimate GitHub URLs
- url_reputation: 50% (conf 0%) — **timed out** (60s), correctly excluded from scoring
- sender_profiling: 45% (conf 50%)
- domain_intelligence: 20% (conf 80%)
- nlp_intent: 5% (conf 98%) — correctly identified as non-phishing with high confidence
- header_analysis: 0% (conf 83%)
- brand_impersonation: 0% (conf 80%)

**Note:** url_reputation timed out entirely. The 60s timeout caused a 0% confidence return which the pipeline correctly excluded. This is the designed behavior.

---

### Sample 12: Work Email (Plain Text)

**Verdict:** CLEAN (13%) — TN (Lowest score in set)

**Analyzers:**
- sender_profiling: 45% (conf 50%)
- nlp_intent: 9% (conf 98%) — correctly identified as routine communication
- header_analysis: 0% (conf 83%)
- All others: 0% (conf 0%) — no URLs, no brand signals, correctly excluded

---

### Sample 13: Legitimate Amazon Order Confirmation

**Verdict:** CLEAN (19%) — TN

**Analyzers:**
- url_detonation: 60% (conf 80%) — flagged redirect on amazon.com links
- sender_profiling: 45% (conf 50%)
- domain_intelligence: 20% (conf 80%)
- nlp_intent: 5% (conf 95%) — correctly low
- url_reputation: 0% (conf 80%) — amazon.com verified clean
- brand_impersonation: 0% (conf 80%) — correctly identified `auto-confirm@amazon.com` as legitimate

**Key test:** This is the mirror of sample_07 (phishing Amazon). The pipeline correctly distinguished real Amazon from fake Amazon. brand_impersonation scored 75% on the fake (`email-amazn.com`) and 0% on the real (`amazon.com`).

---

### Sample 14: Legitimate PayPal Receipt

**Verdict:** CLEAN (13%) — TN

**Analyzers:**
- sender_profiling: 45% (conf 50%)
- nlp_intent: 30% (conf 45%) — moderate phishing signal due to payment language, but low confidence dampens it
- domain_intelligence: 20% (conf 80%)
- url_reputation: 3% (conf 80%)
- brand_impersonation: 0% (conf 80%) — `service@paypal.com` correctly identified as legitimate

---

### Sample 15: Legitimate Google Security Alert

**Verdict:** CLEAN (14%) — TN

**Analyzers:**
- domain_intelligence: 60% (conf 80%)
- sender_profiling: 55% (conf 50%)
- nlp_intent: 5% (conf 85%) — correctly low despite "Security alert" subject line
- header_analysis: 0% (conf 83%)
- url_reputation: 0% (conf 80%)
- brand_impersonation: 0% (conf 80%) — `no-reply@accounts.google.com` correctly identified as legitimate

**Key test:** Google security alerts use the exact same language as phishing ("New sign-in from Chrome on Windows"). The pipeline correctly distinguished this from sample_01 (Microsoft credential harvest) because the sender domain is legitimate.

---

### Sample 16: Legitimate Netflix Newsletter

**Verdict:** CLEAN (17%) — TN

**Analyzers:**
- url_detonation: 50% (conf 53%) — some redirect behavior on netflix.com links
- sender_profiling: 45% (conf 50%)
- domain_intelligence: 20% (conf 80%)
- nlp_intent: 5% (conf 95%) — correctly identified as marketing content
- brand_impersonation: 0% (conf 80%) — `info@mailer.netflix.com` correctly identified as legitimate Netflix subdomain

**Key test:** Mirror of sample_05 (phishing Netflix). Pipeline correctly identified real Netflix vs fake Netflix. The known-brand exemption for mailer.netflix.com prevents the "booking" substring from triggering a lookalike match.

---

### Sample 17: Legitimate LinkedIn Weekly Digest — FALSE POSITIVE

**Verdict:** SUSPICIOUS (36%) — FP (KNOWN ISSUE, UNRESOLVED)

**Analyzers:**
- nlp_intent: 99% (conf 85%) — **ROOT CAUSE OF FALSE POSITIVE**
- url_detonation: 60% (conf 80%)
- sender_profiling: 45% (conf 50%)
- domain_intelligence: 20% (conf 80%)
- header_analysis: 0% (conf 83%)
- url_reputation: 0% (conf 100%) — linkedin.com verified clean
- brand_impersonation: 0% (conf 80%) — `messages-noreply@linkedin.com` correctly identified as legitimate

**Root cause:** NLP scores "12 people viewed your profile" as 99% phishing because engagement language ("viewed your profile," "connect with," "expand your network") is structurally identical to phishing bait. The NLP cannot see that SPF/DKIM/DMARC passed from real linkedin.com — it only sees the email text. Every other analyzer correctly identified this as legitimate, but NLP's 99% at 85% confidence overwhelms them in the weighted formula.

**Contrast with sample_10:** The phishing LinkedIn (from `linkedln-mail.com`) also scored 99% NLP. The content is genuinely indistinguishable — the difference is only in sender authentication, which the NLP doesn't have access to.

---

### Sample 18: Legitimate Bank of America Statement

**Verdict:** CLEAN (12%) — TN

**Analyzers:**
- sender_profiling: 45% (conf 50%)
- nlp_intent: 5% (conf 95%) — correctly low
- header_analysis: 0% (conf 83%)
- brand_impersonation: 0% (conf 80%) — `ealerts@ealerts.bankofamerica.com` correctly identified

**Key test:** Mirror of sample_06 (phishing BofA wire transfer). Pipeline correctly distinguished real BofA from fake.

---

### Sample 19: Legitimate DHL Tracking

**Verdict:** CLEAN (10%) — TN (Second-lowest score)

**Analyzers:**
- sender_profiling: 45% (conf 50%)
- domain_intelligence: 20% (conf 80%)
- nlp_intent: 5% (conf 85%) — correctly low
- url_reputation: 0% (conf 80%)
- brand_impersonation: 0% (conf 80%) — `noreply@dhl.com` correctly identified as legitimate

**Key test:** Mirror of sample_03 (phishing DHL). Pipeline correctly distinguished real DHL from fake.

---

### Sample 20: Legitimate Stripe Invoice

**Verdict:** CLEAN (12%) — TN

**Analyzers:**
- sender_profiling: 45% (conf 50%)
- nlp_intent: 5% (conf 95%) — correctly low despite payment language
- header_analysis: 0% (conf 83%)
- brand_impersonation: 0% (conf 80%)

---

### Sample 21: Legitimate Substack Newsletter

**Verdict:** CLEAN (24%) — TN

**Analyzers:**
- brand_impersonation: 63% (conf 70%) — partial brand match on newsletter content mentioning tech brands
- sender_profiling: 45% (conf 50%)
- url_detonation: 40% (conf 80%)
- domain_intelligence: 20% (conf 80%)
- nlp_intent: 5% (conf 95%) — correctly low
- url_reputation: 3% (conf 80%)

**Note:** brand_impersonation scored 63% because the newsletter body mentions multiple tech brands (AI companies, earnings reports). This is a known limitation — newsletters that discuss brand names trigger brand-content mismatch signals. At 24%, it stays CLEAN but this is higher than ideal for a legitimate newsletter.

---

### Sample 22: Legitimate DocuSign

**Verdict:** CLEAN (27%) — TN

**Analyzers:**
- domain_intelligence: 60% (conf 80%)
- url_detonation: 50% (conf 80%)
- sender_profiling: 45% (conf 50%)
- nlp_intent: 32% (conf 45%) — moderate signal due to "please sign" language, but low confidence
- url_reputation: 3% (conf 80%)
- brand_impersonation: 0% (conf 80%) — `dse_na3@docusign.net` correctly identified as legitimate

**Note:** At 27%, this is the closest legitimate sample to the 30% threshold (excluding the FP). The "please sign" language and DocuSign's inherently action-oriented emails make this a borderline case for content-based classifiers.
