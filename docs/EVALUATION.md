# Evaluation Methodology

This document describes how the phishing detection pipeline should be evaluated against real-world corpora, what metrics to report, and what the current honest answer is for each metric. It exists because **a detection project that doesn't say what it catches and what it misses is selling vibes, not detection**.

The goal is not to claim impressive numbers. The goal is to make the methodology reproducible so that anyone — me, a reviewer, an interviewer — can run the same evaluation and get the same numbers, and so that improvements can be measured against a baseline rather than asserted.

---

## 1. Corpora

### 1.1 Phishing-positive corpora

| Corpus                          | Size (approx) | Provenance                                         | Use                              |
| ------------------------------- | ------------- | -------------------------------------------------- | -------------------------------- |
| **Nazario phishing corpus**     | ~25k emails   | Jose Nazario's monthly archive (2004–present)      | Long-tail historical phishing    |
| **PhishTank exports**           | varies        | URLs, not full emails — used for `url_reputation` only | URL-layer baseline           |
| **APWG eCrime archive**         | varies        | APWG members only — not redistributable            | Cited but not redistributable    |
| **Internal sample set**         | ~50 emails    | Hand-curated from `tests/sample_emails/` and `tests/real_world_samples/` | Reproducible smoke tests |

### 1.2 Negative (legitimate) corpora

| Corpus                          | Size (approx) | Provenance                                         | Use                              |
| ------------------------------- | ------------- | -------------------------------------------------- | -------------------------------- |
| **Enron email dataset**         | ~500k emails  | Public release, c. 2003, business correspondence   | Bulk false-positive baseline     |
| **TREC public mail tracks**     | ~50k emails   | TREC 2007 spam track, ham split                    | Diverse legitimate mail          |
| **Synthetic legitimate set**    | growing       | `tests/sample_emails/legitimate/` — hand-curated   | Reproducible negative cases      |

### 1.3 Quality caveats

- **Nazario is biased toward older phishing.** Brand impersonation patterns from 2008 don't reflect 2024 attack tradecraft. Treat as a *recall floor*, not a tradecraft sample.
- **Enron is biased toward American corporate English.** Legitimate transactional mail in other languages and formats is underrepresented; expect higher false positive rates on multilingual inboxes than Enron suggests.
- **PhishTank URLs are post-hoc labeled.** Many were dead by the time of labeling. Run URL-layer evaluation against historical reputation data, not live API calls.

---

## 2. Metrics

### 2.1 Verdict-level metrics

For each verdict (`CLEAN`, `SUSPICIOUS`, `LIKELY_PHISHING`, `CONFIRMED_PHISHING`):

- **Precision** — of all emails the pipeline labeled X, what fraction were actually X?
- **Recall** — of all emails actually X, what fraction did the pipeline catch?
- **F1** — harmonic mean.

The honest target metrics for a defensive deployment are:

| Verdict             | Precision goal | Recall goal | Why                                                                |
| ------------------- | -------------- | ----------- | ------------------------------------------------------------------ |
| CONFIRMED_PHISHING  | ≥ 0.99         | ≥ 0.30      | High precision because this verdict drives auto-block in operator workflows. Recall is secondary; we'd rather miss than mislabel. |
| LIKELY_PHISHING     | ≥ 0.90         | ≥ 0.60      | Drives analyst review. False positives waste analyst time.        |
| SUSPICIOUS          | ≥ 0.70         | ≥ 0.80      | Catch-all bucket; high recall is the point.                       |
| CLEAN               | ≥ 0.95         | ≥ 0.90      | Equivalent to negative-class precision.                           |

The **confidence-capping rule** (verdicts capped to SUSPICIOUS when overall confidence < 0.4, see `decision_engine.py:444`) means SUSPICIOUS will always be the high-recall bucket and CONFIRMED_PHISHING will always be the high-precision bucket *by design*. Evaluate this trade-off, don't fight it.

### 2.2 Analyzer-level metrics

For each analyzer, evaluate independently:

- **Coverage** — of emails where this analyzer's signal is *applicable* (e.g., for URL reputation, emails containing URLs), what fraction did it produce a confidence > 0 result for?
- **Per-analyzer precision/recall** — treating `risk_score >= 0.5` as positive.
- **Failure mode breakdown** — for analyzers that returned `confidence == 0`, why? API timeout? Missing data? Library not installed?

The point of analyzer-level evaluation is to catch silent degradation. If `url_detonator` coverage drops from 95% to 60% because the headless browser is OOM-killing, the verdict-level metrics will degrade gradually, but analyzer coverage shows it immediately.

### 2.3 ATT&CK-level recall

For each technique listed in `docs/MITRE_ATTACK_MAPPING.md`, manually label a small set of corpus emails (~20 per technique) and measure how often the responsible analyzer fires. This is the metric that actually answers "does the pipeline catch what it claims to catch?"

This is labor-intensive and should be run quarterly, not per-PR.

### 2.4 Latency

- **End-to-end p50 / p95 / p99** for the pipeline on a single email
- **Per-analyzer p95**
- **Sandbox detonation timeout rate** (analyzer returned no data because the 120s pipeline timeout fired before the sandbox finished)

Latency matters because the pipeline is async and concurrent. A regression in one analyzer's tail latency drags every verdict.

---

## 3. Procedure

### 3.1 Reproducible run

```bash
# 1. Stage corpus
python scripts/eval_prepare_corpus.py --output ./eval_corpus/

# 2. Run pipeline against every email, write structured results
python scripts/eval_run.py --corpus ./eval_corpus/ --output ./eval_results.jsonl

# 3. Compute metrics against ground-truth labels
python scripts/eval_metrics.py --results ./eval_results.jsonl --labels ./eval_corpus/labels.csv

# 4. Diff against baseline
python scripts/eval_diff.py --baseline ./eval_baselines/2026-04.json --current ./eval_results_summary.json
```

**None of these scripts exist yet.** Building this harness is a roadmap item (see `ROADMAP.md` "Automated evaluation harness"). Today the project has unit tests but no detection-quality metrics on real corpora.

The shape of the harness is documented here so when it gets built, the design isn't reinvented.

### 3.2 What to fix the seed on

- API client randomness (jitter on retries) — disable during eval
- LLM intent classifier — pin model version + temperature 0
- Sandbox VM selection — prefer same provider for reproducibility

Without seed control, eval runs aren't comparable across days.

### 3.3 Data leakage

The unit tests in `tests/unit/` use a small set of hand-crafted emails that exist in the repository. **These must not be in the evaluation corpus.** Any overlap inflates metrics by measuring memorization rather than generalization.

---

## 4. Current honest answer

As of this commit:

- **No corpus-based evaluation has been run.** The numbers above are *targets*, not reported results.
- **Unit tests pass at 676/676**, but unit tests measure code correctness, not detection quality. They are necessary, not sufficient.
- **Manual verification** has been done on the small sample set in `tests/real_world_samples/` and `tests/sample_emails/`. Those are smoke tests, not evaluation.
- **The evaluation harness (§3) is not built.** Building it is on the roadmap. Until it exists, any precision/recall claim from this project is suspect and should be challenged.

This is the right answer to give a reviewer: "we have a methodology and we know we don't have results yet." It is wrong to publish made-up numbers and worse to publish numbers from a corpus that overlaps the test set.

---

## 5. When numbers exist

When the harness lands and produces real numbers, this section will be filled in with:

- Date of evaluation run
- Commit SHA
- Corpora used (with sizes and version dates)
- Verdict-level confusion matrix
- Per-analyzer metrics table
- ATT&CK technique recall table
- Latency percentiles
- Diff vs. previous baseline (regressions called out by name)

Until then, it is intentionally blank. **Do not fill this section in with synthetic numbers.**
