# Automated Phishing Detection Pipeline — Project Briefing

**Date:** 2026-04-03
**Version:** v1.0 (all bugs fixed, temperature=0)
**Stack:** Python 3.10+ / FastAPI / asyncio / SQLAlchemy / Playwright

---

## What It Does

An automated email phishing detection system that ingests emails (via IMAP polling, Gmail API, Outlook, or manual upload), extracts threat indicators, runs them through 7-8 concurrent analyzers backed by external threat intelligence APIs, scores results using a confidence-weighted formula, and delivers verdicts through a web dashboard with analyst feedback for continuous improvement.

The pipeline processes an email in 3 phases: **extraction** (parse MIME, validate headers, pull URLs/QR codes/attachments) → **analysis** (concurrent threat intelligence queries) → **decision** (weighted scoring, override rules, verdict mapping).

---

## Current Performance

Tested against 22 synthetic email samples: 10 phishing campaigns (Microsoft, PayPal, DHL, Apple, Netflix, BofA, Amazon, Google Workspace, IRS, LinkedIn) plus 12 legitimate brand emails from the same senders being impersonated.

| Metric | Stable Value | Notes |
|--------|-------------|-------|
| Recall | **90%** (9/10) | Sample_08 BEC oscillates near threshold — not reliable |
| Precision | **91%** (10/11) | 1 persistent FP: LinkedIn digest |
| F1 Score | **0.90** | |
| False Positives | 1 (LinkedIn) | NLP misclassifies engagement language |
| False Negatives | 0-1 (Google BEC) | Unstable: 31% vs 30% threshold |

All samples are synthetic .eml files, not captured wild phishing. Real-world performance against adversarial evasion techniques will be lower.

---

## Architecture

```
                          ┌─────────────────────────────────────────────┐
                          │              INGESTION LAYER                │
                          │  IMAP Poller │ Gmail API │ Outlook │ Upload │
                          └─────────────────────┬───────────────────────┘
                                                │
                          ┌─────────────────────▼───────────────────────┐
                          │           EXTRACTION LAYER (Sequential)      │
                          │  EML Parser → Header Analyzer → URL Extract  │
                          │  → QR Decoder → Attachment Handler → Metadata│
                          └─────────────────────┬───────────────────────┘
                                                │
              ┌─────────────┬───────────┬───────▼────────┬──────────────┬─────────────┐
              │             │           │                │              │             │
        ┌─────▼─────┐ ┌────▼────┐ ┌────▼─────┐  ┌──────▼───────┐ ┌───▼────┐ ┌──────▼──────┐
        │    URL     │ │ Domain  │ │   URL    │  │    Brand     │ │  NLP   │ │ Attachment  │
        │ Reputation │ │  Intel  │ │Detonation│  │Impersonation │ │ Intent │ │  Sandbox    │
        │ (VT, GSB,  │ │(WHOIS,  │ │(Playwright│ │(domain match,│ │(LLM or │ │(HybridAnlys │
        │ urlscan,   │ │ DNS,    │ │ headless  │ │ content,     │ │sklearn) │ │ AnyRun,     │
        │ AbuseIPDB) │ │ feeds)  │ │ browser)  │ │ visual sim)  │ │        │ │ YARA)       │
        └─────┬──────┘ └────┬────┘ └────┬─────┘  └──────┬───────┘ └───┬────┘ └──────┬──────┘
              │             │           │                │             │             │
              └─────────────┴───────────┴────────┬───────┴─────────────┴─────────────┘
                                                 │
                          ┌──────────────────────▼──────────────────────┐
                          │           DECISION ENGINE                    │
                          │  Weighted Scoring → Override Rules →         │
                          │  Confidence Capping → Verdict → Reasoning    │
                          └──────────────────────┬──────────────────────┘
                                                 │
                    ┌────────────────────────────┼───────────────────────────┐
                    │                            │                           │
              ┌─────▼──────┐          ┌──────────▼──────────┐      ┌────────▼────────┐
              │   Reports   │          │    Web Dashboard     │      │  IOC Export     │
              │ (JSON/HTML) │          │  (FastAPI + Feedback)│      │  (STIX 2.1)     │
              └────────────┘          └─────────────────────┘      └─────────────────┘
```

---

## Scoring Formula

```
score = Σ(weight_i × risk_i × confidence_i) / Σ(weight_i × confidence_i)
```

Each analyzer returns a `risk_score` (0.0–1.0) and `confidence` (0.0–1.0). Analyzers with no relevant data (e.g., attachment analyzer when there are no attachments) return `confidence=0.0`, which correctly excludes them from the calculation. Weights are configurable and default to:

| Analyzer | Weight | What It Does |
|----------|--------|---|
| url_reputation | 0.15 | Queries VirusTotal, Google Safe Browsing, urlscan.io, AbuseIPDB |
| url_detonation | 0.15 | Opens URL in headless Chromium, detects credential forms/redirects |
| attachment_sandbox | 0.15 | File analysis via HybridAnalysis/AnyRun + YARA rules |
| nlp_intent | 0.15 | LLM-based (Claude) or sklearn TF-IDF intent classification |
| domain_intelligence | 0.10 | WHOIS age, DNS records, phishing feed lookups |
| brand_impersonation | 0.10 | Domain-brand mismatch, display name spoofing, keyword analysis |
| header_analysis | 0.10 | SPF/DKIM/DMARC validation, From/Reply-To mismatch |
| sender_profiling | 0.10 | Behavioral baseline: frequency, recipients, timing anomalies |

**Verdict thresholds:** CLEAN [0, 0.3) → SUSPICIOUS [0.3, 0.6) → LIKELY_PHISHING [0.6, 0.8) → CONFIRMED_PHISHING [0.8, 1.0]

---

## Directory Structure

```
Automated Phishing Detection/
├── main.py                        # Entry point: CLI analysis + FastAPI server
├── config.yaml                    # Default configuration
├── requirements.txt               # ~40 dependencies
├── Dockerfile / docker-compose.yml
│
├── src/
│   ├── models.py                  # EmailObject, AnalyzerResult, PipelineResult, Verdict enum
│   ├── config.py                  # PipelineConfig loader (YAML + env vars)
│   ├── orchestrator/pipeline.py   # PhishingPipeline — 3-phase async orchestrator
│   ├── scoring/
│   │   ├── decision_engine.py     # Weighted scoring, overrides, confidence capping
│   │   ├── confidence.py          # Multi-source confidence aggregation
│   │   ├── thresholds.py          # Verdict range management
│   │   └── blocklist_allowlist.py # Fast-path known good/bad sender checks
│   ├── analyzers/                 # 7 concurrent threat analyzers
│   │   ├── url_reputation.py      # Multi-API URL checking
│   │   ├── domain_intel.py        # WHOIS/DNS/feed lookups
│   │   ├── url_detonation.py      # Playwright headless browser
│   │   ├── brand_impersonation.py # Brand spoofing detection
│   │   ├── nlp_intent.py          # LLM + sklearn intent classification
│   │   ├── attachment_sandbox.py  # File sandbox + YARA
│   │   ├── sender_profiling.py    # Behavioral baseline tracking
│   │   └── clients/               # API client layer (circuit breaker, caching)
│   ├── extractors/                # Feature extraction
│   │   ├── eml_parser.py          # MIME parsing
│   │   ├── header_analyzer.py     # SPF/DKIM/DMARC
│   │   ├── url_extractor.py       # URL extraction + defanging
│   │   ├── qr_decoder.py          # QR from images/PDFs/DOCXs
│   │   ├── attachment_handler.py  # Magic bytes, macros, nested files
│   │   └── metadata_extractor.py  # Sender/reply chain
│   ├── feedback/                  # Analyst feedback → weight retraining
│   │   ├── feedback_api.py        # FastAPI endpoints
│   │   ├── database.py            # SQLAlchemy ORM
│   │   ├── retrainer.py           # Logistic regression weight tuning
│   │   └── scheduler.py           # Scheduled background retraining
│   ├── reporting/                 # JSON, HTML, STIX 2.1, web dashboard
│   ├── ingestion/                 # IMAP, Gmail, Outlook, manual upload
│   ├── automation/                # Email monitoring loops
│   ├── security/                  # AES-256-GCM credential vault
│   └── utils/                     # Encoding helpers, screenshots, validators
│
├── reports/                       # Test results and analysis write-ups
│   ├── batch_test_summary.md      # 90% recall, 91% precision, known issues
│   ├── sample_analyses.md         # Per-sample write-ups (22 samples)
│   ├── batch_results.json         # Machine-readable results
│   ├── live_feed_test_report.md   # Real active phishing URL test results
│   └── README.md
│
├── lessons-learned.md             # Honest accounting of bugs, misses, and limitations
│
├── tests/
│   ├── unit/ + integration/       # pytest suite
│   ├── fixtures/                  # Sample emails, attachments, QR codes
│   └── real_world_samples/        # 22 .eml files + batch/live test runners
│
├── models/                        # Pre-trained ML models (brand + intent)
├── config/brand_references/       # Brand logo images for visual comparison
├── templates/                     # Jinja2 dashboard + report templates
└── data/                          # Runtime: feedback.db, sender_profiles.db
```

---

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Web dashboard |
| POST | `/api/analyze` | Upload .eml for analysis |
| GET | `/api/results/{email_id}` | Retrieve result JSON |
| POST | `/api/feedback` | Submit analyst verdict correction |
| GET | `/api/feedback/stats` | Feedback statistics |
| GET | `/api/gap-analysis` | Identify weakest analyzers |
| POST | `/api/feedback/export` | Export feedback as CSV/JSONL |
| GET | `/api/health` | Health check |

---

## External Dependencies

**API Keys Required (in `.env`):**

| Key | Service | Used By |
|-----|---------|---------|
| `VIRUSTOTAL_API_KEY` | VirusTotal | url_reputation, attachment_sandbox |
| `URLSCAN_API_KEY` | urlscan.io | url_reputation |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | url_reputation |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google | url_reputation |
| `HYBRID_ANALYSIS_API_KEY` | Hybrid Analysis | attachment_sandbox |
| `ANYRUN_API_KEY` | AnyRun | attachment_sandbox |
| `ANTHROPIC_API_KEY` | Claude | nlp_intent |

**System Dependencies:** Playwright + Chromium (url_detonation), libzbar0 (QR decoding), dnspython (domain_intel)

---

## Bugs Fixed

1. **Confidence scoring dilution** (3 analyzers): "No data" returns used confidence=1.0 instead of 0.0, diluting all scores. Recall went from 30% to 90% after fix.
2. **NLP non-determinism**: Anthropic API called with default temperature=1.0 — same email scored differently across runs, flipping verdicts. Fixed to temperature=0.
3. **UNIQUE constraint crash**: sender_profiling INSERT failed on batch re-runs. Fixed with INSERT OR IGNORE.
4. **Unclosed aiohttp sessions**: Pipeline didn't close API client sessions. Added close() method and try/finally cleanup.
5. **Brand database gaps**: Added 15 brands (IRS, SSA, gaming, financial). Added .gov domain validation.
6. **Cross-brand false positives**: Amazon mentioning USPS, Google triggering bank_generic. Fixed with known-brand exemption system.

See `lessons-learned.md` in project root for detailed root cause analysis of each bug.

---

## Known Gaps

1. **LinkedIn false positive (persistent)** — NLP scores 99% on legitimate LinkedIn engagement language. Requires cross-analyzer context sharing (NLP needs to see authentication results) to fix properly. See `lessons-learned.md`.
2. **url_reputation dilutes phishing scores** — VirusTotal returns "clean" with 80% confidence for non-resolving domains, suppressing phishing scores by ~15 points. This is why all phishing lands in SUSPICIOUS (31-53%) and none reach LIKELY_PHISHING (60%+).
3. **BEC detection is fragile** — Sample_08 (Google Workspace shared doc) scores 31% against a 30% threshold. BEC using authority/curiosity manipulation is structurally hard for this pipeline.
4. **Sender profiling has no discrimination** — Returns 45% for all unknown senders. Needs history accumulation.
5. **Score clustering** — Phishing scores compressed into 22-point band (31-53%) by url_reputation dilution and sender_profiling's flat 45%.
6. **Circuit breaker inconsistency** — URLScan hits rate limits after 4-6 samples, degrading url_detonation for later samples in batch runs.
7. **LLM fallback quality** — Without Anthropic API key, NLP falls back to sklearn TF-IDF (~70% vs ~92% accuracy).
8. **Synthetic test set only** — All 22 samples are lab-constructed. Real phishing uses obfuscation, IDN homographs, and evasion techniques these samples don't exercise.

---

## Quick Start

```bash
# Install
pip install -r requirements.txt
playwright install chromium

# Configure
cp .env.example .env   # Add your API keys

# Analyze a single email
python main.py --analyze path/to/email.eml --format json

# Start the dashboard
python main.py --serve --port 8000

# Run batch test
python tests/real_world_samples/run_batch_test.py

# Run live feed test (fetches real phishing URLs)
python tests/real_world_samples/run_live_test.py

# Docker
docker-compose up -d
```

---

## Feedback Loop

Analysts submit verdict corrections through the dashboard or `/api/feedback`. The `RetrainOrchestrator` uses logistic regression on accumulated feedback to adjust analyzer weights. A background scheduler runs retraining periodically. The system also maintains local blocklists/allowlists for fast-path overrides on known senders.

---

## Configuration Hierarchy

Lowest → Highest priority: **Hardcoded defaults** → **config.yaml** → **Environment variables** → **CLI arguments**

Key tuning levers: analyzer weights in `config.yaml`, verdict thresholds (default 0.3/0.6/0.8), concurrent analyzer limit (default 10), pipeline timeout (default 120s).
