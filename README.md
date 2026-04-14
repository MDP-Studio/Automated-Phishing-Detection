# Automated Phishing Detection Pipeline

A modular, async Python pipeline that ingests emails (IMAP polling or manual upload), extracts features, runs 7 concurrent analyzers against threat intelligence APIs, scores results with weighted confidence aggregation, and emits detection content (STIX 2.1 IOCs and Sigma rules) for downstream defensive consumption.

This is a **detection engineering** project, not just a classifier. Every analyzer is mapped to MITRE ATT&CK techniques in [`docs/MITRE_ATTACK_MAPPING.md`](docs/MITRE_ATTACK_MAPPING.md), the trust boundaries and residual risks are documented in [`THREAT_MODEL.md`](THREAT_MODEL.md), and security disclosure is in [`SECURITY.md`](SECURITY.md).

## Architecture

```
Email Ingestion → Feature Extraction → Concurrent Analysis → Decision Engine → Reporting
     │                   │                    │                    │              │
  IMAP poll         EML parsing         7 analyzers           Weighted        JSON/HTML
  Manual upload     Header analysis     (async parallel)      scoring         STIX 2.1
  .eml/.msg files   URL extraction      API clients           Overrides       Dashboard
                    QR decoding         NLP intent            Confidence
                    Attachments         Brand matching        Thresholds
```

## Detection Coverage

The pipeline covers ~12 sub-techniques across **TA0001 Initial Access**, **TA0042 Resource Development**, **TA0005 Defense Evasion**, and **TA0008 Lateral Movement**. Full mapping with per-analyzer rationale and known gaps lives in [`docs/MITRE_ATTACK_MAPPING.md`](docs/MITRE_ATTACK_MAPPING.md).

| Tactic                   | Techniques covered                                                                  |
| ------------------------ | ----------------------------------------------------------------------------------- |
| Initial Access           | T1566.001, T1566.002, T1566.003, T1534, T1078 (anomaly only)                         |
| Resource Development     | T1583.001, T1584.001, T1585.002                                                      |
| Defense Evasion          | T1656, T1036.005, T1027.006 (HTML smuggling)                                         |
| User Execution           | T1204.001, T1204.002                                                                 |

The mapping doc also includes an explicit **uncovered techniques** table — what an honest reader would ask about and what the pipeline does not pretend to detect (T1078 full, T1189, T1497, etc.).

### 5-Stage Pipeline

1. **Ingestion** — IMAP polling with UID tracking, manual `.eml`/`.msg` upload, FastAPI upload endpoint
2. **Extraction** — MIME parsing, header analysis (SPF/DKIM/DMARC), URL extraction, QR code decoding, attachment classification via magic bytes
3. **Analysis** — 7 concurrent analyzers: header analysis, URL reputation, domain intelligence, URL detonation, brand impersonation, attachment sandbox, NLP intent classification
4. **Decision** — Weighted confidence scoring with override rules (known malware, BEC intent, confirmed feeds), confidence capping, verdict thresholds
5. **Feedback** — Analyst verdict submission via REST API, logistic regression weight retraining, scheduled retraining loop

## Quick Start

```bash
# 1. Clone and install
git clone <repo-url> && cd automated-phishing-detection
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env with your API keys (VirusTotal, urlscan, AbuseIPDB, etc.)

# 3. Analyze a single email
python main.py --analyze tests/sample_emails/suspicious.eml

# 4. Start the server (IMAP polling + dashboard + feedback API)
python main.py --serve
```

## Configuration

Configuration loads from two sources (env vars override YAML):

| Source | File | Purpose |
|--------|------|---------|
| YAML | `config.yaml` | Non-secret defaults (weights, thresholds, timeouts) |
| Environment | `.env` | Secrets (API keys, IMAP credentials) |

See `config.yaml` for all available options with inline documentation.

## API Keys Required

| Service | Environment Variable | Purpose | Free Tier |
|---------|---------------------|---------|-----------|
| VirusTotal | `VIRUSTOTAL_API_KEY` | URL/file reputation | 500 req/day |
| urlscan.io | `URLSCAN_API_KEY` | URL scanning | 5,000 req/day |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP reputation | 1,000 req/day |
| Google Safe Browsing | `GOOGLE_SAFE_BROWSING_API_KEY` | URL threat matching | 10,000 req/day |
| Hybrid Analysis | `HYBRID_ANALYSIS_API_KEY` | File sandbox detonation | Limited |

Optional: Anthropic/OpenAI key for NLP intent classification, ANY.RUN/Joe Sandbox keys for additional sandbox providers.

## Project Structure

```
src/
├── config.py                    # Configuration (env + YAML)
├── models.py                    # Data models and enums
├── ingestion/
│   ├── imap_fetcher.py          # IMAP polling with UID tracking
│   └── manual_upload.py         # File/directory upload handler
├── extractors/
│   ├── eml_parser.py            # MIME email parsing
│   ├── header_analyzer.py       # SPF/DKIM/DMARC validation
│   ├── url_extractor.py         # URL extraction and defanging
│   ├── qr_decoder.py            # QR code decoding from images/PDFs
│   ├── metadata_extractor.py    # Sender/reply chain metadata
│   └── attachment_handler.py    # Magic byte classification, macros
├── analyzers/
│   ├── url_reputation.py        # Multi-service URL checking
│   ├── domain_intel.py          # WHOIS age, DNS, phishing feeds
│   ├── url_detonator.py         # Headless browser detonation
│   ├── brand_impersonation.py   # Visual similarity (pHash/SSIM)
│   ├── nlp_intent.py            # LLM + sklearn intent classification
│   ├── sender_profiling.py      # Behavioral baseline tracking
│   ├── attachment_sandbox.py    # File sandbox submission
│   └── clients/                 # API client layer
│       ├── base_client.py       # Circuit breaker, cache, rate limiting
│       ├── virustotal.py
│       ├── urlscan.py
│       ├── abuseipdb.py
│       ├── google_safebrowsing.py
│       ├── whois_client.py
│       └── sandbox_client.py
├── scoring/
│   ├── decision_engine.py       # Weighted scoring + overrides
│   ├── confidence.py            # Multi-source confidence aggregation
│   └── thresholds.py            # Verdict range management
├── feedback/
│   ├── feedback_api.py          # FastAPI analyst endpoints
│   ├── database.py              # SQLAlchemy ORM
│   ├── retrainer.py             # Logistic regression weight tuning
│   └── scheduler.py             # Background retraining
├── reporting/
│   ├── report_generator.py      # JSON + HTML reports
│   ├── ioc_exporter.py          # STIX 2.1 bundle export
│   └── dashboard.py             # Web dashboard
├── orchestrator/
│   └── pipeline.py              # Main async orchestrator
└── utils/
    ├── cyberchef_helpers.py     # Encoding/decoding utilities
    ├── screenshot.py            # URL detonation captures
    └── validators.py            # Input validation
```

## Detection Content Exports

The pipeline emits two complementary detection artifacts in addition to JSON/HTML reports:

| Format    | Purpose                                                          | Generator                              |
| --------- | ---------------------------------------------------------------- | -------------------------------------- |
| STIX 2.1  | Per-incident IOC bundle for sharing with TI platforms (MISP, OpenCTI, TAXII) | `src/reporting/ioc_exporter.py`        |
| Sigma     | Per-campaign detection rule for SIEM consumption, plus a static rule library covering broader behavioral patterns | `src/reporting/sigma_exporter.py` + `sigma_rules/` |

```bash
# Single email → JSON report
python main.py analyze tests/sample_emails/suspicious.eml --format json

# Single email → STIX 2.1 bundle of detected IOCs
python main.py analyze tests/sample_emails/suspicious.eml --format stix

# Single email → Sigma rule scoped to this campaign's observables
python main.py analyze tests/sample_emails/suspicious.eml --format sigma

# All four (json + html + stix + sigma) written side by side
python main.py analyze tests/sample_emails/suspicious.eml --format all
```

The static Sigma rule library in [`sigma_rules/`](sigma_rules/) ships hand-written rules for visual brand impersonation, quishing, newly registered domains, BEC wire fraud intent, HTML smuggling, and auth-failure-with-attachment patterns. Each rule carries `tags:` referencing the same ATT&CK techniques in the coverage mapping above.

## Testing

The test suite has **879 tests across 31 modules** (unit + integration), exercising every analyzer, the decision engine override rules (including the cycle 7 ordering fix that catches pure-text BEC), the cross-analyzer calibration pass (ADR 0001) with explicit cap-ceiling tests, scoring confidence capping, IOC export, the Sigma exporter, the URL reputation dead-domain confidence downgrade, credential encryption migration, the LLM determinism contract, the body_html sanitizer with hostile XSS payloads, the data retention purge, and the web security middleware (bearer auth, SSRF guard, security headers). CI runs the full suite on every push and PR against a fresh checkout from the hash-pinned lock file. CI-bites verified by deliberate-red sanity check on a throwaway branch.

```bash
# Run all tests
python -m pytest

# Run with verbose output
python -m pytest -v

# Run a single module
python -m pytest tests/unit/test_decision_engine.py

# Coverage HTML report
python -m pytest --cov=src --cov-report=html
```

| Layer            | Test modules                                                                                          |
| ---------------- | ----------------------------------------------------------------------------------------------------- |
| Extractors       | `test_eml_parser`, `test_header_analyzer`, `test_url_extractor`, `test_qr_decoder`, `test_attachment_handler` |
| Analyzers        | `test_attachment_sandbox`, `test_brand_impersonation`, `test_url_detonation`                          |
| Scoring          | `test_decision_engine`, `test_scoring`                                                                |
| Ingestion        | `test_imap_fetcher`, `test_email_monitor`, `test_blocklist_allowlist`                                 |
| Feedback         | `test_feedback_api`, `test_retrainer`                                                                 |
| Reporting        | `test_report_generator`, `test_ioc_exporter`                                                          |
| Security & utils | `test_security`, `test_web_security`, `test_html_sanitizer`, `test_credentials`, `test_multi_account_monitor`, `test_models`, `test_utils` |
| Detection content | `test_sigma_exporter` (34 tests covering canonical analyzer keys, ATT&CK tag derivation, deterministic UUIDs) |
| URL reputation | `test_url_reputation` (11 tests including the dead-domain confidence downgrade regression) |
| LLM client | `test_anthropic_client` (10 tests locking the determinism contract: temperature=0, top_p=1, model version capture) |
| Integration      | `test_full_pipeline`                                                                                  |

## Known Limitations

1. **Network-dependent features**: URL detonation, API client calls, and IMAP polling require outbound internet access. All API clients degrade gracefully when offline (circuit breaker pattern returns empty results, not errors).

2. **Browser engine required for detonation**: URL detonation and screenshot capture require either Playwright or Selenium with headless Chromium. Without a browser engine, these analyzers return empty results and the pipeline continues with reduced confidence.

3. **QR code decoding dependencies**: Full QR decoding requires `pyzbar`, `opencv-python`, and system library `libzbar0`. Without these, QR-embedded URLs in images won't be extracted. Install with: `apt-get install libzbar0 && pip install pyzbar opencv-python`.

4. **NLP intent classification**: Best results require an LLM API key (Anthropic Claude or OpenAI). Falls back to a sklearn TF-IDF classifier with reduced accuracy (~70% vs ~92% with LLM).

5. **Brand impersonation detection**: Requires `imagehash` and reference brand logos in `brand_references/`. Without reference images, visual similarity scoring is skipped. The pipeline still detects brand impersonation via domain name analysis.

6. **Sandbox analysis latency**: File sandbox detonation (Hybrid Analysis, ANY.RUN, Joe Sandbox) can take 2-10 minutes per file. The pipeline timeout (default 120s) may need increasing for attachment-heavy emails.

7. **STIX 2.1 export**: Requires the `stix2` library (already pinned in `requirements.txt`). Sigma rule export has no extra dependencies — YAML is hand-emitted.

8. **Rate limiting**: Free-tier API keys have strict rate limits. The circuit breaker and TTL cache help, but high-volume deployments need paid API tiers or self-hosted alternatives.

9. **No GPU acceleration**: NLP intent classification and image similarity run on CPU only. This is adequate for email-volume workloads but not for bulk retroactive analysis of large archives.

10. **Single-node deployment**: The current architecture runs on a single node. For multi-node deployment, you'd need to add a message queue (Redis/RabbitMQ) between ingestion and the pipeline, which the async generator interface is designed to support but doesn't implement out of the box.

## Docker Deployment

```bash
docker-compose up -d
```

The current `docker-compose.yml` defines a **single `orchestrator` service** containing the pipeline, dashboard, and Playwright headless browser in one image. The earlier multi-container layout (separate `browser-sandbox` and `redis` services) is a planned change tracked in `ROADMAP.md` — once it lands, browser execution will move to a dedicated network namespace per `THREAT_MODEL.md` §6 R3 hardening guidance.

The image:
- Installs from `requirements.lock` with `pip install --require-hashes` so any dependency tampering fails the build.
- Uses a `urllib.request`-based healthcheck (no `curl` package).
- Runs `docker-entrypoint.sh` as root briefly to chown the `/app/data` and `/app/logs` bind mounts to UID 1000, then `gosu`s to the non-root `phishing` user before exec'ing the pipeline. This closes the bind-mount UID-mismatch issue that previously broke `results.jsonl` writes on Linux hosts where the host bind-mount source is root-owned.

## Data retention & privacy

Stored email metadata in `data/results.jsonl` is regulated personal information under the Australian Privacy Act and the EU GDPR. The pipeline ships with a 30-day default retention window and a `purge` CLI subcommand:

```bash
# Show what would be deleted without modifying the file
python main.py purge --dry-run

# Apply the default 30-day retention from config
python main.py purge

# Custom retention window
python main.py purge --older-than 7

# Strict mode: also drop rows with unparseable timestamps
python main.py purge --strict
```

Run it from cron daily. Configure the default retention via `data_retention_days` in `config.yaml` or the `DATA_RETENTION_DAYS` environment variable. See `THREAT_MODEL.md` §6a for the full privacy threat model.

## Project documentation

| File                                                       | Purpose                                                                          |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------- |
| [`docs/MITRE_ATTACK_MAPPING.md`](docs/MITRE_ATTACK_MAPPING.md) | Per-analyzer ATT&CK technique coverage with explicit gaps                       |
| [`THREAT_MODEL.md`](THREAT_MODEL.md)                       | STRIDE-per-trust-boundary, adversary archetypes, residual risks, non-goals       |
| [`SECURITY.md`](SECURITY.md)                               | Vulnerability disclosure policy, supported versions, hardening guidance          |
| [`docs/EVALUATION.md`](docs/EVALUATION.md)                 | Evaluation methodology and corpus plan                                            |
| [`docs/adr/0001-cross-analyzer-context-passing.md`](docs/adr/0001-cross-analyzer-context-passing.md) | ADR for the two-pass calibration design |
| [`docs/calibration_rules.md`](docs/calibration_rules.md)   | Registry of cross-analyzer calibration rules with FP/FN motivation and tests     |
| [`ROADMAP.md`](ROADMAP.md)                                 | Planned, in-progress, and explicitly-deferred work                                |
| [`sigma_rules/README.md`](sigma_rules/README.md)           | Static Sigma rule library index and logsource adaptation guide                   |

## License

See LICENSE file.
