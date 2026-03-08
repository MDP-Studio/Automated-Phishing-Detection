# Automated Phishing Detection Pipeline

A modular, async Python pipeline that ingests emails (IMAP polling or manual upload), extracts features, runs 7 concurrent analyzers against threat intelligence APIs, scores results with weighted confidence aggregation, and provides analyst feedback loops for continuous improvement.

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

## Testing

```bash
# Run all tests
python -m pytest

# Run with verbose output
python -m pytest -v

# Run specific test file
python -m pytest tests/unit/test_attachment_handler.py

# Run with coverage
python -m pytest --cov=src --cov-report=html
```

## Known Limitations

1. **Network-dependent features**: URL detonation, API client calls, and IMAP polling require outbound internet access. All API clients degrade gracefully when offline (circuit breaker pattern returns empty results, not errors).

2. **Browser engine required for detonation**: URL detonation and screenshot capture require either Playwright or Selenium with headless Chromium. Without a browser engine, these analyzers return empty results and the pipeline continues with reduced confidence.

3. **QR code decoding dependencies**: Full QR decoding requires `pyzbar`, `opencv-python`, and system library `libzbar0`. Without these, QR-embedded URLs in images won't be extracted. Install with: `apt-get install libzbar0 && pip install pyzbar opencv-python`.

4. **NLP intent classification**: Best results require an LLM API key (Anthropic Claude or OpenAI). Falls back to a sklearn TF-IDF classifier with reduced accuracy (~70% vs ~92% with LLM).

5. **Brand impersonation detection**: Requires `imagehash` and reference brand logos in `brand_references/`. Without reference images, visual similarity scoring is skipped. The pipeline still detects brand impersonation via domain name analysis.

6. **Sandbox analysis latency**: File sandbox detonation (Hybrid Analysis, ANY.RUN, Joe Sandbox) can take 2-10 minutes per file. The pipeline timeout (default 120s) may need increasing for attachment-heavy emails.

7. **STIX 2.1 export**: Requires the `stix2` library. IOC export is optional and won't affect core pipeline operation if the library is missing.

8. **Rate limiting**: Free-tier API keys have strict rate limits. The circuit breaker and TTL cache help, but high-volume deployments need paid API tiers or self-hosted alternatives.

9. **No GPU acceleration**: NLP intent classification and image similarity run on CPU only. This is adequate for email-volume workloads but not for bulk retroactive analysis of large archives.

10. **Single-node deployment**: The current architecture runs on a single node. For multi-node deployment, you'd need to add a message queue (Redis/RabbitMQ) between ingestion and the pipeline, which the async generator interface is designed to support but doesn't implement out of the box.

## Docker Deployment

```bash
docker-compose up -d
```

Services: orchestrator (pipeline + dashboard), browser-sandbox (headless Chromium), redis (caching).

## License

See LICENSE file.
