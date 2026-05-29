# PhishAnalyze / PayShield

PhishAnalyze and PayShield share one FastAPI detection platform with two
product faces:

- **PhishAnalyze** is the general suspicious-email scanner for phishing,
  malicious URLs, sender/domain risk, attachments, social engineering, and scan
  history.
- **PayShield** is the payment-scam workflow for invoice fraud, supplier
  impersonation, bank-detail changes, and payment-risk decision support.

The platform is designed to show a clear verdict, the evidence behind it, which
checks were locked or skipped, and what the user should do next. It is decision
support, not a payment authorization system.

MDP Studio project pages:

- [PhishAnalyze suspicious email analysis](https://mdpstudio.com.au/projects/phishing-email-analysis/)
- [PayShield invoice fraud triage](https://mdpstudio.com.au/projects/invoice-fraud-triage/)

## Current Product Shape

| Area | Routes | Purpose |
| --- | --- | --- |
| PhishAnalyze | `/product`, `/analyze`, `/dashboard`, `/monitor`, `/settings`, `/trust` | Introduce the scanner, upload suspicious `.eml` files, review private scan history, connect monitored mailboxes, manage simple settings, and read the PhishAnalyze trust page. |
| PayShield | `/product`, `/app`, `/trust` | Analyze invoice and payment-related emails, see payment-risk evidence, and use PayShield-specific trust copy. |
| Search readiness | `/robots.txt`, `/sitemap.xml` | Serve host-aware crawl instructions and sitemaps for `phishanalyze.mdpstudio.com.au` and `payshield.mdpstudio.com.au`. |
| Public growth guides | `/guides/*` | Host-aware phishing and payment-scam guide pages that link into the scanner or PayShield app. |
| Admin | `/admin/*` | Private owner console for aggregate system health, API status, billing status, and operational checks. |

PhishAnalyze verdicts:

```text
CLEAN | SUSPICIOUS | LIKELY_PHISHING | CONFIRMED_PHISHING
```

PayShield customer-facing decisions:

```text
NOT_PAYMENT_SPECIFIC | SAFE | VERIFY | DO_NOT_PAY_UNTIL_VERIFIED
```

The backend and older dataset tools may still contain the enum `DO_NOT_PAY`.
Customer-facing PayShield copy should say "Do not pay until independently
confirmed" or `DO_NOT_PAY_UNTIL_VERIFIED`.

## What Works Now

- `.eml` upload through the SaaS app.
- JSON channel scans for SMS, chat, and voice transcripts through
  `/api/saas/analyze/channel`, normalized into the same analyzer-compatible
  message model as email.
- Upload help for saving emails from Gmail, Outlook desktop, Outlook web, Apple
  Mail, and Zoho Mail, plus a sample email button for first-time users.
- Email parsing for sender, reply-to, subject, body, URLs, attachments, and
  headers.
- Local analyzers that work without paid APIs.
- Remote access lure detection for fake document, invoice, HR, tax, crypto,
  Teams/Zoom, Adobe, and SSA-style messages that try to push installer or
  support-tool downloads.
- AI instruction safety detection for hidden, encoded, or direct email content
  that attempts to control AI agents, tools, prompts, or secret handling.
- Optional local prompt-injection ML model trained as a shared hostile-input
  lane using LLMail attacks plus clean Enron/SpamAssassin mail.
- Normalized analyzer result contract with `success`, `failed`, `timeout`,
  `skipped`, `feature_locked`, `not_configured`, `quota_exceeded`, and `cached`
  statuses.
- Product-specific verdict mapping for PhishAnalyze and PayShield.
- Result UI with verdicts, score, evidence, locked checks, failures, skipped
  checks, and next steps.
- Plain-language result summaries that answer what was found, why, and what to
  do next before showing the detailed check table.
- Print-friendly and downloadable HTML reports for sharing scan outcomes.
- First-run checklist for upload, result review, scan deletion, upgrade, and
  later mailbox connection.
- Signed user accounts, workspaces, CSRF-protected sessions, and tenant-scoped
  scan history.
- Delete controls for stored scan results.
- Lightweight incident cases tied to stored scan IDs, with status transitions,
  assigned owner, immutable evidence events, manual escalation state, and
  audit-only remediation plans.
- Plan-gated analyzers, quota checks, and locked-check reporting before paid
  API clients load.
- Stripe Checkout, Customer Portal, yearly/monthly pricing, billing-cadence
  display, renewal-date display, and webhook sync.
- Encrypted mailbox credential storage and gated on-demand mailbox scan now.
- PayShield mailbox scans run a cheap payment-relevance gate first. Clear
  non-payment emails are skipped without being stored as deep scan results;
  invoice, payment request, bank-detail change, receipt, billing, and uncertain
  emails continue to the full pipeline.
- A PhishAnalyze settings page with workspace summary, billing entry points,
  mailbox status, privacy links, team member visibility, and platform-managed
  API coverage guidance.
- Passkey/WebAuthn support for owner/admin step-up. The default `monitor` mode
  exposes policy state and registration without blocking users; `enforce`
  requires a fresh passkey step-up for team, mailbox, billing, passkey,
  scan-deletion, incident-case, remediation-planning, and simulation-ingest
  mutations when a passkey exists.
- Signed STIX/Sigma file export manifests with Ed25519 signatures and a
  validator for hashes, signatures, STIX parsing, and Sigma structure.
- Optional TAXII 2.1 STIX push for operator CTI sharing, with safe status
  reporting in the private admin overview.
- CI-backed Sigma conversion validation through pySigma and the Splunk backend
  so exported rules are checked against a real downstream converter.
- Signed CTI compatibility report artifacts that validate STIX/Sigma exports,
  OpenCTI TAXII Add Objects envelopes, and Sigma backend conversion per release
  or scheduled CI run.
- CTI freshness validation that pins ATT&CK mapping to v19.1 and checks Sigma
  technique tags against the documented coverage matrix.
- PayShield payment-corpus assurance reporting for redacted real-world sample
  breadth, decision balance, and channel drift coverage.
- `/mailbox-guide` with provider-specific setup steps and direct settings links
  for Gmail, Outlook, Yahoo, iCloud, Zoho, Fastmail, Proton, AOL, and generic
  IMAP.
- Optional LLM evidence summaries behind paid gating. The LLM explains
  structured evidence only; it does not decide the verdict.
- Awareness simulation result ingest for small internal phish pilots, plus a
  dashboard risk card for sample size, report rate, click rate, and risk score.
- Privacy-preserving admin aggregate status.
- Cloudflare Tunnel and Docker deployment.
- Minimal Chrome/Edge extension starter that only opens the web app routes.

## What Is Not Claimed Yet

- OAuth mailbox connection is not the public default yet. Current mailbox
  connection uses app-password/IMAP style credentials, verifies IMAP access
  before saving, and stores credentials encrypted.
- Customer bring-your-own API keys are not part of normal onboarding. Public
  users see a simple message that external reputation checks are included on
  paid plans. The settings page keeps advanced API-key wording separate for
  private deployments or a future encrypted customer-key flow.
- External sandbox providers require provider keys and strict timeout/cost
  controls. The product should remain useful without them.
- LLMs are explanation helpers, not final verdict authorities.
- PayShield does not approve payments. It gives risk evidence and verification
  guidance.
- Legacy analyst-token `/admin` access is not phishing-resistant. Keep it
  internal until it is migrated to user-bound passkeys.
- Incident cases are a lightweight response tracker, not a full SOAR. They do
  not send notifications, quarantine mail, or open external tickets.
- Simulation results are a feedback loop for awareness metrics, not an LMS.
  Campaign delivery, training content, and learner management stay out of
  scope.

## Analyzer Pipeline

The runtime flow is intentionally simple:

```text
Ingestion -> Extraction -> Analyzer execution -> Product verdict mapping -> UI/API report
```

Current analyzers include:

- `header_analysis`
- `url_reputation`
- `domain_intelligence`
- `url_detonation`
- `attachment_analysis`
- `nlp_intent`
- `rmm_lure`
- `agent_prompt_injection`
- `sender_profiling`
- `payment_relevance`
- `payment_fraud`
- `brand_impersonation`

Each analyzer result is normalized before it reaches the API, UI, admin
overview, or future cost/cache reporting.

## Quick Start

```powershell
cd "C:\Users\meidi\Documents\personal project\Automated Phishing Detection"
.\.venv\Scripts\python.exe main.py serve --host 127.0.0.1 --port 8766
```

Then open:

```text
http://127.0.0.1:8766/product
http://127.0.0.1:8766/analyze
http://127.0.0.1:8766/settings
http://127.0.0.1:8766/app
```

Local `/product` shows the PhishAnalyze product intro by default. On the
configured PayShield hostname, `/product` shows the PayShield product page.

Run the compact PayShield sample demo:

```powershell
.\.venv\Scripts\python.exe scripts\agent_payment_demo.py
```

## Production Configuration

Use `.env.production.example` as the template and keep real values only in the
host `.env` or environment variables. Do not commit production secrets.

Stripe is the source of truth for paid subscription changes. The app mirrors
the active plan, monthly/yearly cadence, and renewal date from Checkout and
subscription webhooks. Configure Stripe Customer Portal so annual-to-monthly
changes are scheduled for the next renewal if you want annual customers to keep
their prepaid access until the current period ends.

Core required settings for a public SaaS deployment:

```bash
ANALYST_API_TOKEN=
SAAS_SESSION_SECRET=
SAAS_DB_PATH=data/saas.db
SAAS_PUBLIC_SIGNUP_ENABLED=true
ACCOUNTS_ENCRYPTION_KEY=
PHISHANALYZE_PASSKEY_ENFORCEMENT=monitor
PROMPT_INJECTION_MODEL_PATH=models/prompt_injection_classifier/prompt_injection_model.joblib
PROMPT_INJECTION_ML_THRESHOLD=0.90
PAYMENT_RELEVANCE_MODEL_PATH=models/payment_classifier/payment_relevance_model.joblib
PHISHANALYZE_PUBLIC_URL=https://phishanalyze.mdpstudio.com.au
PAYSHIELD_PUBLIC_URL=https://payshield.mdpstudio.com.au
```

Recommended external checks:

| Service | Environment variable | Used for |
| --- | --- | --- |
| Google Safe Browsing | `GOOGLE_SAFE_BROWSING_API_KEY` | URL threat matching |
| urlscan.io | `URLSCAN_API_KEY` | URL scan lookup/submission |
| VirusTotal | `VIRUSTOTAL_API_KEY` | URL/domain/file reputation |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP reputation |
| DeepSeek | `DEEPSEEK_API_KEY` | Cost-first LLM explanation and intent analysis |
| Hybrid Analysis | `HYBRID_ANALYSIS_API_KEY` | Optional attachment sandboxing |

Optional LLM evidence summaries:

```bash
LLM_PROVIDER=deepseek
LLM_EVIDENCE_SUMMARY_ENABLED=true
DEEPSEEK_API_KEY=
```

Optional CTI sharing:

```bash
TAXII_PUSH_ENABLED=false
TAXII_BASE_URL=
TAXII_COLLECTION_ID=
TAXII_OBJECTS_URL=
TAXII_BEARER_TOKEN=
TAXII_STATUS_PATH=data/taxii_push_status.json
SIGMA_CONVERSION_STATUS_PATH=data/sigma_conversion_status.json
CTI_DOCKER_NETWORK=
CTI_DOCKER_NETWORK_REQUIRED=0
```

Password reset prefers Zoho Mail API direct send:

```bash
ZOHO_CLIENT_ID=
ZOHO_CLIENT_SECRET=
ZOHO_REFRESH_TOKEN=
ZOHO_ACCOUNTS_BASE=https://accounts.zoho.com.au
ZOHO_ACCOUNT_ID=
ZOHO_FROM=
ZOHO_API_BASE=https://mail.zoho.com.au
ZOHO_ENABLE_DIRECT_SEND=true
```

If Zoho token refresh returns `general_error`, regenerate the refresh token in
the same Zoho data center as `ZOHO_ACCOUNTS_BASE` with
`ZohoMail.messages.CREATE` or `ZohoMail.messages.ALL`.

Stripe Billing:

```bash
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=
STRIPE_PRICE_STARTER=
STRIPE_PRICE_STARTER_YEARLY=
STRIPE_PRICE_PRO=
STRIPE_PRICE_PRO_YEARLY=
STRIPE_PRICE_BUSINESS=
STRIPE_PRICE_BUSINESS_YEARLY=
STRIPE_ADAPTIVE_PRICING_ENABLED=true
```

Passkey step-up:

```bash
PHISHANALYZE_PASSKEY_ENFORCEMENT=monitor
PASSKEY_RP_NAME=PhishAnalyze
PASSKEY_RP_ID=phishanalyze.mdpstudio.com.au
PASSKEY_ORIGIN=https://phishanalyze.mdpstudio.com.au
PASSKEY_STEP_UP_TTL_SECONDS=600
```

Use `enforce` only after owner/admin users have enrolled at least one passkey.
When enforced and a passkey exists, team management, mailbox connection,
mailbox scan-now, mailbox deletion, billing checkout or portal access, passkey
registration or deletion, scan deletion, incident case mutation, and simulation
result ingest require a fresh WebAuthn assertion for owner/admin users.

Signed STIX/Sigma file exports:

```bash
EXPORT_SIGNING_PRIVATE_KEY_B64=
EXPORT_SIGNING_PUBLIC_KEY_B64=
EXPORT_SIGNING_KEY_ID=production-export-key
```

`python main.py --analyze sample.eml --format stix` and `--format sigma` still
print unsigned inspection output to stdout. `--format all` writes STIX/Sigma
files plus a signed export manifest and requires the signing key. Validate a
bundle with:

```powershell
.\.venv\Scripts\python.exe scripts\validate_exports.py --manifest sample_export_manifest.json
```

## Plans And Cost Gates

Plan behavior is enforced before paid analyzers or mailbox features run.

- Free: 5 manual scans/month, local checks only.
- Starter: URL/domain intelligence style checks.
- Pro: LLM explanation, monitoring, attachment/browser-backed checks.
- Business: higher limits, team/audit-oriented usage, and broader operating
  room.

Locked checks are still shown in results as `feature_locked`, so users can see
what would be unlocked without burning API quota.

## Testing

Current collected test suite:

```text
1343 tests across 78 test modules
```

Run all tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Fast documentation/count check:

```powershell
.\.venv\Scripts\python.exe -m pytest --collect-only -q
```

The tests cover analyzer normalization, product verdict mapping, SaaS sessions,
CSRF, tenant isolation, scan deletion, mailbox credential encryption, mailbox
scan-now behavior, Stripe Checkout/Portal/webhooks, admin aggregate redaction,
TAXII status redaction, Sigma converter checks, URL detonation SSRF
protections, HTML/report escaping, LLM provider wiring, and payment-fraud,
phishing, and prompt-injection dataset tooling.

## Evaluation

Evaluation numbers are development evidence, not production guarantees.

Current committed 22-sample project corpus, live API run:

- Permissive scoring: 0.90 recall, 1.00 precision, 0.95 F1.
- Strict scoring: 0.00 recall because many phishing detections currently sit in
  the `SUSPICIOUS` score band rather than `LIKELY_PHISHING`.

Remote public-corpus smoke run on commit `c459237`:

- 15 samples from Nazario phishing plus Enron and SpamAssassin ham.
- Permissive precision 0.714, recall 1.000, F1 0.833, accuracy 0.867.
- Strict F1 0.000.

Per-sample committed eval data lives in [`eval_runs/`](eval_runs/). Larger
generated public corpora and trained model artifacts stay ignored under `data/`
and `models/`.

Generate a compact scorecard from the latest eval summaries with:

```powershell
.\.venv\Scripts\python.exe scripts\detection_scorecard.py --output-dir reports\detection-scorecards
```

Scorecards include corpus mix, permissive/strict metrics, and deltas from the
previous run. They intentionally omit raw message bodies, raw headers, and
sample text.

Mixed-channel evaluation uses a private JSON or JSONL manifest with `channel`,
`label`, and either `path`, `text`, `body`, or `transcript`. The summary JSON
includes per-channel false positives, false negatives, and errors:

```powershell
.\.venv\Scripts\python.exe scripts\run_eval.py --mixed-manifest data\mixed_channel_corpus\manifest.jsonl
```

PayShield assurance uses ignored, redacted payment samples:

```powershell
.\.venv\Scripts\python.exe scripts\payment_dataset.py assurance-report --dataset data\payment_scam_dataset
.\.venv\Scripts\python.exe scripts\payment_dataset.py prelabel-relevance --dataset data\payment_scam_dataset
.\.venv\Scripts\python.exe scripts\payment_train.py --dataset data\payment_scam_dataset --target payment_relevance
.\.venv\Scripts\python.exe scripts\payment_relevance_eval.py --dataset data\payment_scam_dataset
```

See [`docs/payment-detection-assurance.md`](docs/payment-detection-assurance.md)
for the 100-sample redacted real-world target and channel drift rules.
See [`docs/cti-transport.md`](docs/cti-transport.md) for TAXII push and Sigma
converter validation.

## Deployment

Local Docker:

```bash
docker-compose up -d
```

Production deploy command used for the remote host:

```bash
ssh meidie@100.110.79.52 "cd /home/meidie/.openclaw/workspace/Automated-Phishing-Detection && git pull --ff-only && bash scripts/docker_deploy.sh"
```

The production compose setup keeps the orchestrator bound to
`127.0.0.1:8010` on the host while the container still listens on `8000`, uses
Cloudflare Tunnel for public traffic, and runs URL detonation in a separate
Playwright browser-sandbox container.

## Security And Privacy Boundaries

Preserve these before treating any feature as public-trust ready:

- Tenant isolation and scan ownership checks.
- CSRF on logged-in mutations.
- File size limits and no unsafe raw `.eml` rendering.
- HTML escaping in report views.
- No API keys or app passwords returned to the browser.
- Encrypted mailbox credentials with a stable `ACCOUNTS_ENCRYPTION_KEY`.
- Stripe webhook signature verification.
- Admin route protection.
- Privacy-preserving admin aggregates only, not customer email contents.
- Delete controls for scan history.

## Browser Extension Starter

The `browser_extension/` folder contains a minimal Manifest V3 companion
extension for Chrome/Edge. It does not scrape pages, read mailbox contents,
store credentials, or include API keys. It only opens:

- `https://phishanalyze.mdpstudio.com.au/analyze`
- `https://payshield.mdpstudio.com.au/app`

## Project Documentation

| File | Purpose |
| --- | --- |
| [`docs/analyzer-result-contract.md`](docs/analyzer-result-contract.md) | Standard analyzer contract, statuses, cost tiers, and cache semantics. |
| [`docs/product-verdict-mapping.md`](docs/product-verdict-mapping.md) | Product-specific verdict and PayShield wording rules. |
| [`docs/platform-expansion-features.md`](docs/platform-expansion-features.md) | LLM summaries, mailbox scan now, roles, extension, and sandbox wiring. |
| [`docs/saas-architecture.md`](docs/saas-architecture.md) | SaaS users, workspaces, plan gates, and Stripe architecture. |
| [`docs/mailbox-connection-guide.md`](docs/mailbox-connection-guide.md) | Provider mailbox setup guide, direct settings links, and OAuth/admin caveats. |
| [`docs/payment-fraud-firewall.md`](docs/payment-fraud-firewall.md) | PayShield payment-scam workflow and SME positioning. |
| [`docs/incident-response-workflow.md`](docs/incident-response-workflow.md) | Lightweight scan-linked cases, status transitions, owner assignment, escalation, and evidence chains. |
| [`docs/awareness-simulation-feedback.md`](docs/awareness-simulation-feedback.md) | Simulation result ingest, awareness risk score, and LMS boundaries. |
| [`docs/agent-prompt-injection.md`](docs/agent-prompt-injection.md) | AI-agent prompt-injection boundary and email safety controls. |
| [`docs/ml-datasets.md`](docs/ml-datasets.md) | ML and evaluation dataset plan for phishing, payment scams, and agent-safety tests. |
| [`docs/product-ml-training.md`](docs/product-ml-training.md) | Separate PhishAnalyze, PayShield, and prompt-injection training/eval lanes. |
| [`docs/ml-training-runs.md`](docs/ml-training-runs.md) | Remote raw-corpus, prepared-corpus, and model-artifact run log. |
| [`docs/agent-payment-tool.md`](docs/agent-payment-tool.md) | CLI/MCP payment email analysis tool contract. |
| [`docs/gemini-mcp-demo-kit.md`](docs/gemini-mcp-demo-kit.md) | Gemini MCP recording package. |
| [`docs/MITRE_ATTACK_MAPPING.md`](docs/MITRE_ATTACK_MAPPING.md) | ATT&CK mapping with explicit gaps. |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | STRIDE threat model and residual risks. |
| [`SECURITY.md`](SECURITY.md) | Vulnerability disclosure and hardening guidance. |
| [`docs/production-operations.md`](docs/production-operations.md) | Backup, health, retention, alerting, and load-test runbook. |
| [`docs/EVALUATION.md`](docs/EVALUATION.md) | Evaluation methodology and corpus plan. |
| [`HISTORY.md`](HISTORY.md) | Engineering audit-cycle history. |
| [`ROADMAP.md`](ROADMAP.md) | Planned and deferred work. |

## Project Arc

This began as a detection-engineering portfolio project and grew into a
two-product SaaS prototype. The engineering history is intentionally preserved:
earlier audits found serious issues, the fixes are documented, and the eval
story includes the periods where the numbers were weak. Read
[`HISTORY.md`](HISTORY.md) and [`docs/WRITEUP.md`](docs/WRITEUP.md) for that
portfolio narrative.

## License

No license file is currently committed. Treat the code as private unless a
license is added.
