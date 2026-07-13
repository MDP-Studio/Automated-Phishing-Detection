# Security Policy

## Reporting a vulnerability

If you've found a security issue in this project, please **do not** open a public GitHub issue. Instead, report it privately so the fix can ship before the details are public.

**How to report:**
- Open a [private security advisory](https://github.com/Meidie/Automated-Phishing-Detection/security/advisories/new) on GitHub, or
- Email the maintainer with the subject line `SECURITY: phishing-detection` and a clear description.

**What to include:**
- Affected component (file path, analyzer name, or endpoint)
- Reproduction steps or a proof-of-concept payload (a sample `.eml` is ideal)
- Impact you observed and impact you believe is reachable
- Whether you've tested against `main` or a specific commit

**Response expectations:**
- Acknowledgement: within a few days
- Triage and severity assessment: shortly after acknowledgement
- Fix or mitigation: depends on severity; critical issues are prioritized
- Public disclosure: coordinated with the reporter once a fix is available

I'm a solo maintainer, not a vendor SOC. I'll do my best on response times but cannot commit to enterprise SLAs.

## Supported versions

This is a portfolio / research project. Only the `main` branch is supported. There are no LTS branches. Fixes are committed to `main`; users running older commits should rebase.

## Scope

### In scope

Vulnerabilities in any of these are in scope and welcome:

- **Parsers** — EML, MIME, attachment handlers, QR decoder, header parser. Crafted inputs that cause RCE, infinite loops, or memory exhaustion.
- **Analyzer pipeline** — race conditions, async deadlocks, SSRF via URL detonation, request smuggling against external APIs.
- **Scoring & override rules** — verdict bypasses where a malicious email reliably scores CLEAN, or where a benign email reliably scores CONFIRMED_PHISHING due to a logic flaw (not just a tunable false-positive).
- **Browser sandbox** — container escape, host filesystem access, host network egress that should be blocked.
- **Feedback API** — auth bypass, IDOR, SQL injection, label-poisoning attacks beyond the documented "no-auth-by-default" residual risk.
- **Secrets handling** — credentials leaking into logs, reports, STIX exports, dashboard responses, or git history.
- **Passkey step-up** - privileged owner/admin SaaS mutations should run with
  `PHISHANALYZE_PASSKEY_ENFORCEMENT=monitor` until passkeys are enrolled, then
  move to `enforce` for team, mailbox, billing, passkey registration/deletion,
  scan deletion, incident case mutation/remediation planning, and simulation ingest actions. The
  `/api/saas/security/policy` payload exposes the covered action matrix.
  A fresh passkey step-up can also authenticate the private admin browser
  surface only when the owner/admin account is independently listed in
  `PHISHANALYZE_ADMIN_USER_EMAILS`. Tenant role alone is insufficient.
  Password-only sessions and legacy analyst tokens are not phishing-resistant.
- **Operational alert privacy** - alert payloads for analyzer outages,
  repeated campaigns, payment-risk escalation, and login throttling must reject
  mailbox content, addresses, subjects, URLs, client IPs, raw users, and raw
  tenant identifiers. Schema bypasses or webhook disclosure are in scope.
- **Export integrity** — shareable STIX/Sigma file exports require an Ed25519
  signing key and a signed manifest. Validate manifests before sharing threat
  intel externally.
- **Dependency-chain issues** — vulnerable pinned dependencies in `requirements.txt`.

### Out of scope

These are intentionally not security issues:

- **False positives or false negatives in detection.** The pipeline is probabilistic. Tuning is not a security report. (Exception: a *reliable, weaponizable* bypass of the override rules — that *is* in scope.)
- **Vendor-side issues.** If VirusTotal or urlscan returns a wrong answer, that's not this project's bug.
- **Sandbox-evading malware.** Documented limitation (`THREAT_MODEL.md` §6 R8). Bring a novel evasion against the parser or container, not against an upstream sandbox.
- **Self-DoS via giant attachments.** The handler has size limits; reports must demonstrate bypass of those limits.
- **Anything requiring physical access** to the host running the pipeline.
- **Social engineering of the maintainer.**

## Hardening guidance for operators

If you're running this in any non-laptop context, do at minimum:

1. **The server defaults to binding `127.0.0.1`** (loopback only). To expose it elsewhere, you must set `ANALYST_API_TOKEN` to a high-entropy value AND pass `--host <addr>` explicitly. The server refuses to start with a non-loopback host if the token is unset. For internet exposure, put it behind a reverse proxy with TLS termination.
2. **Prefer the owner passkey path for browser admin access.** Sign in at
   `/settings`, register and verify a passkey, then open `/admin` while the
   step-up is fresh. `/admin/login` and `Authorization: Bearer
   <ANALYST_API_TOKEN>` remain compatibility paths for internal clients.
3. **Treat `PUBLIC_DEMO_MODE=true` as sample-only.** It opens `/demo`, not the real dashboard, live upload analysis, mailbox monitoring, feedback learning, paid API-backed checks, or account management. Keep `ANALYST_API_TOKEN` configured.
4. **Treat `/app` public signup as a privacy switch.** Keep `SAAS_PUBLIC_SIGNUP_ENABLED=false` until you are ready to accept visitor email uploads, set a high-entropy `SAAS_SESSION_SECRET`, and have retention/support/abuse handling in place. User signup, login, and password-reset routes require same-origin `Origin` or `Referer` headers before setting cookies.
5. **Keep the token path internal.** Use
   `PHISHANALYZE_ADMIN_AUTH_MODE=token_or_owner_passkey` for the user-bound
   browser bridge and explicitly list platform administrators in
   `PHISHANALYZE_ADMIN_USER_EMAILS`. An empty allowlist disables the bridge.
   Never add every workspace owner. The legacy analyst token is useful for
   diagnostics and API clients, but it is shared and not phishing-resistant.
6. **Register Stripe webhooks only over HTTPS and keep `STRIPE_WEBHOOK_SECRET` secret.** `/api/stripe/webhook` verifies Stripe signatures before changing subscription state. Do not disable signature checks.
7. **Run the `browser-sandbox` container on its own Docker network.** Do not give it host networking. The default `docker-compose.yml` already separates it; verify before deploying.
8. **Treat `.env` as secret material.** Don't commit it. Don't bake it into images. Mount it at runtime.
9. **Back up runtime data and purge it on a schedule.** Results, phishing alerts, feedback labels, sender profiles, and SaaS scan results can contain regulated personal data. Operational alerts use a separate closed schema and are retained by the same command. Use `python scripts/backup_runtime_data.py` for non-secret backups and `python main.py purge --target all --dry-run` before deleting rows.
10. **Monitor uptime and mailbox freshness.** Run `python scripts/production_health_check.py --require-monitor-running` from cron or an external monitor and send failures to a webhook.
11. **Configure operational alert delivery.** Set
    `OPERATIONAL_ALERT_WEBHOOK_URL` and a separate
    `OPERATIONAL_ALERT_HASH_KEY`. Circuit-open transitions, repeated campaigns,
    high payment-risk decisions, and login throttle thresholds then reach the
    operations channel without mailbox evidence. Review
    `data/operational_alerts.jsonl` if the webhook is unavailable.
12. **Install from the hash-pinned lock and keep the advisory gate green.** Use
    `pip install --require-hashes -r requirements.lock` in production and run
    `python -m pip_audit -r requirements.lock --disable-pip` after every lock
    refresh. The July 2026 lock has no known vulnerabilities.
13. **Pin the brand reference set.** Treat `brand_references/` as detection content under change control. Anyone who can write to that directory can blind the visual similarity analyzer.

## Coordinated disclosure

I'm happy to coordinate disclosure timelines with reporters, credit researchers in release notes (or keep them anonymous, your call), and work with downstream consumers if a vulnerability affects their TI workflows.

If you've made a good-faith effort to report a vulnerability privately and haven't gotten a response, you're welcome to escalate by opening a GitHub issue that says only "I sent a security report, please check your inbox." Do not include details in the issue.

## Acknowledgements

Thanks to anyone who's reported issues responsibly. (None to acknowledge yet — be the first.)
