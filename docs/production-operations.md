# Production Operations Runbook

This is the operating checklist for a 24/7 self-hosted deployment. It assumes
Docker Compose, Cloudflare Tunnel, and an analyst token in `.env`.

## Backup Runtime Data

Create a non-secret backup of analysis artifacts:

```bash
python scripts/backup_runtime_data.py --destination backups --retention-days 14
```

Backed up by default:
- `data/results.jsonl`
- `data/alerts.jsonl`
- `data/operational_alerts.jsonl`
- `data/feedback.db`
- `data/saas.db`
- `data/sender_profiles.db`

Credentials are excluded by default. If you must back up account tokens, run:

```bash
python scripts/backup_runtime_data.py --include-secrets --destination backups
```

Store secret backups encrypted and off the host. Do not commit `backups/`.

Recommended cron:

```cron
17 2 * * * cd /srv/Automated-Phishing-Detection && /usr/bin/python3 scripts/backup_runtime_data.py --destination backups --retention-days 14 >> logs/backup.log 2>&1
```

## Log Rotation

Docker JSON logs are capped in `docker-compose.production.yml`:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

Host-side script logs should rotate with logrotate:

```conf
/srv/Automated-Phishing-Detection/logs/*.log {
  daily
  rotate 14
  compress
  missingok
  notifempty
  copytruncate
}
```

## Uptime And Alerts

Health probe:

```bash
python scripts/production_health_check.py \
  --base-url https://detect.example.com \
  --token "$ANALYST_API_TOKEN" \
  --require-monitor-running \
  --alert-webhook "$ALERT_WEBHOOK_URL"
```

The script exits `0` when healthy and `2` when it should alert. It checks:
- `/api/health`
- `/api/monitor/stats`
- monitor running state when requested
- monitor error count
- last poll freshness

Recommended cron:

```cron
*/5 * * * * cd /srv/Automated-Phishing-Detection && /usr/bin/python3 scripts/production_health_check.py --base-url https://detect.example.com --token "$ANALYST_API_TOKEN" --require-monitor-running --alert-webhook "$ALERT_WEBHOOK_URL" >> logs/health.log 2>&1
```

Cloudflare or another uptime monitor should also hit `/api/health` every
minute from outside the host.

The application also emits closed-schema operational events when an analyzer
circuit opens, authentication failures reach the throttle threshold, a stored
tenant scan repeats concrete campaign infrastructure, or PayShield reaches a
high-risk payment decision. Configure delivery with:

```dotenv
OPERATIONAL_ALERT_LOG_PATH=data/operational_alerts.jsonl
OPERATIONAL_ALERT_WEBHOOK_URL=https://alerts.example.net/hooks/security
OPERATIONAL_ALERT_HASH_KEY=<independent-random-secret>
OPERATIONAL_ALERT_COOLDOWN_SECONDS=900
```

When `OPERATIONAL_ALERT_WEBHOOK_URL` is empty, the dispatcher falls back to
`ALERT_WEBHOOK_URL`. Every accepted event is written locally before webhook
delivery. A webhook failure is logged without the payload or destination and
does not interrupt scanning or authentication. There is no durable retry queue,
but an unavailable receiver can add up to the configured 10-second total timeout
to the event-triggering request. Monitor the local JSONL file and webhook
receiver separately. Event schemas
reject mailbox content, addresses, subjects, URLs, client IPs, raw user IDs,
and raw tenant IDs. See `docs/operational-alerting.md` for the field contract.

## SaaS Mailbox Worker

The `phishing-saas-mailbox-worker` container is a separate customer polling
process. It starts in healthy standby when this flag is false:

```dotenv
SAAS_CONTINUOUS_MONITORING_ENABLED=false
```

Before setting it to `true` in production:

1. Back up `data/saas.db` and verify the archive manifest includes it.
2. Deploy the worker and confirm both app and worker health checks are green.
3. Confirm every existing `mail_accounts.automation_enabled` value is `0`.
4. Set the flag to `true`, redeploy, and verify the aggregate heartbeat only.
5. Let each Pro or Business owner/admin opt in individual mailboxes in the app.

Useful checks that do not expose tenant or mailbox identifiers:

```bash
docker inspect --format '{{.State.Health.Status}}' phishing-saas-mailbox-worker
docker exec phishing-saas-mailbox-worker python scripts/saas_mailbox_worker.py --healthcheck
docker exec phishing-saas-mailbox-worker python scripts/saas_mailbox_worker.py --once
```

The worker uses SQLite WAL, serialized claims, expiring leases, current tenant
and entitlement checks, duplicate-message receipts, and failure backoff. This is
a single-host operating model. Do not run multiple database hosts or claim high
availability until the PostgreSQL migration is complete. Completed mailbox
analyses reserve and consume the same monthly scan budget shown to the workspace.

## Runtime Retention

Default retention is 30 days through `DATA_RETENTION_DAYS`. Run:

```bash
python main.py purge --target all
```

For a data subject erasure:

```bash
python main.py purge --target all --by-address person@example.com
```

Run daily in production. `--target all` includes JSONL results, phishing alerts,
privacy-minimized operational alerts, analyst feedback, SaaS user scan rows in
`data/saas.db`, and sender profiles:

```cron
37 2 * * * cd /srv/Automated-Phishing-Detection && /usr/bin/python3 main.py purge --target all >> logs/retention.log 2>&1
```

## CTI Transport Checks

STIX/Sigma file export remains the default sharing path. If a TAXII 2.1
collection is configured, push a generated STIX bundle with:

```bash
python scripts/taxii_push.py --stix data/exports/example_iocs.json
```

The command writes a safe status file to `data/taxii_push_status.json`. The
private admin overview shows only status, target URL without query strings,
object count, HTTP status, and timing. It does not show TAXII credentials or
STIX object contents.

When TAXII points to a private OpenCTI container, set `CTI_DOCKER_NETWORK` so
`scripts/docker_deploy.sh` reconnects `phishing-orchestrator` to that internal
network after each redeploy.

Validate Sigma converter compatibility locally before relying on a rule export:

```bash
python scripts/sigma_convert_check.py --backend splunk
```

CI runs the same check with `--require-converter` after installing pySigma and
the Splunk backend.

## PayShield Corpus Assurance

Before tuning PayShield thresholds or training payment-specific ML, generate a
redacted real-world corpus report:

```bash
python scripts/payment_dataset.py assurance-report --dataset data/payment_scam_dataset
```

The default target is 100 PII-free real/redacted/internal payment samples, with
at least 20 examples for each payment decision. The admin overview reads only
aggregate counts from the JSON report.

## Auth And Session Checks

Production must set a high-entropy analyst token:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

API clients should use `Authorization: Bearer $ANALYST_API_TOKEN`. The signed
analyst session at `/admin/login` remains a compatibility path and is not
phishing-resistant. For user-bound browser administration, configure:

```dotenv
PHISHANALYZE_ADMIN_AUTH_MODE=token_or_owner_passkey
PHISHANALYZE_ADMIN_USER_EMAILS=platform-owner@example.com
```

The allowlist must contain only platform administrators, not every workspace
owner. An eligible user signs in at `/settings`, registers a passkey, completes
a fresh step-up, and then opens `/admin`. The bridge also requires the account
to have an owner/admin organization role and uses the SaaS CSRF cookie for
mutations. An empty allowlist disables the bridge without disabling bearer or
analyst-session compatibility.

Operational checks:
- Rotate `ANALYST_API_TOKEN` if it has been shared in chat, logs, or tickets.
- Review `PHISHANALYZE_ADMIN_USER_EMAILS` as a platform privilege list. Removing
  an address blocks new bridge requests immediately.
- Keep Cloudflare Access or Tailscale in front of the dashboard for demos.
- If `PUBLIC_DEMO_MODE=true`, verify only `/demo` is public. It must not expose
  live analysis, mailbox data, feedback learning, paid API usage, or account
  management.
- Do not expose the app publicly by host port. The production compose file uses
  a loopback-only host port, `127.0.0.1:8010:8000`, for local health probes.
  The app still listens on container port `8000`; host port `8000` is kept free
  for other local infrastructure such as Coolify.

## Docker Self-Healing

Docker restart policies do not restart a container that is still running but
marked `unhealthy`. Run the host-level self-heal script from cron so unhealthy
containers are restarted without mounting the Docker socket into a privileged
helper container:

```cron
* * * * * cd /srv/Automated-Phishing-Detection && /usr/bin/bash scripts/docker_self_heal.sh >> logs/docker-self-heal.log 2>&1
```

For code updates, use:

```bash
bash scripts/docker_deploy.sh
```

That script fast-forwards git, rebuilds the production stack, removes orphaned
old containers, creates the shared `mdp-tunnel` network when needed, and waits
for both `phishing-orchestrator` and `phishing-saas-mailbox-worker` to become
healthy before declaring success.

## Load And Error Probe

Run a short probe against a deployment with the mailbox monitor enabled:

```bash
python scripts/monitor_load_test.py \
  --base-url https://detect.example.com \
  --token "$ANALYST_API_TOKEN" \
  --duration-seconds 60 \
  --concurrency 8 \
  --require-monitor-running
```

This repeatedly checks health, monitor stats, and recent compact logs. It does
not fetch mailbox contents itself, so it is safe to run against production.
