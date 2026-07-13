# Operational Alerting

PhishAnalyze and PayShield emit a separate, privacy-minimized operations stream
for conditions that require owner attention. This stream is intentionally not
the same as `data/alerts.jsonl`, whose private analyst records can contain
mailbox evidence.

## Events

| Event | Trigger | Delivered fields |
| --- | --- | --- |
| `analyzer_circuit_open` | An external API client transitions into open-circuit state after its failure threshold. | Analyzer class, failure count, recovery timeout. |
| `tenant_campaign_repeated` | A newly stored workspace scan shares a sender, sender domain, URL, URL domain, or attachment hash with a prior scan. A shared payment decision alone does not trigger this event. | Related count, signal type names, high-payment-risk flag, optional pseudonymous tenant reference. |
| `payment_risk_escalation` | PayShield produces `DO_NOT_PAY` or `DO_NOT_PAY_UNTIL_VERIFIED`. | Decision class, related count, optional pseudonymous tenant reference. |
| `auth_failure_threshold` | Analyst-token or SaaS-user login failures reach the throttle threshold. | Authentication namespace, attempt count, time window. |

The schema does not accept email addresses, sender values, subjects, URLs,
message content, reasoning, client IP addresses, tokens, raw user identifiers,
or raw tenant identifiers. Unknown event fields are rejected before any log or
webhook write.

## Configuration

```bash
OPERATIONAL_ALERT_LOG_PATH=data/operational_alerts.jsonl
OPERATIONAL_ALERT_WEBHOOK_URL=
OPERATIONAL_ALERT_HASH_KEY=
OPERATIONAL_ALERT_COOLDOWN_SECONDS=900
```

Use a random `OPERATIONAL_ALERT_HASH_KEY` that is different from account,
session, export-signing, and analyst-token secrets. With this key configured,
tenant events include a stable `tenant_<16 hex characters>` HMAC reference.
Without the key, the tenant reference is omitted.

`OPERATIONAL_ALERT_WEBHOOK_URL` takes priority. If it is blank, the runtime can
reuse `ALERT_WEBHOOK_URL` so existing operations channels continue to work.
Webhook URLs must be absolute HTTP or HTTPS URLs and cannot contain URL
userinfo. Never commit the real URL if the path contains a webhook credential.

Every accepted event is first attempted against the JSONL log. Webhook failure
is explicit in application logs but does not change a scan verdict, stored scan,
login failure, or circuit state. The receiver call has a 10-second total timeout,
so the event-triggering request can incur up to that bounded latency when the
receiver is unavailable. Delivery does not have a durable retry queue.

## Owner Admin Authentication

The same release adds a user-bound browser route into `/admin`:

```bash
PHISHANALYZE_ADMIN_AUTH_MODE=token_or_owner_passkey
PHISHANALYZE_ADMIN_USER_EMAILS=
```

The bridge requires a valid SaaS session, owner/admin role, at least one
registered WebAuthn credential, a fresh passkey step-up, and an exact
case-insensitive email match in `PHISHANALYZE_ADMIN_USER_EMAILS`. This
platform-admin allowlist is separate from tenant roles because public signup
creates a new owner for every workspace. An empty allowlist disables the
bridge. State-changing admin requests use the SaaS CSRF cookie and same-origin
check. Bearer tokens and the legacy analyst browser session remain accepted for
internal compatibility.

Set `token_only` for a rollback to the earlier browser boundary. Do not treat
that mode as phishing-resistant.

Owner flow:

1. Sign in at `/settings` with the owner/admin workspace account.
2. Add a passkey if none is registered.
3. Select **Verify passkey** to create the short-lived step-up.
4. Open `/admin` before `PASSKEY_STEP_UP_TTL_SECONDS` expires.

## Verification

Run the focused regression suite:

```powershell
.\.venv\Scripts\python.exe -m pytest `
  tests\unit\test_operational_alerts.py `
  tests\unit\test_base_client_operational_alerts.py `
  tests\unit\test_dashboard_session_auth.py `
  tests\unit\test_saas_api.py -q
```

Inspect only the schema, not private runtime evidence:

```bash
tail -n 1 data/operational_alerts.jsonl | python -m json.tool
```

For a webhook smoke test, point the configuration at an operator-controlled
test receiver, trigger one failed-login threshold in a non-production test
account, and confirm the received JSON contains only the fields documented
above. Do not use a real client mailbox or invoice for the smoke test.

## Backup and Retention

`scripts/backup_runtime_data.py` includes the operational alert log in its
non-secret backup set. The standard retention command includes it too:

```bash
python main.py purge --target all
```

To purge only this stream:

```bash
python main.py purge --target operational-alerts
```

The stream is designed not to contain data-subject addresses, so
`--by-address` has nothing to match in this file.
