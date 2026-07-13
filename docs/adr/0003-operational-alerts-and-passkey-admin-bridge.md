# ADR 0003: Privacy-minimized operational alerts and passkey admin bridge

- **Status:** accepted
- **Date:** 2026-07-13
- **Cycle:** operational trust gap implementation
- **Supersedes:** none
- **Superseded by:** none

## Context

The runtime already records phishing-email alerts, analyzer circuit-breaker
state, related tenant scan signals, payment decisions, and authentication
failure budgets. These controls do not currently form an operator alert path.
An analyzer circuit can open without notifying an owner, a repeated campaign is
only visible after a user opens related-scan history, and authentication
throttling is observable only in application logs.

The existing `AlertDispatcher` cannot be reused for these events because its
payload intentionally contains email addresses, subjects, recipients, URLs,
and reasoning for a private analyst workflow. Forwarding that payload to a
general operations webhook would create a new disclosure boundary.

The owner dashboard has a separate trust gap. Browser access is signed and
CSRF-protected, but its identity is still the shared `ANALYST_API_TOKEN`.
Normal SaaS owner/admin accounts already support user-bound sessions,
WebAuthn credentials, and short-lived passkey step-up records. Replacing the
token outright would break automation and internal API clients, while simply
accepting a normal user session would weaken the dashboard boundary.

## Decision

### Operational alerts

Add a separate `OperationalAlertDispatcher` with a closed event schema. Each
event type has an explicit attribute allowlist. Callers cannot attach arbitrary
strings, email content, headers, URLs, subjects, client addresses, raw user
identifiers, or raw tenant identifiers.

The first event set is:

- `analyzer_circuit_open`, emitted only on the transition into open state;
- `tenant_campaign_repeated`, emitted when a newly stored tenant scan shares
  campaign signals with prior scans;
- `payment_risk_escalation`, emitted for a `DO_NOT_PAY` or
  `DO_NOT_PAY_UNTIL_VERIFIED` result;
- `auth_failure_threshold`, emitted when an analyst or SaaS-user login failure
  budget reaches its throttle threshold.

Every accepted alert is appended to `data/operational_alerts.jsonl`. An
optional webhook receives the same payload. Delivery failures are logged with
the event type but never with payload content, and they do not change scan or
authentication decisions. A bounded in-memory cooldown suppresses repeat
delivery for the same operational condition.

Tenant correlation is optional and pseudonymous. When
`OPERATIONAL_ALERT_HASH_KEY` is configured, the dispatcher emits a truncated
HMAC reference. When it is absent, the tenant reference is omitted rather than
falling back to a raw identifier or an unkeyed hash.

### Passkey-backed admin bridge

Keep bearer-token and legacy analyst-session behavior for compatibility. Add a
second accepted browser path for `/admin` pages and their protected APIs:

1. a valid SaaS user session;
2. current account context still belongs to the session organization;
3. normalized account email is present in the fail-closed
   `PHISHANALYZE_ADMIN_USER_EMAILS` platform-admin allowlist;
4. role is `owner` or `admin`;
5. at least one WebAuthn credential is registered for that user;
6. a fresh passkey step-up record exists;
7. state-changing requests pass the SaaS double-submit CSRF and same-origin
   checks.

This bridge is controlled by
`PHISHANALYZE_ADMIN_AUTH_MODE=token_or_owner_passkey`. The secure bridge mode is
the documented default. Setting `token_only` restores the prior behavior. The
bridge never accepts an analyst-role session, an owner without a registered
passkey, an unallowlisted tenant owner, or an expired/missing step-up. An empty
platform-admin allowlist disables the bridge rather than trusting every tenant
owner created through public signup.

## Options considered

### Reuse phishing alert webhooks

Rejected. That payload is useful to a private analyst but contains personal and
attacker-controlled content. Filtering at individual call sites would create
several privacy policies that can drift.

### Send complete related-campaign evidence

Rejected. Sender addresses, URL values, attachment hashes, and subjects are
not required to tell an operator that a repeated campaign exists. The private
tenant UI remains the place to inspect evidence.

### Replace `ANALYST_API_TOKEN` immediately

Rejected. Existing health probes and internal API clients use bearer auth. A
hard cutover would turn an authentication improvement into an availability
regression and would require a coordinated credential migration.

### Accept any owner/admin SaaS session

Rejected. Password-only owner sessions are not phishing-resistant. The bridge
exists specifically to require a registered passkey and fresh assertion.

## Failure modes

### FM1: A caller attempts to place sensitive content in an alert

The dispatcher rejects unknown event types, unknown attributes, nested
objects, and overlong values. Event summaries are defined internally, not
accepted from callers. Tests attempt to pass subject, email, URL, token, and IP
fields and require rejection.

### FM2: The alert webhook is unavailable

The local JSONL write is attempted independently. Webhook exceptions are
logged without payload content and returned as an explicit failed-delivery
status. Detection and authentication behavior is preserved.

### FM3: Alert storms during a vendor outage or brute-force attempt

The circuit event fires only on the state transition. Other alerts use a
configurable in-memory cooldown keyed by event class and internal condition.
The cooldown is a noise control, not a security boundary.

### FM4: A public tenant owner attempts global admin access

Every newly created workspace has an owner, so tenant role alone cannot grant a
global administration surface. The bridge requires an independent,
operator-configured platform-admin email allowlist. An empty list fails closed.
Tests give an unallowlisted owner a valid passkey and fresh step-up and require
denial.

### FM5: The SaaS session is stolen without the passkey

The bridge checks the database for a registered credential and an unexpired
step-up on every request. Possession of the signed user cookie alone is
insufficient.

### FM6: CSRF through the new cookie-authenticated admin path

Non-safe methods authenticated through the SaaS path call the same
`verify_user_csrf` primitive used by SaaS mutations. Existing bearer auth does
not require CSRF because browsers do not attach bearer headers automatically.

### FM7: Passkey enrollment or step-up expires while browsing admin pages

The next request stops satisfying the bridge and is redirected to the admin
login for HTML or receives `401` for API access. This is an intentional
fail-closed boundary. The user can return to account settings to perform a new
step-up.

## Test strategy

- Dispatcher tests lock the allowlist, privacy rejection, local persistence,
  webhook failure semantics, HMAC tenant references, and cooldown behavior.
- Base-client tests prove an alert is emitted once when a circuit opens and
  not on every later failure.
- SaaS API tests prove high payment risk and repeated campaign events are
  emitted without sender, subject, URL, email, or raw organization values.
- Authentication tests prove threshold alerts omit principals and client IPs.
- Admin-auth tests prove owner plus registered passkey plus fresh step-up can
  enter only when platform-allowlisted, while an unallowlisted tenant owner,
  owner without step-up, analyst role, and forged CSRF cannot.
- Existing token and analyst-session tests remain unchanged as the compatibility
  proof.

## Migration

No database migration is required. Operational alerts use a new append-only
JSONL file. Existing WebAuthn credential and step-up tables are reused.

Operators should configure `OPERATIONAL_ALERT_WEBHOOK_URL` and a dedicated
`OPERATIONAL_ALERT_HASH_KEY`, enroll owner/admin passkeys, verify the webhook,
set `PHISHANALYZE_ADMIN_USER_EMAILS` to the intended platform administrators,
and then retain the default `token_or_owner_passkey` mode. Existing bearer
clients continue to work throughout the migration. Do not populate the
allowlist automatically from all workspace owners.

## Consequences

Positive:

- High-value runtime failures become actionable without forwarding mailbox
  content to an operations channel.
- The owner dashboard gains a phishing-resistant, user-bound browser path.
- Token automation remains compatible while the browser migration proceeds.
- Alert privacy is enforced centrally by code rather than operator convention.

Negative:

- Cooldown state resets on process restart, so a restart can repeat an alert.
- Webhook delivery is best effort and does not yet have a durable retry queue.
- Owners must step up in account settings before entering `/admin` through the
  new path.

## Open questions

- Whether alert retry state should move to SQLite after delivery volume proves
  a need.
- Whether the legacy analyst browser form should be disabled after all owner
  accounts have verified passkey enrollment and API clients have separate
  scoped credentials.
- Whether external incident-ticket routing belongs in this project or should
  remain an integration built from the webhook contract.
