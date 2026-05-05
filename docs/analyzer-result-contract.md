# Analyzer Result Contract

Customer-facing scan APIs normalize each analyzer into one contract before the
frontend renders a report. This lets PhishAnalyze and PayShield show completed,
locked, skipped, failed, and unconfigured checks without guessing from raw
analyzer internals.

Each analyzer result includes:

- `analyzer_id`
- `display_name`
- `status`
- `plan_required`
- `plan_required_name`
- `cost_tier`
- `evidence`
- `risk_contribution`
- `failure_reason`
- `started_at`
- `completed_at`
- `duration_ms`
- `cached`
- `timing.duration_ms`
- `risk_score`
- `confidence`
- `details`
- `errors`

Supported statuses:

- `success`
- `failed`
- `timeout`
- `skipped`
- `feature_locked`
- `not_configured`
- `quota_exceeded`
- `cached`

Feature-locked analyzers must be returned as result rows, not omitted. Failed
or unconfigured analyzers use zero confidence so they stay visible in the UI
without voting on the final verdict.

Supported cost tiers:

- `free_local`: local or already-included deterministic checks.
- `paid_low`: low-cost external URL, domain, or reputation lookups.
- `paid_medium`: LLM-backed explanation or intent checks.
- `paid_high`: browser detonation, attachment sandboxing, or similar high-cost
  analysis.

Cache semantics:

- Cache hits use `status: "cached"` and `cached: true`.
- Cached rows keep their analyzer id, display name, evidence, plan metadata, and
  cost tier so UI, admin, and future cost reporting can count reused checks.
- Cache metadata must not expose API keys, auth tokens, credentials, or raw
  binary artifacts. Screenshot details are summarized as placeholders.

Product verdict mapping:

- PhishAnalyze maps the pipeline verdict to `CLEAN`, `SUSPICIOUS`,
  `LIKELY_PHISHING`, or `CONFIRMED_PHISHING`.
- PayShield preserves backend payment enums for compatibility, including
  `DO_NOT_PAY`, but exposes customer-facing decision support as `SAFE`,
  `VERIFY`, or `DO_NOT_PAY_UNTIL_VERIFIED`.
- The PayShield display label for the blocking case is “Do not pay until
  independently confirmed”.

Admin aggregates:

- Admin overview reads stored normalized analyzer rows from `result_json` and
  returns counts only: statuses, failures, locked checks, not configured checks,
  cached checks, cost tiers, phishing verdicts, and PayShield display decisions.
- Admin overview must not return raw email bodies, raw result JSON, mailbox
  credentials, external mailbox IDs, Stripe IDs, API keys, tokens, or secrets.
