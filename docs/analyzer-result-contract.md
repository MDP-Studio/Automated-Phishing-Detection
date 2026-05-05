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
