# Awareness Simulation Feedback

PayShield and PhishAnalyze now have a compact simulation-results ingest path
for internal phishing drills. This is a measurement loop, not a learning
management system.

## Purpose

The goal is to connect detection outcomes with human-response signals:

- how many people reported the simulated phish
- how many opened or clicked
- how many submitted credentials
- whether the campaign reached the 10-result pilot threshold
- whether the dashboard risk score is moving in the right direction month to
  month

## API

Ingest JSON results:

```http
POST /api/saas/simulations/results
Content-Type: application/json

{
  "campaign_id": "may-pilot",
  "results": [
    {
      "recipient_ref": "finance-seat-1",
      "scenario": "invoice_update",
      "outcome": "reported"
    },
    {
      "recipient_ref": "finance-seat-2",
      "scenario": "bank_detail_change",
      "outcome": "submitted_credentials"
    }
  ]
}
```

Read the dashboard summary:

```http
GET /api/saas/simulations/summary?days=90
```

Summary fields include:

- `total`
- `reported`
- `clicked`
- `submitted_credentials`
- `report_rate`
- `click_rate`
- `credential_submission_rate`
- `risk_score`
- `risk_level`
- `status`

## Data Handling

- The API accepts `recipient_ref`, not full user profiles.
- If `recipient_ref` looks like an email address, the store saves only an
  organization-scoped hash.
- Raw message bodies, HTML, passwords, tokens, and secrets are dropped from
  metadata.
- Results are scoped to the authenticated organization.
- Owner/admin ingest is covered by passkey step-up enforcement when
  `PHISHANALYZE_PASSKEY_ENFORCEMENT=enforce` and a passkey exists.

## Non-Goals

- No campaign sender.
- No content library.
- No training assignments.
- No learner records beyond compact outcome rows.
- No LMS features.

For validation, run one monthly internal simulated phish set, ingest the JSON
results, and compare report rate, click rate, credential submission rate, and
closure of related incident cases.
