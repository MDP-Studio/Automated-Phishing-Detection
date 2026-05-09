# Platform Expansion Feature Notes

This note covers the safe expansion work added after the analyzer contract and
product verdict cleanup. These features stay behind the existing tenant,
session, CSRF, plan, and quota controls.

## LLM Evidence Summaries

LLM summaries are optional and run after the deterministic pipeline has already
produced analyzer evidence and product verdicts.

- Enable with `LLM_EVIDENCE_SUMMARY_ENABLED=true`.
- Gate with the existing `llm_intent` entitlement.
- Default provider is DeepSeek via `LLM_PROVIDER=deepseek` and
  `DEEPSEEK_API_KEY`.
- The prompt receives normalized analyzer status, evidence text, risk
  contribution, and product verdicts only.
- The LLM must explain the existing result. It does not decide or modify the
  verdict.
- If the feature is locked, disabled, not configured, or fails, the API records
  that state in `evidence_summary.llm_status` without blocking the scan.

## Mailbox Scan Now

Connected mailboxes can be scanned on demand through:

`POST /api/saas/mailboxes/{mail_account_id}/scan-now`

Rules:

- Requires CSRF and an owner, admin, or analyst workspace role.
- Runs the `mailbox_monitoring` entitlement before mailbox lookup or IMAP
  connection.
- Reads at most 10 unread messages per request.
- Runs the local `payment_relevance` gate before deep analysis. Clear
  non-payment messages are skipped and not written to scan history. Invoice,
  payment request, bank-detail change, receipt, billing notice, and unknown
  messages continue to the full pipeline.
- Stores results as `mailbox_scan` scan history entries.
- Does not return raw email bodies, mailbox passwords, encrypted credential
  blobs, or provider tokens to the browser.

## Workspace Roles

Workspace memberships now support these roles:

- `owner`: manages billing, mailbox connections, scans, history deletion, and
  team membership.
- `admin`: manages billing, mailbox connections, scans, history deletion, and
  team membership.
- `analyst`: can run scans, scan connected mailboxes, view history, and delete
  scan results.
- `viewer`: can view workspace history and account state only.

The store preserves at least one active owner per workspace.

## Browser Extension Starter

The `browser_extension/` folder contains a minimal Chrome/Edge Manifest V3
companion extension. It opens the signed-in web app routes only:

- PhishAnalyze `/analyze`
- PayShield `/app`

It does not scrape browser pages, read mailbox contents, store credentials, or
include API keys.

## Sandbox Provider Wiring

Hybrid Analysis, ANY.RUN, Joe Sandbox, and browser detonation remain plan-gated
pipeline checks. The Hybrid Analysis client can now initialize with only the API
key configured, while an API secret remains optional for deployments that need
it.

External sandbox usage still depends on provider keys, timeout limits, and
quota gates. The manual product should stay useful without sandbox providers.
