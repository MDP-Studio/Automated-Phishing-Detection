# PayShield Detection Assurance

PayShield should not claim mature payment-scam detection from synthetic data
alone. Use the payment dataset tools to maintain a redacted real-world review
set, then train or tune only after the evidence shows a clear gap.

## Dataset Shape

`data/payment_scam_dataset/` is ignored by git. Labels live in
`labels.csv`; samples live in `samples/`.

Required label fields include:

- `payment_decision`: `SAFE`, `VERIFY`, or `DO_NOT_PAY`
- `scenario`: payment context such as `bank_detail_change` or `legitimate_invoice`
- `channel`: `email`, `sms`, `chat`, `voice`, or `voice_transcript`
- `source_type`: `real`, `redacted`, `internal`, `public`, or `synthetic`
- `contains_real_pii`: must be `no` before ML export or assurance claims

Older label files without `channel` are still accepted and treated as email.

## Assurance Report

Run:

```bash
python scripts/payment_dataset.py assurance-report --dataset data/payment_scam_dataset
```

The report writes:

- `data/payment_scam_dataset/reports/payment_assurance_report.json`
- `data/payment_scam_dataset/reports/payment_assurance_report.md`

Default target:

- 100 PII-free real/redacted/internal payment samples
- at least 20 PII-free real/redacted/internal samples per decision class
- train, validation, and test split coverage
- channel-labeled SMS, chat, or voice transcript samples before making
  multi-channel drift claims

Public corpus rows are useful for regression tests. Synthetic rows are useful
for plumbing. Neither replaces real or redacted payment examples for product
assurance.

## Admin Visibility

The private admin overview reads the JSON report and shows only aggregate
counts:

- status
- readiness
- PII-free real/redacted/internal count
- recommendation count
- decision counts
- channel counts

It does not show sample filenames, raw email text, mailbox identifiers, payment
details, or customer content.

## Practical Collection Rule

For each real invoice, bank-change, remittance, or supplier-impersonation
sample:

1. Redact it with `scripts/payment_dataset.py redact`.
2. Run `scripts/payment_dataset.py audit-pii`.
3. Label the redacted `.eml` with the expected PayShield decision.
4. Keep source files and generated reports under ignored `data/`.
5. Re-run the assurance report before training or changing thresholds.
