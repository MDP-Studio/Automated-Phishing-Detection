# Product Verdict Mapping

PhishAnalyze and PayShield share analyzer evidence but do not share customer
decision copy.

## PhishAnalyze

PhishAnalyze shows a phishing verdict from the pipeline:

- `CLEAN`
- `SUSPICIOUS`
- `LIKELY_PHISHING`
- `CONFIRMED_PHISHING`

The UI frames these as email-security outcomes with phishing indicators,
sender/domain risk, URL evidence, attachment signals, locked checks, failed
checks, and next steps.

## PayShield

PayShield shows payment-risk decision support:

- `NOT_PAYMENT_SPECIFIC`: no payment workflow is needed for this email.
- `SAFE`: safe to continue normal checks.
- `VERIFY`: verify out of band.
- `DO_NOT_PAY_UNTIL_VERIFIED`: do not pay until independently confirmed.

The backend payment analyzer may still store `DO_NOT_PAY` for compatibility with
datasets and historical tests. Product-facing payloads add `display_decision`
and `display_label` so the UI never needs to show raw backend enum wording.
When the payment-relevance gate skips a clear non-payment email, PayShield shows
`NOT_PAYMENT_SPECIFIC` instead of presenting it as a safe invoice or payment
request.

## LLM Summary Boundary

LLM-backed checks explain structured analyzer evidence only. They do not replace
the scoring engine, decide the phishing verdict, or decide the PayShield display
decision. If the LLM-backed analyzer is unavailable, locked, or not configured,
the API still returns a deterministic structured evidence summary.
