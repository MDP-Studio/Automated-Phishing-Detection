# Payment Fraud Firewall

This product layer turns the phishing detector into a payment decision guard for SMEs.

Instead of only answering "is this email phishing?", it also answers:

- `SAFE`: no material payment scam indicators were found.
- `VERIFY`: do not pay until the supplier or executive is verified independently.
- `DO_NOT_PAY`: block payment release until verification is completed.

## What It Detects

- Fake invoice emails
- Supplier impersonation
- Changed bank detail requests
- Urgent payment pressure
- Approval bypass or secrecy language
- CEO/CFO style transfer requests
- Reply-to domain mismatch
- SPF, DKIM, or DMARC failure on payment requests
- Free-email supplier payment requests
- Risky invoice-themed attachments
- Bank details, BSBs, account numbers, IBANs, SWIFT/BIC codes, PayIDs, ABNs, and amounts

Sensitive payment identifiers are masked in analyzer output by default.

## Pipeline Integration

The new analyzer is `src/analyzers/payment_fraud.py`.

It runs as part of the existing analyzer set under the name `payment_fraud`, and returns:

- risk score
- confidence
- payment decision
- explainable signals
- masked payment fields
- verification steps

The pipeline uses the payment decision as a business-aware override:

- `DO_NOT_PAY` with high risk maps to `CONFIRMED_PHISHING`.
- `DO_NOT_PAY` with moderate risk maps to at least `LIKELY_PHISHING`.
- `VERIFY` maps a clean email to at least `SUSPICIOUS`.

## Recommended SME Workflow

When an email returns `VERIFY` or `DO_NOT_PAY`:

1. Do not use links, phone numbers, or reply-to addresses from the email.
2. Call the supplier or executive using a saved contact from the accounting system.
3. Compare bank details with the last approved supplier payment record.
4. Require second-person approval for any bank-detail change.
5. Record verifier name, date, and approval outcome before releasing funds.

## Product Positioning

Working name:

> Payment Scam Firewall powered by the phishing detector

Simple pitch:

> Stops invoice scams before your business pays the wrong account.

This keeps the project connected to detection engineering while making the output easier for SMEs to understand and buy.
