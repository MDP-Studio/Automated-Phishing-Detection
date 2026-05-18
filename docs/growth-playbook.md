# Growth Playbook

This repo powers two public products from the same FastAPI app:

- PhishAnalyze: `https://phishanalyze.mdpstudio.com.au`
- PayShield: `https://payshield.mdpstudio.com.au`

## Search Pages

| Product | Page | Search intent |
| --- | --- | --- |
| PhishAnalyze | `/guides/email-header-analysis` | How to read email headers, SPF, DKIM, DMARC, and sender mismatch evidence. |
| PhishAnalyze | `/guides/safe-eml-scanner` | How to scan a suspicious `.eml` file without clicking links. |
| PhishAnalyze | `/guides/phishing-examples` | Common phishing examples and warning patterns. |
| PayShield | `/guides/invoice-fraud-checklist` | Invoice fraud checklist before paying suppliers. |
| PayShield | `/guides/bec-verification` | Business email compromise verification workflow. |
| PayShield | `/guides/before-you-pay` | Quick before-payment safety checklist for SMEs. |

## Weekly Tracking

Check Google Search Console each week and record:

| Week | Product | Top query | Impressions | Clicks | CTR | Position | Action |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 2026-05-18 | PhishAnalyze |  |  |  |  |  | Check which guide gets first impressions. |
| 2026-05-18 | PayShield |  |  |  |  |  | Check whether invoice fraud or BEC terms show earlier demand. |

## Distribution Assets

### LinkedIn: PhishAnalyze

Suspicious emails are easier to judge when you keep the original evidence.

I added public PhishAnalyze guides for:

- reading email headers
- safely scanning `.eml` files
- recognizing realistic phishing patterns

The scanner keeps the verdict, evidence, failed checks, skipped checks, and next steps visible instead of hiding everything behind a generic risk score.

Link: https://phishanalyze.mdpstudio.com.au/guides/email-header-analysis

### LinkedIn: PayShield

Invoice fraud is a workflow problem as much as a technical one.

PayShield now has public guides for:

- invoice fraud checks
- BEC verification
- before-payment review

The goal is simple: hold risky payment requests, verify through trusted channels, and record the evidence before money leaves the account.

Link: https://payshield.mdpstudio.com.au/guides/invoice-fraud-checklist

## Demo Ideas

- Record a 20 second PhishAnalyze clip: upload `.eml`, show verdict, show evidence and next steps.
- Record a 20 second PayShield clip: paste a payment email, show `DO_NOT_PAY_UNTIL_VERIFIED`, show verification steps.
- Use the guide pages as the post links, then route interested users into `/analyze` or `/app`.

## Next Content Bets

- PhishAnalyze: add one sanitized public example page for each verdict type.
- PayShield: add an Australian SME invoice fraud page with concrete verification workflow and no legal claims.
- Both: add FAQ sections after Search Console reveals real user queries.
