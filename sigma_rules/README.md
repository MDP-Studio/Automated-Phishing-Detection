# Sigma Detection Rules

This directory contains hand-written Sigma rules covering the patterns this pipeline detects. They are version-controlled detection content meant for direct consumption by other operators.

## Two flavors of Sigma in this repo

| Source | What it produces | When to use |
|---|---|---|
| **`sigma_rules/*.yml`** (this directory) | Curated, broad behavioral rules. Generic and reusable across deployments. | Drop into your SIEM / Sigma converter as standing detection content. |
| **`src/reporting/sigma_exporter.py`** | Per-campaign rules generated from a single `PipelineResult`. Narrow, observable-specific. | Share the artifact of a specific incident with peers or feed it into a TI platform. |

The static rules in this directory map to the same MITRE ATT&CK techniques documented in [`docs/MITRE_ATTACK_MAPPING.md`](../docs/MITRE_ATTACK_MAPPING.md). Each rule's `tags:` list is the contract.

## Rule index

| File | Title | Technique(s) | Level |
|---|---|---|---|
| `email_brand_impersonation_visual_match.yml` | Visual brand impersonation match | T1656, T1036.005 | high |
| `email_qr_code_credential_phish.yml` | QR-encoded credential phishing (quishing) | T1566.002, T1204.001 | high |
| `email_newly_registered_domain_link.yml` | Link to newly registered domain | T1583.001, T1566.002 | medium |
| `email_bec_wire_fraud_intent.yml` | Business Email Compromise wire-fraud intent | T1534, T1656 | high |
| `email_html_smuggled_attachment.yml` | HTML-smuggled attachment via blob URL | T1027.006, T1566.001 | critical |
| `email_auth_failure_with_attachment.yml` | SPF/DKIM/DMARC failure carrying attachment | T1566.001, T1656 | high |

## Logsource adaptation

All rules use the generic Sigma logsource:

```yaml
logsource:
  category: email
```

Operators consuming these rules should adapt the logsource to their telemetry source. Common substitutions:

```yaml
# Microsoft 365 message trace
logsource:
  product: m365
  service: messagetrace

# Proofpoint TAP / Smart Search
logsource:
  product: proofpoint
  service: tap

# This pipeline's own JSON output (treated as a log source)
logsource:
  product: phishing_detection_pipeline
  category: verdict
```

Field names (`sender_address`, `subject`, `url`, `attachment_hash`, etc.) follow the Sigma email taxonomy and may need vendor-specific aliasing.

## Contributing rules

If you write a new rule:

1. Place it in this directory with the `email_<descriptor>.yml` naming convention.
2. Include `tags:` referencing the appropriate ATT&CK technique IDs.
3. Add it to the index table above.
4. Add a corresponding row in `docs/MITRE_ATTACK_MAPPING.md` if the rule covers a technique not yet listed.
