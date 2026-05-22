# Lightweight Incident Workflow

This project now includes a small incident workflow layer for PhishAnalyze and
PayShield. It is intentionally a case tracker, not a SOAR platform.

## Purpose

The workflow closes the gap between detection and response by preserving the
minimum state needed for a manual incident review:

- case ID tied to one `scan_results.id`
- status: `open`, `triaged`, `investigating`, `contained`, or `closed`
- severity: `low`, `medium`, `high`, or `critical`
- owner from the workspace membership table
- immutable event chain with scan evidence, status changes, owner changes,
  severity changes, notes, and escalation markers

This supports a practical
[NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) / CSF 2.0
style response loop while avoiding automated remediation.

## API

List cases:

```http
GET /api/saas/cases
```

Create a case from a stored scan result:

```http
POST /api/saas/cases
Content-Type: application/json

{
  "scan_result_id": "res_...",
  "severity": "high",
  "note": "Finance pilot case"
}
```

Update state, owner, severity, note, or escalation:

```http
PATCH /api/saas/cases/case_...
Content-Type: application/json

{
  "status": "triaged",
  "escalate": true,
  "escalation_reason": "Finance owner review"
}
```

Read the evidence chain:

```http
GET /api/saas/cases/case_...
```

## Security Boundary

- Every case query is scoped by authenticated `org_id`.
- Case creation requires the scan result to belong to the same organization.
- Case owners must be active members of the same workspace.
- Owner/admin case mutations are included in the passkey step-up matrix when
  `PHISHANALYZE_PASSKEY_ENFORCEMENT=enforce` and a passkey exists.
- Evidence events store scan identifiers, verdict, payment decision, and
  subject. They do not store raw email bodies.

## Non-Goals

- No auto-quarantine.
- No external ticket creation.
- No user notifications.
- No playbook automation.
- No full SOAR workflow engine.

The fastest validation remains a 10-incident manual pilot. Track whether each
case reaches `closed`, who owned it, whether it was escalated, and time from
case creation to closure.
