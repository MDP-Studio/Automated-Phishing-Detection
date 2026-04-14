"""
Allowlist of social-platform sender domains used by the LinkedIn / social
calibration rule in `src/scoring/calibration.py`.

This is *augmentation*, not a security boundary. A spoofed sender pretending
to be one of these domains cannot benefit from the list because:

  1. The spoof's actual From: domain isn't on the list (typo squat like
     `linkedln-mail.com`), AND
  2. The spoof can't produce valid SPF/DKIM/DMARC from the real domain
     because they don't control the DKIM private key.

The calibration rule that consumes this list ALWAYS gates on auth-pass +
domain-on-list. Either condition alone is insufficient.

Each entry has a date-added comment and a sample reference. Adding a new
entry requires:
  - The sample .eml that motivated it
  - A new test row in tests/unit/test_calibration.py
  - A row in docs/calibration_rules.md (next to the rule that uses it)

Quarterly review cadence — see ADR 0001 §FM3.
"""
from __future__ import annotations


# Each entry is the registrable domain (eTLD+1). Subdomains are matched
# automatically because the rule uses an `endswith("." + domain)` check
# in addition to exact match.
SOCIAL_PLATFORM_DOMAINS: frozenset[str] = frozenset({
    # LinkedIn — the original LinkedIn FP sample_17_legitimate_linkedin_digest.eml
    # uses messages-noreply@linkedin.com. Added 2026-04-14. ADR 0001.
    "linkedin.com",
    # LinkedIn also routes through "engagement" subdomains and a few sister
    # domains. linkedinmail.com is the bulk-mail ESP. Added preemptively
    # based on lessons-learned.md observation that LinkedIn uses 3+ domains.
    # The eTLD+1 match plus the auth-gate makes this safe to broaden.
    "linkedinmail.com",
})


def is_social_platform_domain(from_domain: str) -> bool:
    """
    Return True if `from_domain` is on the social-platform allowlist.

    Matches exact domain or any subdomain (e.g. `e.linkedin.com` matches
    `linkedin.com`). Case-insensitive.
    """
    if not from_domain:
        return False
    domain = from_domain.strip().lower().lstrip(".")
    if domain in SOCIAL_PLATFORM_DOMAINS:
        return True
    return any(domain.endswith("." + allowed) for allowed in SOCIAL_PLATFORM_DOMAINS)
