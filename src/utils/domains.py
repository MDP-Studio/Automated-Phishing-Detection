"""
Shared domain-manipulation helpers.

Kept small on purpose. If this file grows, split by concern
(registrable-domain extraction vs. canonicalisation vs. comparison)
rather than accreting helpers into one module.

Why not `tldextract`? It's already a declared dependency, and the
Public Suffix List is the "correct" answer. But tldextract triggers
a network fetch on first use unless the PSL snapshot is shipped
with the install, and running analyzers synchronously inside a
hot per-email path makes that latency an operational risk.
The two-part-TLD table below covers every TLD that appears in our
corpus and the audit reports. When a sample surfaces a TLD the
table misses, add it here — don't bring tldextract in as a quick
fix, because the real fix is always "this suffix belongs in the
table".
"""
from __future__ import annotations

# Two-part effective TLDs we care about. Extend as new TLDs show up
# in real samples. Kept explicit rather than PSL-derived so every
# entry has a traceable reason in the commit that added it.
_TWO_PART_TLDS: frozenset[str] = frozenset({
    "co.uk", "com.au", "co.in", "co.jp", "co.nz", "com.br",
    "com.mx", "org.uk", "gov.uk", "gov.au", "co.za", "com.sg",
    "com.hk", "com.py", "co.kr", "com.cn", "org.au", "net.au",
})


def get_root_domain(domain: str) -> str:
    """
    Return the registrable (root) domain for ``domain``.

    Examples::

        >>> get_root_domain("noreply.github.com")
        'github.com'
        >>> get_root_domain("mail.google.com")
        'google.com'
        >>> get_root_domain("auspost.com.au")
        'auspost.com.au'
        >>> get_root_domain("deep.sub.foo.co.uk")
        'foo.co.uk'

    An empty or single-label input is returned unchanged (lowercased,
    with leading/trailing dots stripped) — callers pass sender-address
    fragments and URL hosts that may already have been normalised
    inconsistently upstream.
    """
    if not domain:
        return ""
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts) if parts else ""
    last_two = ".".join(parts[-2:])
    if last_two in _TWO_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
