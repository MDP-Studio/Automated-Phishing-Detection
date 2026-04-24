"""
Unit tests for src/utils/domains.py.

Locks the registrable-domain extraction behaviour for the two callers
that depend on it today (brand_impersonation.py and header_analyzer.py).
If these tests drift, both reply-to-mismatch signals drift with them —
which is why the table is explicit rather than PSL-derived.
"""
from __future__ import annotations

import pytest

from src.utils.domains import get_root_domain


class TestGetRootDomain:
    @pytest.mark.parametrize("fqdn,expected", [
        # Simple two-label domains stay as-is
        ("github.com", "github.com"),
        ("example.org", "example.org"),
        # Subdomains collapse to the registrable root
        ("noreply.github.com", "github.com"),
        ("mail.google.com", "google.com"),
        ("very.deep.sub.example.com", "example.com"),
        # Two-part TLDs keep three labels
        ("auspost.com.au", "auspost.com.au"),
        ("example.co.uk", "example.co.uk"),
        ("deep.sub.example.co.uk", "example.co.uk"),
        ("ato.gov.au", "ato.gov.au"),
        # Case is normalised
        ("NoReply.GitHub.COM", "github.com"),
        # Leading/trailing dots stripped
        (".github.com.", "github.com"),
    ])
    def test_canonical_cases(self, fqdn: str, expected: str) -> None:
        assert get_root_domain(fqdn) == expected

    def test_empty_input_returns_empty(self) -> None:
        assert get_root_domain("") == ""

    def test_single_label_returned_unchanged(self) -> None:
        # Lone labels (localhost, intranet hostnames) aren't valid
        # registrable domains — return them as-is so the caller can
        # decide whether to treat that as a mismatch.
        assert get_root_domain("localhost") == "localhost"

    def test_subdomain_of_same_root_compares_equal(self) -> None:
        """The whole point of the helper: github.com and its subdomains
        compare equal, so reply-to mismatches don't false-positive."""
        assert get_root_domain("noreply.github.com") == get_root_domain("github.com")
        assert get_root_domain("mail.auspost.com.au") == get_root_domain("auspost.com.au")

    def test_different_roots_compare_unequal(self) -> None:
        """Distinct orgs still show up as distinct — the helper must not
        over-collapse (e.g., github.com vs gitlab.com)."""
        assert get_root_domain("github.com") != get_root_domain("gitlab.com")
        assert get_root_domain("paypal.com") != get_root_domain("paypa1.com")
