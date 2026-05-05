from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_phishanalyze_static_copy_has_no_payment_decision_language():
    source = (ROOT / "static" / "phish_app.js").read_text(encoding="utf-8")

    forbidden = [
        "Payment decision",
        "Payment-risk decision",
        "DO_NOT_PAY",
        "Do not pay until independently confirmed",
        "legal approval",
    ]
    for phrase in forbidden:
        assert phrase not in source


def test_payshield_static_copy_uses_safe_decision_support_wording():
    source = (ROOT / "static" / "saas.js").read_text(encoding="utf-8")

    assert "DO_NOT_PAY_UNTIL_VERIFIED" in source
    assert "Do not pay until independently confirmed" in source
    assert "Payment-risk decision support" in source
    forbidden = [
        "legal approval",
        "approve payment",
        "authorized payment",
        "authorization decision",
        "Do not release payment",
    ]
    lowered = source.lower()
    for phrase in forbidden:
        assert phrase.lower() not in lowered
