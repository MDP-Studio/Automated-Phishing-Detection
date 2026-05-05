from __future__ import annotations

import json
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


def test_browser_extension_stays_link_only_and_privacy_bounded():
    extension = ROOT / "browser_extension"
    manifest = json.loads((extension / "manifest.json").read_text(encoding="utf-8"))
    popup_html = (extension / "popup.html").read_text(encoding="utf-8").lower()
    readme = (extension / "README.md").read_text(encoding="utf-8").lower()

    assert manifest["manifest_version"] == 3
    assert manifest["permissions"] == []
    assert manifest["host_permissions"] == [
        "https://phishanalyze.mdpstudio.com.au/*",
        "https://payshield.mdpstudio.com.au/*",
    ]
    assert "does not read mailbox contents" in popup_html
    assert "no background scraping" in readme
    assert "no credential storage" in readme
