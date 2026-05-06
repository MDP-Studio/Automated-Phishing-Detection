from __future__ import annotations

import json
import re
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


def test_mailbox_guide_is_easy_to_find_and_privacy_bounded():
    guide = (ROOT / "templates" / "mailbox_guide.html").read_text(encoding="utf-8")
    docs = (ROOT / "docs" / "mailbox-connection-guide.md").read_text(encoding="utf-8")
    phish = (ROOT / "templates" / "phish_app.html").read_text(encoding="utf-8")
    payshield = (ROOT / "templates" / "saas_app.html").read_text(encoding="utf-8")

    combined = guide + docs
    assert "Use an app password, not your normal email password" in guide
    assert "Microsoft, work, school, and university accounts may need OAuth or admin approval" in guide
    assert "Gmail" in combined
    assert "Outlook / Microsoft 365" in combined
    assert "Zoho Mail" in combined
    assert "Proton Mail Bridge" in combined
    assert "AOL Mail" in guide
    assert "https://myaccount.google.com/apppasswords" in combined
    assert "https://outlook.live.com/mail/0/options/mail/accounts/popImap" in combined
    assert "https://login.yahoo.com/account/security" in combined
    assert "https://account.apple.com/account/manage" in combined
    assert "https://mail.zoho.com/zm/#settings/mailaccounts" in combined
    assert "https://app.fastmail.com/settings/security" in combined
    assert "https://login.aol.com/account/security" in combined
    assert "It never accepts or stores passwords." in docs
    assert '<option value="yahoo">Yahoo Mail</option>' in phish
    assert '<option value="icloud">iCloud Mail</option>' in payshield
    assert '<option value="fastmail">Fastmail</option>' in phish
    assert 'name="port"' in phish
    assert 'name="port"' in payshield
    assert "/mailbox-guide" in phish
    assert "/mailbox-guide" in payshield


def test_external_template_links_open_in_new_tab_safely():
    templates = [
        ROOT / "templates" / "mailbox_guide.html",
        ROOT / "templates" / "accounts.html",
        ROOT / "templates" / "monitor.html",
    ]

    external_anchor = re.compile(r"<a\b[^>]*href=\"https?://[^>]+>", re.IGNORECASE)
    for template in templates:
        source = template.read_text(encoding="utf-8")
        for match in external_anchor.findall(source):
            assert 'target="_blank"' in match, f"{template.name}: {match}"
            assert 'rel="noopener noreferrer"' in match, f"{template.name}: {match}"
