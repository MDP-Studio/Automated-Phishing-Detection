"""Customer-facing mailbox connection guidance."""
from __future__ import annotations

from copy import deepcopy
from typing import Any


MAILBOX_GUIDE_TOOL_NAME = "mailbox_connection_guide"


MAILBOX_GUIDE_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "provider": {
            "type": "string",
            "description": (
                "Email provider to explain. Use all, gmail, outlook, yahoo, "
                "icloud, zoho, fastmail, proton, aol, or imap."
            ),
            "default": "all",
        }
    },
    "additionalProperties": False,
}


MAILBOX_GUIDE_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "tool": {"type": "string"},
        "schema_version": {"type": "string"},
        "provider": {"type": "string"},
        "summary": {"type": "string"},
        "common_rules": {"type": "array", "items": {"type": "string"}},
        "providers": {"type": "array", "items": {"type": "object"}},
        "privacy": {"type": "object"},
    },
    "required": ["tool", "schema_version", "provider", "summary", "providers"],
    "additionalProperties": True,
}


COMMON_RULES = [
    "Use an app-specific password when your provider supports it. Do not use your normal mailbox password unless your provider explicitly requires it.",
    "Use IMAP over SSL/TLS on port 993.",
    "Use the full email address as the username unless the provider says otherwise.",
    "Work, school, and university accounts may need an administrator to allow IMAP, app passwords, or third-party mailbox access.",
    "If Microsoft or Google blocks the connection, use manual .eml upload until the OAuth connector is enabled.",
]


PRIVACY_NOTICE = {
    "stored": "Only encrypted mailbox connection material and scan metadata are stored.",
    "not_returned": "The raw app password, encrypted token material, and full mailbox body are never returned in API responses.",
    "disconnect": "Users can delete a mailbox connection from the app. If a provider app password is used, revoke it in the provider account settings too.",
}


PROVIDER_GUIDES: dict[str, dict[str, Any]] = {
    "gmail": {
        "name": "Gmail / Google Workspace",
        "works_with_current_imap": True,
        "difficulty": "Medium",
        "host": "imap.gmail.com",
        "port": 993,
        "password_label": "Google app password",
        "quick_setup": [
            "Open Gmail in a browser and make sure IMAP is enabled.",
            "Turn on 2-Step Verification for the Google account.",
            "Create a Google app password for Mail.",
            "In PhishAnalyze or PayShield, choose Gmail, enter the email address, use imap.gmail.com as the host, and paste the app password.",
        ],
        "watch_out": [
            "Google revokes app passwords when the Google Account password changes.",
            "Some Google Workspace admins disable app passwords or IMAP. If you cannot create an app password, ask the admin or use manual .eml upload.",
        ],
        "official_links": [
            {
                "label": "Google app passwords",
                "url": "https://support.google.com/mail/answer/185833",
            },
            {
                "label": "Gmail IMAP server settings",
                "url": "https://developers.google.com/workspace/gmail/imap/imap-smtp",
            },
        ],
    },
    "outlook": {
        "name": "Outlook / Hotmail / Microsoft 365",
        "works_with_current_imap": "limited",
        "difficulty": "Hard until OAuth is available",
        "host": "outlook.office365.com",
        "port": 993,
        "password_label": "Usually OAuth, not a normal password",
        "quick_setup": [
            "For personal Outlook.com accounts, first enable IMAP in Outlook settings if it is available.",
            "Try only if the account or tenant allows IMAP access with the credential you provide.",
            "If the connection fails, use manual .eml upload for now. Microsoft commonly requires Modern Auth/OAuth2, which is the safer connector to build next.",
        ],
        "watch_out": [
            "Microsoft states Outlook.com requires Modern Auth/OAuth2 for POP/IMAP.",
            "Work and university Microsoft 365 accounts often need tenant admin consent.",
            "Do not keep retrying your normal password if Microsoft blocks IMAP. That can trigger security lockouts.",
        ],
        "official_links": [
            {
                "label": "Microsoft Outlook.com IMAP settings",
                "url": "https://support.microsoft.com/en-gb/office/pop-imap-and-smtp-settings-for-outlook-com-d088b986-291d-42b8-9564-9c414e2aa040",
            }
        ],
    },
    "yahoo": {
        "name": "Yahoo Mail",
        "works_with_current_imap": True,
        "difficulty": "Medium",
        "host": "imap.mail.yahoo.com",
        "port": 993,
        "password_label": "Yahoo app password",
        "quick_setup": [
            "Open Yahoo Account Security.",
            "Generate an app password for Mail.",
            "Choose IMAP or Yahoo in the app, enter your full Yahoo email address, use imap.mail.yahoo.com, and paste the app password.",
        ],
        "watch_out": [
            "Yahoo app-password creation is sometimes unavailable on new or restricted accounts.",
            "If Yahoo refuses the app password, use manual .eml upload and try again later from Yahoo account security.",
        ],
        "official_links": [
            {
                "label": "Yahoo IMAP settings",
                "url": "https://my.help.yahoo.com/kb/SLN4075.html",
            }
        ],
    },
    "icloud": {
        "name": "iCloud Mail",
        "works_with_current_imap": True,
        "difficulty": "Medium",
        "host": "imap.mail.me.com",
        "port": 993,
        "password_label": "Apple app-specific password",
        "quick_setup": [
            "Make sure two-factor authentication is enabled for the Apple Account.",
            "Generate an app-specific password from Apple Account settings.",
            "Choose IMAP, enter your iCloud email, use imap.mail.me.com, and paste the app-specific password.",
        ],
        "watch_out": [
            "Apple says the username is often the part before @icloud.com. If that fails, try the full email address.",
            "Changing the Apple Account password can require a fresh app-specific password.",
        ],
        "official_links": [
            {
                "label": "Apple iCloud Mail server settings",
                "url": "https://support.apple.com/en-lamr/102525",
            }
        ],
    },
    "zoho": {
        "name": "Zoho Mail",
        "works_with_current_imap": True,
        "difficulty": "Easy to Medium",
        "host": "imap.zoho.com",
        "port": 993,
        "password_label": "Zoho password or Zoho app-specific password when 2FA is enabled",
        "quick_setup": [
            "Open Zoho Mail settings and confirm IMAP access is enabled for the mailbox.",
            "If Zoho two-factor authentication is enabled, create an application-specific password.",
            "Choose IMAP, enter your full Zoho email address, use imap.zoho.com, and paste the Zoho app-specific password.",
        ],
        "watch_out": [
            "Some Zoho plans or organization policies may disable IMAP.",
            "If your Zoho account is in a regional data center and imap.zoho.com fails, check Zoho's account-specific server guidance.",
        ],
        "official_links": [
            {
                "label": "Zoho IMAP server settings",
                "url": "https://help.zoho.com/portal/en/kb/mail/access-from-external-mail-clients/articles/what-are-the-incoming-outgoing-server-settings-for-zoho-to-setup-as-imap-account",
            },
            {
                "label": "Zoho IMAP access settings",
                "url": "https://www.zoho.com/mail/help/imap-access.html",
            },
        ],
    },
    "fastmail": {
        "name": "Fastmail",
        "works_with_current_imap": True,
        "difficulty": "Easy",
        "host": "imap.fastmail.com",
        "port": 993,
        "password_label": "Fastmail app password",
        "quick_setup": [
            "Create an app password in Fastmail settings.",
            "Choose IMAP, enter your Fastmail username or email address, use imap.fastmail.com, and paste the app password.",
        ],
        "watch_out": [
            "Fastmail Basic plans may not include third-party IMAP/app-password access.",
            "Fastmail also provides proxy hosts if a firewall blocks normal mail ports.",
        ],
        "official_links": [
            {
                "label": "Fastmail app password guidance",
                "url": "https://www.fastmail.help/hc/en-us/articles/360058752834-Set-up-Fastmail-on-your-device",
            },
            {
                "label": "Fastmail server names and ports",
                "url": "https://www.fastmail.help/hc/en-us/articles/1500000278342-Server-names-and-ports",
            },
        ],
    },
    "proton": {
        "name": "Proton Mail",
        "works_with_current_imap": "advanced",
        "difficulty": "Advanced",
        "host": "127.0.0.1 or the host shown in Proton Mail Bridge",
        "port": "Bridge IMAP port, often 1143",
        "password_label": "Bridge-generated mailbox password",
        "quick_setup": [
            "Install and sign in to Proton Mail Bridge on the machine that can reach the app.",
            "Open Bridge and copy its IMAP server, port, username, and generated password.",
            "Choose IMAP in the app and enter the Bridge details exactly.",
        ],
        "watch_out": [
            "Proton Mail does not provide normal direct IMAP access without Bridge.",
            "Bridge is easiest for local/private deployments. It is usually not a simple public SaaS connection path.",
        ],
        "official_links": [
            {
                "label": "Proton Mail Bridge",
                "url": "https://proton.me/support/support/bridge",
            }
        ],
    },
    "aol": {
        "name": "AOL Mail",
        "works_with_current_imap": True,
        "difficulty": "Medium",
        "host": "imap.aol.com or export.imap.aol.com",
        "port": 993,
        "password_label": "AOL app password when required",
        "quick_setup": [
            "Open AOL account security.",
            "Generate an app password if AOL requires it for your account.",
            "Choose IMAP, enter your full AOL email address, use imap.aol.com or export.imap.aol.com, and paste the app password.",
        ],
        "watch_out": [
            "AOL documents both imap.aol.com and export.imap.aol.com in support material. If one host fails, try the other official host.",
        ],
        "official_links": [
            {
                "label": "AOL IMAP settings",
                "url": "https://help.aol.com/articles/how-do-i-use-other-email-applications-to-send-and-receive-my-aol-mail",
            },
            {
                "label": "AOL export IMAP settings",
                "url": "https://help.aol.com/articles/download-your-email-from-aol-mail-with-imap",
            },
        ],
    },
    "imap": {
        "name": "Other IMAP / Custom domain",
        "works_with_current_imap": True,
        "difficulty": "Depends on provider",
        "host": "Ask the provider or IT admin",
        "port": 993,
        "password_label": "Provider app password if available",
        "quick_setup": [
            "Find the provider's incoming IMAP server name.",
            "Confirm SSL/TLS on port 993.",
            "Use the full mailbox address as the username unless the provider says otherwise.",
            "Use an app password if the provider supports app passwords.",
        ],
        "watch_out": [
            "Corporate and university accounts may block IMAP or require admin approval.",
            "If the provider only supports OAuth, use manual .eml upload until OAuth is available in the app.",
        ],
        "official_links": [],
    },
}


ALIASES = {
    "all": "all",
    "google": "gmail",
    "google workspace": "gmail",
    "hotmail": "outlook",
    "microsoft": "outlook",
    "microsoft 365": "outlook",
    "office365": "outlook",
    "office 365": "outlook",
    "outlook.com": "outlook",
    "apple": "icloud",
    "apple mail": "icloud",
    "icloud mail": "icloud",
    "zohomail": "zoho",
    "aol mail": "aol",
    "custom": "imap",
    "other": "imap",
    "generic": "imap",
}


def normalize_mailbox_provider(provider: str | None) -> str:
    """Return a known guide provider slug."""
    raw = (provider or "all").strip().lower()
    return ALIASES.get(raw, raw if raw in PROVIDER_GUIDES else "all")


def mailbox_guide_payload(provider: str | None = "all") -> dict[str, Any]:
    """Return sanitized provider guidance for UI, docs, or MCP output."""
    normalized = normalize_mailbox_provider(provider)
    if normalized == "all":
        providers = [deepcopy(PROVIDER_GUIDES[key]) | {"slug": key} for key in PROVIDER_GUIDES]
    else:
        providers = [deepcopy(PROVIDER_GUIDES[normalized]) | {"slug": normalized}]

    return {
        "tool": MAILBOX_GUIDE_TOOL_NAME,
        "schema_version": "1.0",
        "provider": normalized,
        "summary": (
            "Mailbox monitoring currently uses secure IMAP with app-specific "
            "passwords where the provider allows it. Manual .eml upload remains "
            "the safest fallback, especially for Microsoft, work, school, and "
            "university accounts that require OAuth or admin approval."
        ),
        "common_rules": list(COMMON_RULES),
        "providers": providers,
        "privacy": dict(PRIVACY_NOTICE),
    }

