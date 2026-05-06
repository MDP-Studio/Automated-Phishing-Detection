# Mailbox Connection Guide

Use manual `.eml` upload first if you only want to test the product. Mailbox
monitoring is optional and should be connected only when you want the app to
scan new emails from an inbox.

## The Simple Rule

1. Do not use your normal email password.
2. Use an app-specific password when your email provider supports it.
3. Use IMAP with SSL/TLS on port `993`.
4. Use your full email address as the username unless your provider says otherwise.
5. If the account is a work, school, or university account, ask the admin before retrying.

## What The App Stores

The app stores encrypted connection material and scan metadata. It must never
return the raw app password, encrypted token material, or full mailbox body in
API responses. Users can delete a mailbox connection from the app. They should
also revoke the app password inside the email provider account settings.

## Provider Quick Guide

| Provider | Current path | IMAP host | Password to use | Notes |
|---|---|---|---|---|
| Gmail / Google Workspace | Usually works now | `imap.gmail.com` | Google app password | Enable IMAP, turn on 2-Step Verification, then create an app password. Workspace admins may block this. |
| Outlook / Hotmail / Microsoft 365 | Use manual upload unless IMAP is explicitly allowed | `outlook.office365.com` | Usually OAuth, not a normal password | Microsoft commonly requires Modern Auth/OAuth2. Work, school, and university tenants often need admin consent. |
| Yahoo Mail | Usually works now | `imap.mail.yahoo.com` | Yahoo app password | Generate the app password from Yahoo Account Security. |
| iCloud Mail | Usually works now | `imap.mail.me.com` | Apple app-specific password | Two-factor authentication must be enabled. Apple may expect the username before `@icloud.com`. |
| Zoho Mail | Usually works now | `imap.zoho.com` | Zoho app-specific password if 2FA is enabled | Confirm IMAP is enabled in Zoho Mail settings. Some organization policies block IMAP. |
| Fastmail | Usually works now | `imap.fastmail.com` | Fastmail app password | Some lower plans may not include third-party IMAP access. |
| Proton Mail | Advanced | Proton Mail Bridge value | Bridge-generated password | Proton needs Proton Mail Bridge for IMAP. This is better for private/local deployments than public SaaS onboarding. |
| AOL Mail | Usually works now | `imap.aol.com` or `export.imap.aol.com` | AOL app password when required | Try the official alternate host if one host fails. |
| Other IMAP / custom domain | Depends on provider | Ask provider or IT admin | Provider app password if available | Corporate and university accounts may block IMAP or require OAuth. |

## User-Friendly Wording

Use this in the product:

```text
Start with manual .eml upload if you are unsure.
Mailbox monitoring needs an app-specific password, not your normal mailbox password.
Microsoft, work, school, and university accounts may need admin approval.
```

## Agent / MCP Helper

The MCP server exposes `mailbox_connection_guide` for agents that need to help a
user choose the right provider path without asking for credentials.

Example:

```json
{
  "name": "mailbox_connection_guide",
  "arguments": {
    "provider": "gmail"
  }
}
```

The tool returns provider instructions, common safety rules, and privacy notes.
It never accepts or stores passwords.

## Official Provider References

- [Google app passwords](https://support.google.com/mail/answer/185833)
- [Gmail IMAP server settings](https://developers.google.com/workspace/gmail/imap/imap-smtp)
- [Microsoft Outlook.com POP/IMAP/SMTP settings](https://support.microsoft.com/en-gb/office/pop-imap-and-smtp-settings-for-outlook-com-d088b986-291d-42b8-9564-9c414e2aa040)
- [Yahoo IMAP settings](https://my.help.yahoo.com/kb/SLN4075.html)
- [Apple iCloud Mail server settings](https://support.apple.com/en-lamr/102525)
- [Zoho IMAP server settings](https://help.zoho.com/portal/en/kb/mail/access-from-external-mail-clients/articles/what-are-the-incoming-outgoing-server-settings-for-zoho-to-setup-as-imap-account)
- [Zoho IMAP access settings](https://www.zoho.com/mail/help/imap-access.html)
- [Fastmail setup guide](https://www.fastmail.help/hc/en-us/articles/360058752834-Set-up-Fastmail-on-your-device)
- [Fastmail server names and ports](https://www.fastmail.help/hc/en-us/articles/1500000278342-Server-names-and-ports)
- [Proton Mail Bridge](https://proton.me/support/support/bridge)
- [AOL IMAP settings](https://help.aol.com/articles/how-do-i-use-other-email-applications-to-send-and-receive-my-aol-mail)
- [AOL export IMAP settings](https://help.aol.com/articles/download-your-email-from-aol-mail-with-imap)
