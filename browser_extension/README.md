# PhishAnalyze / PayShield Browser Extension Starter

This is a minimal Chrome/Edge Manifest V3 companion extension. It does not read
mailbox contents automatically and it does not store credentials. It gives users
quick links into the signed-in PhishAnalyze and PayShield web apps.

## Local Install

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable developer mode.
3. Choose "Load unpacked".
4. Select this `browser_extension` folder.

## Privacy Boundary

- No background scraping.
- No credential storage.
- No API keys in the extension.
- Analysis still happens inside the web app session and existing server-side
  plan gates.
