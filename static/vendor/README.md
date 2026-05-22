Vendored browser assets used by the dashboard.

Update process:
1. Run `python scripts/vendor_chartjs.py --version VERSION`.
2. Run `python scripts/vendor_chartjs.py --check`.
3. Run `python scripts/dashboard_browser_check.py`.
4. Commit `static/vendor/chart.umd.js`, `static/vendor/chart.umd.js.map`,
   and this README together.

`chart.umd.js`
- Library: Chart.js 4.4.0
- Source: https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js
- Local patch: passive-listener feature-detection catch logs debug context so
  the machine quality gate does not require editing generated code later.
- SHA256: 1D9CF9128AA72407E68A2777C3D439CB514C33B80D5570ABD675425E16F0A38E
- License: MIT, retained in the bundled file header.

`chart.umd.js.map`
- Source: https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js.map
- SHA256: 31C257F6358DF2343ED3E208D7200181AD1E08B6264E4673AA0E1B70CE8D33EC

The dashboard serves this file from `/static/vendor/chart.umd.js` so the
graphing code works with the project's `script-src 'self'` CSP and does not
depend on a public CDN at runtime.
