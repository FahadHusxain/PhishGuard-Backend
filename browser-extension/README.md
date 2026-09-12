# PhishGuard browser extension

This directory is an unpacked Chromium Manifest V3 extension for Chrome and
Edge. It analyzes the active HTTP(S) tab or a manually pasted URL through the
same versioned API used by the PhishGuard web application.

## Local installation

1. Start the backend at `http://127.0.0.1:8000`. The repository root documents
   both virtual-environment and Docker Compose startup.
2. Open `chrome://extensions` in Chrome or `edge://extensions` in Edge.
3. Enable **Developer mode**, choose **Load unpacked**, and select this
   `browser-extension` directory.
4. Pin **PhishGuard Link Scanner**, open any ordinary HTTP(S) page, and click
   the toolbar icon.
5. Select **Analyze URL**. You may replace the current-tab address with any
   complete HTTP(S) URL the evaluator wants to test.

Inside the URL field, **Enter** starts analysis and **Shift+Enter** inserts a
line break. The visible button remains available for pointer and touch input.

Browser-internal pages such as `chrome://settings`, extension-store pages, and
local files cannot be read automatically. Paste an HTTP(S) URL into the popup
when the active page is unsupported.

## Backend configuration

The default backend is `http://127.0.0.1:8000`. Open the gear button in the
popup to use another deployment. Remote deployments must use HTTPS. Chrome
asks for access to that single origin when the setting is saved; a previous
remote origin is removed when the endpoint changes.

Do not configure a public deployment until its TLS, allowed hosts, CORS,
throttling, secrets, PostgreSQL, and Redis settings have passed the release
checklist.

## Security and privacy boundaries

- Required host access is limited to local development addresses.
- Remote HTTPS access is optional and granted at runtime.
- `activeTab` exposes only the invoked tab; there is no browsing-history,
  content-script, scripting, cookie, or web-request permission.
- The extension does not open or download the submitted destination.
- Results are inserted with DOM text nodes; backend text is never interpreted
  as HTML.
- No remote JavaScript, CSS, fonts, analytics, or telemetry are used.
- The scanned URL is sent to the configured backend. The backend stores only
  its normalized origin according to the project's retention policy.

## Tests

From the repository root:

```bash
node --test browser-extension/tests/extension.test.js
python scripts/check_extension.py
```

Regenerate the committed PNG icons after changing the logo generator:

```bash
node scripts/generate_extension_icons.mjs
```
