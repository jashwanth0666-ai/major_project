# AI WatchDog Browser Protection

This optional Manifest V3 extension connects supported Chromium browsers to the local Spring Boot URL analysis service. It uses the existing FastAPI phishing model and Spring policy decision. It does not add or train a model.

## What it does

- Checks sanitized HTTP/HTTPS destinations after an active tab finishes navigation through `POST /api/v1/threat-assessments/url`. The shared assessment adds optional reputation and hostname signals, then records the real visit.
- Injects result-link indicators on Google Search (`google.com`, `google.co.uk`, `google.ca`, `google.com.au`), Bing (`bing.com`), and DuckDuckGo (`duckduckgo.com` and its HTML results host). Other detected Google search URLs are still excluded from ordinary URL analysis, but do not receive result indicators. Search text and result-page URLs are not sent to the URL model.
- Rates up to eight distinct result destinations at a time using `POST /api/v1/threat-assessments/url/preview`. Preview calls use the same model, policy, optional reputation lookup, and hostname signals as navigation analysis, but do not write an audit event for an unvisited result. The content script reads link targets only; it does not collect page text, titles, cookies, or form values.
- Shows a toolbar popup and site report with the actual returned risk level, policy decision, reasons, assessment time, and backend health. Green means the existing model and policy returned `SAFE` and `ALLOW`; it is a low-risk signal, not a guarantee. Missing or failed assessments remain Unknown/unavailable.
- For a `HIGH_RISK` assessment with policy `BLOCK`, installs a Chrome `declarativeNetRequest` rule for the assessed URL. A local exact-host denylist `BLOCK` installs a host-wide rule for that hostname. Matching later navigations redirect to an AI WatchDog warning page. If the rule cannot be installed, is disabled, or cannot safely represent a redacted path, the UI reports that enforcement is unavailable.
- Keeps at most 128 active warning rules and evicts the oldest AI WatchDog rules first; the rule and warning details are reconciled when the extension worker starts.
- Provides a persisted protection switch. Turning it off disables new checks and removes the extension's dynamic warning rules.

## First-visit timing and scope

The browser must send a URL to the local backend and wait for inference before the extension can know the policy decision. The first page can therefore begin loading before a confirmed BLOCK result exists. After that result, the extension installs a real browser redirect rule and re-navigates the current tab through it. Subsequent matching navigations are redirected before the site loads. The extension does not claim to prevent the initial request from reaching the destination.

The rule is scoped to the normalized assessed URL path. Query parameters and fragments are removed before analysis. Credentials, long opaque path segments, and paths containing common secret markers are reduced to the origin; for these redacted paths the extension does not install a rule because that could block unrelated locations or retain a secret. The first visit warning may thus be unavailable in that case.

URL reputation is an optional hostname-only lookup against an operator-configured HTTPS provider and is disabled by default. Local hostname heuristics identify a limited set of IDN, mixed-script, user-information, and deep-subdomain signals; they do not provide comprehensive typo-domain or visual similarity detection. Optional local domain lists can force `BLOCK` for exact host matches; allowlist entries are evidence only. See [domain rule configuration](../doc/URL_DOMAIN_RULES.md). Browser download-content scanning is not implemented. Downloads are not fetched, inspected, or changed. File Shield remains a separate local file feature. Policy outcomes other than `BLOCK` do not install a navigation rule, and there is no proceed action on a BLOCK warning.

## Permissions and privacy

The extension requires its own local API credential. The root launch scripts provision separate per-user credentials for JavaFX, the extension, and the Spring-to-FastAPI connection. Open the extension popup's **Configure local API access** page and paste only the `extension` value from `%APPDATA%\AIWatchDog\auth\api-tokens.json`. The extension credential is scoped by Spring to URL analysis and preview endpoints. It is stored in the browser profile's extension storage; do not share that browser profile with untrusted users. Rotation is described in [the run guide](../doc/RUNNING.md#local-api-credentials).

The manifest requests:

- `tabs` to identify the active tab and its URL for the popup and local analysis.
- `storage` to persist the protection switch, keep current-session tab assessments, and retain sanitized details for active warning rules.
- `declarativeNetRequest` to create and remove actual browser navigation redirect rules after confirmed BLOCK decisions.
- HTTP and HTTPS host access so the browser can redirect matching navigations and run the result-link reader on supported search pages. This broad site-access permission is disclosed by Chrome/Edge when the extension is loaded. Backend requests are restricted in code to `127.0.0.1:8080` and `localhost:8080`.

Before a URL reaches Spring, the extension removes credentials, query parameters, and fragments. It reduces likely secret or opaque path segments to `/`. Search destinations are normalized in the same way. The full URL is not sent to an external reputation service; when the optional provider is enabled, Spring sends only the normalized hostname to its configured HTTPS endpoint. Local warning-rule details contain only the sanitized URL and returned evidence; they are removed when protection is turned off. Current tab assessments use browser-session storage.

## Load for development

1. Start FastAPI and Spring Boot following [the project run guide](../doc/RUNNING.md). Confirm `/api/v1/health` reports the actual Spring and ML service states.
2. In Chrome or Chromium-based Edge, open the extensions page, enable Developer mode, choose **Load unpacked**, and select this directory.
3. Approve the displayed permissions. Open a supported search page or navigate to an HTTP/HTTPS site, then open the AI WatchDog toolbar popup.

Only Chrome and Chromium-based Edge are targeted. The project does not install the extension into a browser profile. Search result selectors and the rule API are browser-version dependent; use the planned browser procedures in [testing.md](../testing.md) before relying on them.

## Backend API

- `POST /api/v1/threat-assessments/url` — unified assessment evidence for an actual navigation; persists an audit event.
- `POST /api/v1/threat-assessments/url/preview` — same evidence and decision path without writing an event; intended for unvisited search destinations.
- `POST /api/v1/analyze` and `/api/v1/analyze/preview` — legacy model/policy response routes remain available to other local clients.
- `GET /api/v1/health` — reports Spring and FastAPI availability. A degraded response can still report Spring `UP` while ML is `DOWN`.

No external provider API key is required for local URL assessment. A local extension credential is required for browser assessment requests.
