# AI WatchDog Browser Protection

This optional Manifest V3 extension connects supported Chromium browsers to the local Spring Boot URL analysis service. It uses the existing FastAPI phishing model and Spring policy decision. It does not add or train a model.

## What it does

- Checks sanitized HTTP/HTTPS destinations after an active tab finishes navigation and records those real visits through `POST /api/v1/analyze`.
- Injects result-link indicators on Google Search (`google.com`, `google.co.uk`, `google.ca`, `google.com.au`), Bing (`bing.com`), and DuckDuckGo (`duckduckgo.com` and its HTML results host). Other detected Google search URLs are still excluded from ordinary URL analysis, but do not receive result indicators. Search text and result-page URLs are not sent to the URL model.
- Rates up to eight distinct result destinations at a time using `POST /api/v1/analyze/preview`. Preview calls use the same model and policy as navigation analysis, but do not create a `monitor_events`/URL audit entry for an unvisited result. The content script reads link targets only; it does not collect page text, titles, cookies, or form values.
- Shows a toolbar popup and site report with the actual returned risk level, policy decision, reasons, assessment time, and backend health. Green means the existing model and policy returned `SAFE` and `ALLOW`; it is a low-risk signal, not a guarantee. Missing or failed assessments remain Unknown/unavailable.
- For a `HIGH_RISK` assessment with policy `BLOCK`, installs a Chrome `declarativeNetRequest` rule for the assessed URL and redirects matching later navigations to an AI WatchDog warning page. If the rule cannot be installed, is disabled, or cannot safely represent a redacted path, the UI reports that enforcement is unavailable.
- Keeps at most 128 active warning rules and evicts the oldest AI WatchDog rules first; the rule and warning details are reconciled when the extension worker starts.
- Provides a persisted protection switch. Turning it off disables new checks and removes the extension's dynamic warning rules.

## First-visit timing and scope

The browser must send a URL to the local backend and wait for inference before the extension can know the policy decision. The first page can therefore begin loading before a confirmed BLOCK result exists. After that result, the extension installs a real browser redirect rule and re-navigates the current tab through it. Subsequent matching navigations are redirected before the site loads. The extension does not claim to prevent the initial request from reaching the destination.

The rule is scoped to the normalized assessed URL path. Query parameters and fragments are removed before analysis. Credentials, long opaque path segments, and paths containing common secret markers are reduced to the origin; for these redacted paths the extension does not install a rule because that could block unrelated locations or retain a secret. The first visit warning may thus be unavailable in that case.

This project has no external URL reputation provider, typo-domain protection, or browser download-content scanning. Downloads are not fetched, inspected, or changed. File Shield remains a separate local file feature. Policy outcomes other than `BLOCK` do not install a navigation rule, and there is no proceed action on a BLOCK warning.

## Permissions and privacy

The manifest requests:

- `tabs` to identify the active tab and its URL for the popup and local analysis.
- `storage` to persist the protection switch, keep current-session tab assessments, and retain sanitized details for active warning rules.
- `declarativeNetRequest` to create and remove actual browser navigation redirect rules after confirmed BLOCK decisions.
- HTTP and HTTPS host access so the browser can redirect matching navigations and run the result-link reader on supported search pages. This broad site-access permission is disclosed by Chrome/Edge when the extension is loaded. Backend requests are restricted in code to `127.0.0.1:8080` and `localhost:8080`.

Before a URL reaches Spring, the extension removes credentials, query parameters, and fragments. It reduces likely secret or opaque path segments to `/`. Search destinations are normalized in the same way. No browsing URL is sent to an external service. Local warning-rule details contain only the sanitized URL and returned evidence; they are removed when protection is turned off. Current tab assessments use browser-session storage.

## Load for development

1. Start FastAPI and Spring Boot following [the project run guide](../doc/RUNNING.md). Confirm `/api/v1/health` reports the actual Spring and ML service states.
2. In Chrome or Chromium-based Edge, open the extensions page, enable Developer mode, choose **Load unpacked**, and select this directory.
3. Approve the displayed permissions. Open a supported search page or navigate to an HTTP/HTTPS site, then open the AI WatchDog toolbar popup.

Only Chrome and Chromium-based Edge are targeted. The project does not install the extension into a browser profile. Search result selectors and the rule API are browser-version dependent; use the planned browser procedures in [testing.md](../testing.md) before relying on them.

## Backend API

- `POST /api/v1/analyze` — same existing API contract; assesses and persists an actual navigation event.
- `POST /api/v1/analyze/preview` — same response schema and model/policy path, without writing an event; intended for unvisited search destinations.
- `GET /api/v1/health` — reports Spring and FastAPI availability. A degraded response can still report Spring `UP` while ML is `DOWN`.

No API keys or optional provider configuration are required.
