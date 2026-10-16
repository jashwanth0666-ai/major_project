# Browser protection flow

```text
Active HTTP(S) navigation
  -> MV3 service worker removes credentials, query, fragment, and sensitive path segments
  -> POST /api/v1/analyze
  -> Spring validation -> existing FastAPI URL model -> existing Spring PolicyEngine
  -> existing URL event logger -> assessment response
  -> popup/report; HIGH_RISK + BLOCK may install a dynamic browser navigation redirect rule

Supported search results page
  -> content script reads a bounded set of result hrefs only
  -> service worker validates supported search-page sender and sanitizes each destination
  -> bounded POST /api/v1/analyze/preview requests
  -> same FastAPI model and PolicyEngine; no event logger call
  -> small evidence-based result labels or Unknown
```

The backend preview operation shares URL validation, ML inference, and policy evaluation with the persisted navigation operation. Only the final event-logger call differs. No new model, prediction threshold, policy mapping, SQLite table, or reputation provider is introduced.

The content script is limited to Google Search, Bing, and DuckDuckGo result pages listed in the manifest. It extracts link targets and does not send search terms, page titles, or page text. Requests are bounded to eight destinations per batch, three concurrent requests, a 12 second request timeout, and a five minute in-memory result cache.

The extension installs a DNR redirect rule only for an actual `HIGH_RISK` plus `BLOCK` result. The rule matches the normalized assessed URL path for main-frame navigation. Since local inference is asynchronous, the first request may already have reached the destination before the extension installs the rule and sends the current tab through it. If rule creation fails or the path was redacted, the extension keeps the true assessment and reports enforcement as unavailable. It retains at most 128 active warning rules and removes the oldest one when adding a new unique rule. A paused protection switch removes rules in the extension-owned ID range.

The popup reads `GET /api/v1/health` and shows each reported service independently. Search previews do not create desktop audit-history rows or trigger the existing JavaFX notification path. Actual navigations continue using the existing persistence and notification integration.

## Data handling

The service worker sends requests only to loopback Spring URLs. The extension strips credentials, all query parameters, fragments, and likely secret/opaque path segments. The current session's tab assessments are held in `chrome.storage.session`; sanitized evidence for confirmed dynamic warning rules is in `chrome.storage.local` so the interstitial remains informative after a service-worker restart. Turning protection off removes these persisted warning details and all dynamic warning rules.

Threat intelligence, typo-domain protection, and browser download-content analysis are not integrated. The extension does not execute or fetch files and does not automatically proceed through a BLOCK decision.
