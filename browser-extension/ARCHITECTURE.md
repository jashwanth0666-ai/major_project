# Browser protection flow

```text
Active HTTP(S) navigation
  -> MV3 service worker removes credentials, query, fragment, and sensitive path segments; observes up to six main-frame redirect hostnames
  -> POST /api/v1/threat-assessments/url
  -> Spring validation -> existing FastAPI URL model -> existing Spring PolicyEngine; intermediate redirect hosts receive local deception checks
  -> local domain rules + hostname heuristics + optional hostname reputation -> audit logger -> unified assessment response
  -> extension session cache -> popup/report
  -> report retrieves the persisted redacted assessment by assessment ID; HIGH_RISK + BLOCK may install a dynamic browser navigation redirect rule

Supported search results page
  -> content script reads a bounded set of result hrefs only
  -> service worker validates supported search-page sender and sanitizes each destination
  -> bounded POST /api/v1/threat-assessments/url/preview requests
  -> same model, policy, hostname heuristics, and optional reputation; no audit logger call
  -> small evidence-based result labels or Unknown
```

The backend preview operation shares URL validation, ML inference, policy evaluation, and supplemental URL evidence with the persisted navigation operation. Only the audit write differs. The legacy `/api/v1/analyze` routes remain available to other local clients. No new model, prediction threshold, or policy mapping is introduced.

The content script is limited to Google Search, Bing, and DuckDuckGo result pages listed in the manifest. It extracts link targets and does not send search terms, page titles, or page text. Requests are bounded to eight destinations per batch, three concurrent requests, a 12 second request timeout, and a five minute in-memory result cache.

The extension installs a DNR redirect rule for an actual `HIGH_RISK` plus `BLOCK` result or a configured exact-host denylist `BLOCK`. Model rules match the normalized assessed URL path; denylist rules match that exact hostname across paths. Since local inference is asynchronous, the first request may already have reached the destination before the extension installs the rule and sends the current tab through it. If rule creation fails or the path was redacted, the extension keeps the true assessment and reports enforcement as unavailable. It retains at most 128 active warning rules and removes the oldest one when adding a new unique rule. A paused protection switch removes rules in the extension-owned ID range.

The popup reads `GET /api/v1/health` and shows each reported service independently. Search previews do not create desktop audit-history rows or trigger the existing JavaFX notification path. Actual navigations continue using the existing persistence and notification integration.

Redirect observation uses the browser's `webNavigation` events for the main frame only. The extension sends at most six hostnames to loopback Spring; it does not send redirect paths, queries, fragments, or credentials. A cross-host redirect sequence is shown in the site report and assessment evidence. Redirects alone do not raise the verdict, but high-severity deception signals on an intermediate host can raise policy to WARN; a BLOCK still requires the model score to meet its configured threshold. First-visit assessment remains asynchronous, so this evidence does not prevent the initial navigation from reaching its destination.

## Data handling

The service worker sends requests only to loopback Spring URLs. The extension strips credentials, all query parameters, fragments, and likely secret/opaque path segments. The current session's tab assessments are held in `chrome.storage.session`; sanitized evidence for confirmed dynamic warning rules is in `chrome.storage.local` so the interstitial remains informative after a service-worker restart. Turning protection off removes these persisted warning details and all dynamic warning rules.

URL reputation is optional and disabled by default; hostname heuristic coverage is limited and is not comprehensive typo-domain or visual similarity protection. Browser download-content analysis is not integrated. The extension does not execute or fetch files and does not automatically proceed through a BLOCK decision.
