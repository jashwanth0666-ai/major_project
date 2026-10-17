# Local URL domain rules

AI WatchDog supports optional operator-configured hostname lists loaded when Spring starts:

- `AI_WATCHDOG_URL_DENYLIST` — exact normalized hostnames that force a `BLOCK` policy verdict.
- `AI_WATCHDOG_URL_ALLOWLIST` — exact normalized hostnames recorded as `ALLOWLIST_EVIDENCE`; they never override model, reputation, denylist, or heuristic evidence.

Separate entries with commas, semicolons, or newlines. Unicode domain names are normalized to ASCII IDN form. Wildcards, paths, ports, and URL schemes are rejected. Matching is exact-host only, so `example.com` does not match `sub.example.com`. A matching denylist entry takes precedence if the same host appears in both lists. The assessment includes only the matching host and action under `sources.localDomainRule`, not the full configured lists.

For example, configure `AI_WATCHDOG_URL_DENYLIST=phishing.example,evil.test` before starting the backend. Rule changes require a backend restart. After removing a deny entry, turn extension protection off and back on to remove already-installed browser rules before relying on the new list. Keep these settings operator-controlled and use reviewed, maintained domain data; an incorrect denylist entry causes the assessment policy to return `BLOCK` for that host.

When the browser extension receives a denylist `BLOCK`, it installs a host-wide redirect rule for that exact hostname. As with model-based blocking, the first request can begin before assessment finishes. Extension protection must be enabled, and browser rule installation can fail; the UI reports the applied state.
