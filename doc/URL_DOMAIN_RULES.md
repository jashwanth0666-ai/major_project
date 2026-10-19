# Local URL domain rules

AI WatchDog supports operator-configured hostname rules. Entries in the Secure Access page are stored in SQLite and apply immediately; environment-configured rules load when Spring starts:

- `AI_WATCHDOG_URL_DENYLIST` — exact normalized hostnames that force a `BLOCK` policy verdict.
- `AI_WATCHDOG_URL_ALLOWLIST` — exact normalized hostnames that skip URL-model inference. Independent reputation, denylist, hostname, redirect, and browser-page checks still apply.

Separate entries with commas, semicolons, or newlines. Unicode domain names are normalized to ASCII IDN form. Wildcards, paths, ports, and URL schemes are rejected. Matching is exact-host only, so `example.com` does not match `sub.example.com`. A matching denylist entry takes precedence if the same host appears in both lists. The assessment includes only the matching host and action under `sources.localDomainRule`, not the full configured lists.

For example, configure `AI_WATCHDOG_URL_DENYLIST=phishing.example,evil.test` before starting the backend. Entries added or removed in Secure Access are stored in SQLite and take effect on the next assessment without restarting the backend. Environment-configured entries are loaded at backend startup. After removing a deny entry, turn extension protection off and back on to remove already-installed browser rules before relying on the new list. Keep these settings operator-controlled and use reviewed, maintained domain data; an incorrect denylist entry causes the assessment policy to return `BLOCK` for that host.

When the browser extension receives a denylist `BLOCK`, it installs a host-wide redirect rule for that exact hostname. As with model-based blocking, the first request can begin before assessment finishes. Extension protection must be enabled, and browser rule installation can fail; the UI reports the applied state.

The extension reads current allowlist entries through its read-only API scope on startup, when its popup is opened, and periodically while running. It removes stale model-only warning rules for newly excepted hosts and rechecks open tabs. Independent denylist and strong reputation or hostname evidence can still block an allowlisted host.
