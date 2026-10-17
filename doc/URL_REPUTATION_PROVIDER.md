# URL reputation provider contract

AI WatchDog can query one operator-configured URL reputation service. It is disabled unless `AI_WATCHDOG_URL_REPUTATION_ENABLED=true` and a valid HTTPS endpoint is configured. This is a generic adapter contract; it does not imply compatibility with Google Safe Browsing, VirusTotal, or another vendor.

## Request

The backend sends a `POST` to the configured endpoint with `Content-Type: application/json` and a body containing only the normalized ASCII hostname:

```json
{"host":"example.com"}
```

It does not send URL paths, query strings, fragments, page contents, or credentials. If configured, the API key is sent in the `X-Api-Key` header. The endpoint must use HTTPS. Redirects are not followed.

## Response

A successful response is JSON with a `reputation` value from `KNOWN_MALICIOUS`, `KNOWN_CLEAN`, `SUSPICIOUS`, or `UNKNOWN`. `observed_at` is optional and, when present, must be an ISO-8601 instant.

```json
{"reputation":"SUSPICIOUS","observed_at":"2026-10-17T10:00:00Z"}
```

HTTP 404 or 204 means `UNKNOWN`. Timeouts, rate limits, invalid data, and other unsuccessful responses mean `UNAVAILABLE`. These states appear in `sources.urlReputation`; they do not become a clean verdict. A reputation observation is supplementary evidence and currently does not change the existing model-derived policy verdict. The response includes provider name, checked time, provider observation time when supplied, and cache age for cached entries. Cached entries live for five minutes. The backend limits uncached lookups to 30 per minute by default; configure `ai-watchdog.url-reputation.requests-per-minute` to change the limit.

## Configuration

Set these environment variables for the backend process:

- `AI_WATCHDOG_URL_REPUTATION_ENABLED` — opt-in switch, default `false`.
- `AI_WATCHDOG_URL_REPUTATION_ENDPOINT` — HTTPS endpoint implementing the contract above.
- `AI_WATCHDOG_URL_REPUTATION_API_KEY` — optional provider credential; never place it in source control.
- `AI_WATCHDOG_URL_REPUTATION_PROVIDER` — display name for provenance.

The provider should support rate limiting and return truthful timestamps. Keep outbound firewall rules limited to the configured provider. Provider failures make the assessment `PARTIAL` while preserving the model's existing verdict.
