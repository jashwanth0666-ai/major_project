# Policy Engine

The policy engine is an independently testable Spring Boot component. It accepts the values already produced by the ML and Risk Engine layers and maps the supplied `risk_level` to a decision.

## Endpoint

`POST /api/policy/evaluate`

The request requires:

- `url`
- `phishing_probability` from `0.0` through `1.0`
- `risk_score` from `0` through `100`
- `risk_level`: `SAFE`, `LOW_RISK` or `LOW RISK`, `SUSPICIOUS`, `HIGH_RISK` or `HIGH RISK`
- `prediction`: `BENIGN` or `PHISHING`

Risk levels are normalized case-insensitively and with surrounding whitespace removed. Decisions are based only on `risk_level`:

| Risk level   | Decision |
| ------------ | -------- |
| `SAFE`       | `ALLOW`  |
| `LOW_RISK`   | `REVIEW` |
| `SUSPICIOUS` | `WARN`   |
| `HIGH_RISK`  | `BLOCK`  |

Invalid or missing values return HTTP 400. Invalid input is never converted to `ALLOW`. The policy engine does not use or modify the ML threshold.

## Example

PowerShell:

```powershell
$body = '{"url":"https://example.com/login","phishing_probability":0.998925,"risk_score":100,"risk_level":"HIGH_RISK","prediction":"PHISHING"}'
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/policy/evaluate -ContentType 'application/json' -Body $body
```

Response:

```json
{
  "url": "https://example.com/login",
  "phishing_probability": 0.998925,
  "risk_score": 100,
  "risk_level": "HIGH_RISK",
  "prediction": "PHISHING",
  "decision": "BLOCK"
}
```

Run the complete backend test suite from `backend` with `./mvnw test` or `./mvnw.cmd test` on Windows.
