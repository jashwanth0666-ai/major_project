# AI WatchDog Current System Audit

**Audit date:** 2026-10-18
**Repository:** `jashwanth0666-ai/major_project`
**Scope:** Current checked-out repository after the runtime and ML-model
directory restructuring.

## Executive summary

AI WatchDog is a local Windows security-monitoring prototype composed of:

1. A Python/FastAPI service for calibrated phishing URL inference and bounded
   static PE analysis.
2. A Java/Spring Boot backend for unified assessment, policy decisions,
   persistence, monitoring, File Shield, local authentication, and optional
   provider integrations.
3. A JavaFX desktop application for configuration, assessment history,
   monitoring, notifications, and File Shield operations.
4. An optional Chromium Manifest V3 browser extension for navigation assessment,
   search-result previews, local warnings, and policy-controlled redirects.

The system is designed for local loopback operation. It is not an antivirus,
EDR, kernel monitor, sandbox, or guarantee of protection.

## Current repository layout

```text
major_project/
├── api/
│   ├── server.py
│   ├── config.py
│   ├── integrity.py
│   ├── inference/
│   │   └── detector.py
│   └── pe_analyzer/
├── backend/
├── Frontend/
├── browser-extension/
├── ml_model/
│   └── phase4/
│       ├── xgboost_calibrated.joblib
│       ├── risk_engine_config.json
│       └── Phase 4 evidence files
├── tests/
├── doc/
├── requirements-api.txt
├── run-aiwatchdog-ml.bat
├── start-aiwatchdog.bat
└── setup-local-auth.ps1
```

The former `data/phase4/` directory has been renamed to
`ml_model/phase4/`. The model artifact was not regenerated or modified.

## Feature status

### Python FastAPI service

| Feature | Status | Current behavior |
| --- | --- | --- |
| Calibrated phishing URL inference | Implemented | Loads the approved XGBoost/isotonic artifact and returns probability, risk score, risk level, prediction, threshold, and rule-based reasons. |
| URL feature extraction | Implemented | Preserves the 25-feature Phase 4 ordering and float32 model input. |
| Model integrity verification | Implemented | SHA-256 is checked before model loading; missing or mismatched artifacts fail closed. |
| Local service authentication | Implemented | Protected endpoints require the Spring-to-ML bearer credential. |
| Health/readiness reporting | Implemented | `/health` reports model readiness, integrity status, authentication readiness, and the verified hash. |
| Single URL CLI inference | Implemented | `python -m api.inference.detector URL` |
| CSV batch inference | Implemented | `python -m api.inference.detector --batch INPUT.csv --output OUTPUT.csv` |
| Static PE analysis | Implemented | Bounded, non-executing `.exe`/`.dll` parsing with SHA-256, metadata, imports, anomalies, and heuristic scoring. |
| Approved-root enforcement | Implemented | PE analysis requires explicitly configured roots and rejects traversal and root escapes. |
| External network inference | Not used | Base URL inference is deterministic and local. |
| LLM explanations | Not implemented | Architecture leaves room for an optional explanation service, but none is active. |

### Spring Boot backend

| Feature | Status | Current behavior |
| --- | --- | --- |
| URL analysis API | Implemented | Receives local client requests and calls the FastAPI model service. |
| Unified threat assessment | Implemented | Combines model output with policy, optional reputation, hostname signals, and evidence. |
| Preview assessment | Implemented | Supports non-persisting assessment for browser search-result previews. |
| Policy decisions | Implemented | Produces ALLOW, REVIEW, WARN, or BLOCK outcomes according to configured evidence and thresholds. |
| Local API authentication | Implemented | Per-user bearer credentials protect backend routes. |
| SQLite persistence | Implemented | Stores URL/security assessment history and local configuration data. |
| File Shield | Implemented | Bounded file hashing, signature inspection, local hash reputation, scan roots, and explicit quarantine/restore operations. |
| File monitoring | Implemented, optional | Recursive monitoring is configurable and disabled by default. |
| Windows script telemetry | Implemented, optional | Requires relevant Windows logging and permissions; disabled by default. |
| Windows process telemetry | Implemented, optional | Uses available Windows security events; disabled by default. |
| External URL reputation | Implemented, optional | Hostname-only HTTPS provider integration; disabled by default. |
| External file threat intelligence | Implemented, optional | Hash-only provider integration with timeout, cache, and rate limits; disabled by default. |

### JavaFX desktop

| Feature | Status |
| --- | --- |
| Dashboard and URL assessment | Implemented |
| Backend health and degraded-state display | Implemented |
| Assessment history and filters | Implemented |
| Settings for monitoring, scan roots, limits, providers, and notifications | Implemented |
| File Shield operations | Implemented |
| Windows notification-area behavior | Implemented where the environment supports it |
| Direct FastAPI or SQLite access | Not used; the desktop communicates through Spring Boot |

### Browser extension

| Feature | Status |
| --- | --- |
| Manifest V3 Chromium extension | Implemented |
| Navigation assessment after page navigation | Implemented |
| Supported Google, Bing, and DuckDuckGo result previews | Implemented |
| URL sanitization before backend submission | Implemented |
| Local toolbar popup and site report | Implemented |
| Dynamic warning redirects for confirmed HIGH_RISK/BLOCK | Implemented |
| Protection on/off switch and warning-rule reconciliation | Implemented |
| First-request blocking before navigation | Not guaranteed; the first page may begin loading before assessment completes |
| Download-content scanning | Not implemented |
| Page text, cookies, or form-value collection | Not performed |

## API surface

### FastAPI service

- `GET /health`
- `GET /auth-check`
- `POST /predict`
- `POST /api/analyze-file`

### Spring Boot service

The backend provides health, URL analysis, unified threat-assessment,
policy, notification, monitoring, and File Shield routes. The authoritative
route definitions are under `backend/src/main/java/`.

The browser-facing routes include:

- `POST /api/v1/threat-assessments/url`
- `POST /api/v1/threat-assessments/url/preview`
- `POST /api/v1/analyze`
- `POST /api/v1/analyze/preview`
- `GET /api/v1/health`

## Security and privacy posture

- Services bind to loopback by default.
- Credentials are generated and stored under the current user's
  `%APPDATA%\AIWatchDog\auth` directory.
- Credential files receive restrictive Windows ACLs.
- The FastAPI model is verified before loading.
- PE analysis never executes analyzed files.
- PE analysis returns basenames and structured results rather than echoing
  arbitrary local paths in response bodies.
- Browser URLs are sanitized before local backend submission.
- Optional providers are disabled unless explicitly configured.
- The extension sends only the normalized hostname to an optional URL reputation
  provider.
- The extension does not collect page content, cookies, or form values.
- Local databases and credentials are excluded from version control.

## Model and configuration status

| Item | Current value |
| --- | --- |
| Model path | `ml_model/phase4/xgboost_calibrated.joblib` |
| Risk configuration | `ml_model/phase4/risk_engine_config.json` |
| Inference threshold | `0.15` |
| Feature count | 25 |
| Model SHA-256 | `b46d8ae98125357a349bc308a9e839a2b1804b2e6bc291931aa72c1e358d69b7` |
| Model replacement/retraining in this audit | None |
| Default FastAPI bind | `127.0.0.1:8000` |
| Default backend bind | `127.0.0.1:8080` |

## Validation status

The following checks have been executed for the current architecture:

| Validation | Result |
| --- | --- |
| Python diagnostics for changed modules | Passed |
| Python API and PE analyzer tests | Passed: 14 tests; 1 platform-dependent symlink test skipped |
| Model SHA-256 verification and load | Passed |
| Representative before/after detector comparison | Passed; outputs were identical |
| FastAPI OpenAPI route check | Passed |
| Detector CLI check | Passed |
| Browser-extension tests | Passed: 6 tests |
| JavaFX Maven tests | Passed: 9 tests |
| Backend Maven suite | Two existing File Shield tests failed in the audited environment; unrelated to the path refactor |
| Windows full multi-process launch | Not run during this audit |

## Known limitations and risks

1. The first browser navigation can begin before a remote/local assessment
   returns.
2. The model is a URL-risk classifier, not a malware detector or browser
   sandbox.
3. PE scoring is heuristic and not a calibrated malware probability.
4. Browser download scanning is not implemented.
5. Optional reputation and threat-intelligence providers depend on operator
   configuration, provider availability, credentials, timeouts, and rate limits.
6. Windows telemetry depends on local audit policy, permissions, and event
   availability.
7. The repository contains runtime model assets but no tracked training or
   enterprise evaluation `scripts/` directory.
8. Full Windows startup, browser loading, notification-area behavior, and
   provider integrations require manual environment-specific verification.

## Recommended next actions

1. Resolve the two existing backend File Shield test failures and rerun the
   complete backend suite.
2. Run the Windows launch sequence using
   [`start-aiwatchdog.bat`](../start-aiwatchdog.bat).
3. Verify the model health response and authenticated prediction request.
4. Execute the manual browser-extension procedures in
   [`testing.md`](../testing.md).
5. If training or evaluation workflows are restored, place them under a
   dedicated `ml/` hierarchy and keep them separate from runtime inference.
6. Add optional LLM explanations or threat-intelligence integrations only
   behind explicit feature flags, bounded timeouts, and failure-safe behavior.

## Related documentation

- [Architecture](ARCHITECTURE.md)
- [Repository restructure plan](REPOSITORY_RESTRUCTURE_PLAN.md)
- [Windows run guide](../RUNNING.md)
- [PE analyzer documentation](../api/PE_ANALYZER.md)
- [Browser extension documentation](../browser-extension/README.md)
- [Testing plan](../testing.md)
