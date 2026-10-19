# AI WatchDog

AI WatchDog is a local Windows security monitoring prototype with a JavaFX desktop UI, a Spring Boot application backend, and a Python FastAPI phishing URL model. The URL model uses the existing calibrated XGBoost artifact and threshold; this implementation does not retrain or replace it.

Production inference sends only the normalized scheme and hostname to the model. The desktop result displays the full URL submitted by the user, while audit history continues to store a sanitized URL. The 0.31 threshold and calibrated model artifact are unchanged. The evaluation workflow still compares full-URL, sanitized-path, and host-only representations for future model decisions.

## Components

- `Frontend/`: JavaFX UI. It talks to Spring Boot over REST and does not access SQLite or FastAPI directly.
- `backend/`: Spring Boot REST API, URL policy, event history, file/process engines, and SQLite persistence.
- `api/`: FastAPI inference service, runtime URL inference, and PE analysis.
- `browser-extension/`: optional Chromium MV3 extension for supported search-result ratings, local URL analysis, and policy-controlled browser warning redirects.
- `ml_model/phase4/`: calibrated model and its risk configuration.

File and process monitoring use metadata heuristics. The app records ALLOW/REVIEW/WARN/BLOCK policy results; it does not block file access or terminate processes. It is not antivirus, EDR, or a kernel monitor.

The backend also provides File Shield for SHA-256 hashing, signature inspection, local hash reputation checks, and explicitly confirmed quarantine/restore. Approved scan roots are empty on a clean install and must be configured before scanning. Hashes absent from a reputation database are reported as UNKNOWN, not clean; an unavailable or invalid database produces LOOKUP_ERROR. File Shield scan roots, reputation database, limits, and optional real-time monitoring are configurable in JavaFX Settings and persist per user. See [backend File Shield setup](backend/RUNNING_BACKEND.md#read-only-file-shield) and [real-time monitoring configuration](backend/RUNNING_BACKEND.md#optional-real-time-file-shield-monitoring).

The local FastAPI service also provides an isolated static PE analyzer for `.exe` and `.dll` files. It requires explicitly configured approved roots, never executes analyzed files, and reports a deterministic heuristic score rather than a malware probability. See [PE analyzer configuration, API, scoring, and limits](api/PE_ANALYZER.md).

The JavaFX dashboard shows URL metrics separately from lifetime unified-assessment aggregates stored in the existing SQLite `security_events` table. The Activity view includes the latest bounded assessment history, with filters, paging, and structured source details. Assessment metrics remain unavailable when their API request fails; unavailable is not presented as zero. See [unified assessment and dashboard behavior](backend/THREAT_ASSESSMENTS.md) and the [desktop guide](Frontend/README.md).

When the Windows notification area is available, the JavaFX app can minimize to tray, open the alert history, and show user-configurable notifications for newly observed WARN/BLOCK policy events. Notification preferences are served by loopback `GET/PUT /api/v1/notifications/preferences` and saved under `%APPDATA%/AIWatchDog/notification-preferences.json`. Optional Defender telemetry, bounded script analysis, and Windows process correlation are independently configured in Settings and are off by default. Script/process event collection requires relevant Windows logging to be enabled and readable; AI WatchDog does not alter those policies. File quarantine is a separate, explicit user-confirmed operation. The app does not install a startup task or Windows service, terminate processes, or enforce file/process policy at the OS level. Planned acceptance procedures and their not-yet-run status are in [testing.md](testing.md).

Local API routes now require per-user bearer credentials, with a narrower extension token for URL analysis. The root launch scripts initialize the credentials under `%APPDATA%\AIWatchDog\auth`; configure the extension token in its Options page. See [local API credential setup and limits](doc/RUNNING.md#local-api-credentials).

## Start on Windows

For the code-grounded capability gap assessment and prioritized enterprise development plan, see [doc/ENTERPRISE_SECURITY_ROADMAP.md](doc/ENTERPRISE_SECURITY_ROADMAP.md).

Prerequisites: Python with dependencies from `requirements-api.txt`, Java 21 for Spring Boot, Java 17 or newer for JavaFX, and Maven for the desktop build.

Run `start-aiwatchdog.bat` from the repository root. It starts FastAPI, waits for model health, starts Spring Boot, waits for backend and ML health, then starts JavaFX. Each service has its own visible console; use Ctrl+C in each to stop it.

For manual startup, see [doc/RUNNING.md](doc/RUNNING.md) and [backend/RUNNING_BACKEND.md](backend/RUNNING_BACKEND.md). For monitor configuration, data handling, and limitations, see [backend/MONITORING.md](backend/MONITORING.md).

The optional Chrome/Edge browser extension distinguishes search pages from destinations, assesses visits and search previews through the same unified evidence path, and can install browser redirect rules after a `HIGH_RISK` plus `BLOCK` decision or an exact-host local denylist match. The first visit may begin loading before local inference finishes. Optional hostname reputation is disabled by default; local hostname heuristics provide limited indicators, not comprehensive typo-domain protection. Browser download scanning is not implemented. Review its [permissions and limitations](browser-extension/README.md), [domain rule configuration](doc/URL_DOMAIN_RULES.md), and [flow](browser-extension/ARCHITECTURE.md) before loading it.

Optional cloud explanations are disabled by default and are documented in
[doc/LLM_EXPLANATIONS.md](doc/LLM_EXPLANATIONS.md). They explain existing
evidence only and never replace the model or policy decision. Copy
[.env.example](.env.example) to a local `.env` for configuration; never commit
the local file or an API key.

The frozen URL model has a reproducible full-split evaluation workflow at [PHISHING_EVALUATION.md](doc/PHISHING_EVALUATION.md). It reports held-out and unseen-domain metrics and review queues; temporal evaluation remains unavailable until reliable timestamps and label-time provenance exist.

## Existing verification commands

The test plan in [testing.md](testing.md) documents the acceptance cases. The attached implementation directive required that no tests, builds, benchmarks, or validation commands be executed during this work; no new test results are claimed here.

Backend tests:

```powershell
cd backend
.\mvnw.cmd test
```

Desktop tests/build:

```powershell
cd Frontend
mvn test
```

Python model feature parity test:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

For acceptance details, see the [implementation report](doc/AI_WatchDog_COMPLETE_IMPLEMENTATION_REPORT.md), [current system audit](doc/AI_WatchDog_Current_System_Audit.md), and [final acceptance report](doc/AI_WatchDog_FINAL_ACCEPTANCE_REPORT.md).

For JavaFX screen details and UI verification, see the [UI audit](doc/AI_WatchDog_UI_AUDIT.md) and [UI implementation report](doc/AI_WatchDog_UI_IMPLEMENTATION_REPORT.md).
