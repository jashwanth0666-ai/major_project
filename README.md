# AI WatchDog

AI WatchDog is a local Windows security monitoring prototype with a JavaFX desktop UI, a Spring Boot application backend, and a Python FastAPI phishing URL model. The URL model uses the existing calibrated XGBoost artifact and threshold; this implementation does not retrain or replace it.

## Components

- `Frontend/`: JavaFX UI. It talks to Spring Boot over REST and does not access SQLite or FastAPI directly.
- `backend/`: Spring Boot REST API, URL policy, event history, file/process engines, and SQLite persistence.
- `api/` and `scripts/`: FastAPI inference service and validated model pipeline.
- `browser-extension/`: optional Chromium MV3 extension for supported search-result ratings, local URL analysis, and policy-controlled browser warning redirects.
- `data/phase4/`: calibrated model and its risk configuration.

File and process monitoring use metadata heuristics. The app records ALLOW/REVIEW/WARN/BLOCK policy results; it does not block file access or terminate processes. It is not antivirus, EDR, or a kernel monitor.

The backend also provides a read-only File Shield for SHA-256 hashing and local hash reputation checks. Configure approved scan roots before using it. Hashes absent from a reputation database are reported as UNKNOWN, not clean; an unavailable or invalid database produces LOOKUP_ERROR. File Shield scan roots, reputation database, limits, and optional real-time monitoring are configurable in JavaFX Settings and persist per user. See [backend File Shield setup](backend/RUNNING_BACKEND.md#read-only-file-shield) and [real-time monitoring configuration](backend/RUNNING_BACKEND.md#optional-real-time-file-shield-monitoring).

The local FastAPI service also provides an isolated static PE analyzer for `.exe` and `.dll` files. It requires explicitly configured approved roots, never executes analyzed files, and reports a deterministic heuristic score rather than a malware probability. See [PE analyzer configuration, API, scoring, and limits](api/PE_ANALYZER.md).

The JavaFX dashboard shows URL metrics separately from lifetime unified-assessment aggregates stored in the existing SQLite `security_events` table. The Activity view includes the latest bounded assessment history, with filters, paging, and structured source details. Assessment metrics remain unavailable when their API request fails; unavailable is not presented as zero. See [unified assessment and dashboard behavior](backend/THREAT_ASSESSMENTS.md) and the [desktop guide](Frontend/README.md).

When the Windows notification area is available, the JavaFX app can minimize to tray, open the alert history, and show user-configurable notifications for newly observed WARN/BLOCK policy events. Notification preferences are served by loopback `GET/PUT /api/v1/notifications/preferences` and saved under `%APPDATA%/AIWatchDog/notification-preferences.json`. Optional Defender telemetry, bounded script analysis, and Windows process correlation are independently configured in Settings and are off by default. Script/process event collection requires relevant Windows logging to be enabled and readable; AI WatchDog does not alter those policies. No startup task, Windows service, OS blocking, quarantine, or process enforcement is installed by the current app. Planned acceptance procedures and their not-yet-run status are in [testing.md](testing.md).

## Start on Windows

Prerequisites: Python with dependencies from `requirements-api.txt`, Java 21 for Spring Boot, Java 17 or newer for JavaFX, and Maven for the desktop build.

Run `start-aiwatchdog.bat` from the repository root. It starts FastAPI, waits for model health, starts Spring Boot, waits for backend and ML health, then starts JavaFX. Each service has its own visible console; use Ctrl+C in each to stop it.

For manual startup, see [doc/RUNNING.md](doc/RUNNING.md) and [backend/RUNNING_BACKEND.md](backend/RUNNING_BACKEND.md). For monitor configuration, data handling, and limitations, see [backend/MONITORING.md](backend/MONITORING.md).

The optional Chrome/Edge browser extension distinguishes search pages from destinations, rates supported search results through a non-persisting preview API, and can install a real browser redirect rule after a `HIGH_RISK` plus `BLOCK` decision. The first visit may begin loading before local inference finishes. The extension has no reputation feed, typo-domain protection, or browser download scanning. Review its [permissions and limitations](browser-extension/README.md) and [flow](browser-extension/ARCHITECTURE.md) before loading it.

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
cd scripts
..\.venv\Scripts\python.exe -m unittest test_phase5_feature_parity -v
```

For acceptance details, see the [implementation report](doc/AI_WatchDog_COMPLETE_IMPLEMENTATION_REPORT.md), [current system audit](doc/AI_WatchDog_Current_System_Audit.md), and [final acceptance report](doc/AI_WatchDog_FINAL_ACCEPTANCE_REPORT.md).

For JavaFX screen details and UI verification, see the [UI audit](doc/AI_WatchDog_UI_AUDIT.md) and [UI implementation report](doc/AI_WatchDog_UI_IMPLEMENTATION_REPORT.md).
