# AI WatchDog Implementation & Verification Guide

Updated: 2026-10-01. This guide describes the current implementation and labels unverified capabilities explicitly. For final acceptance results, see [AI_WatchDog_FINAL_ACCEPTANCE_REPORT.md](AI_WatchDog_FINAL_ACCEPTANCE_REPORT.md). The system is a local monitoring prototype, not a full antivirus/EDR product.

## 1. Executive Summary

The existing URL inference and Spring backend foundation was preserved. The URL path now has verified Spring-to-FastAPI-to-policy-to-SQLite-to-history behavior. JavaFX reads audit history from Spring and includes risk/decision filters. File and process metadata monitors submit events to separate Spring engines, heuristic risk assessment, policy, and SQLite. A Chromium extension source provides sanitized active-tab URL submission. Current verification is summarized in the [final acceptance report](AI_WatchDog_FINAL_ACCEPTANCE_REPORT.md).

The project remains **partially complete** against the supplied target: the browser extension is not installed, JavaFX screen behavior was not visually inspected, and file/process decisions are recorded but not enforced by Windows.

## 2. Target Architecture

Windows browser, file, and process sources feed the Spring Boot security path. URL events use the validated Python model/risk result. File/process events use Java metadata rules. Both paths pass through Java policy and write to local SQLite. JavaFX retrieves events from Spring.

## 3. Existing Components Reused

- FastAPI URL inference service and checksum-verified calibrated XGBoost model.
- Established URL feature extraction, threshold 0.15, score and risk bands.
- Spring Boot URL orchestration and ML client.
- Java policy mapping including REVIEW for LOW_RISK.
- URL V1 event schema and JavaFX desktop project.
- Existing risk/policy/logger tests and Python feature parity suite.

## 4. Components Added

- Configurable shared SQLite path for URL logger and repository.
- URL audit URL sanitizer.
- JavaFX REST event-history retrieval and risk/decision filters.
- Monitor Event API, file/process event models, and separate `monitor_events` table.
- File Engine, Process Engine, heuristic Risk Engine, and shared Policy Engine routing.
- Java NIO configured-directory watcher and ProcessHandle poller.
- Chromium Manifest V3 active-tab provider source and sanitization tests.
- `start-aiwatchdog.bat` and concise run/monitor documentation.
- Unit and integration tests for monitor engines, persistence, watcher, process monitor, URL privacy, and browser sanitation.

## 5. Components Modified

- Spring URL logger uses the configured database path and canonicalizes persisted labels.
- URL analysis persists sanitized audit URLs while preserving the full submitted URL for inference.
- Spring binds to loopback by default.
- JavaFX controller starts/stops monitors with the application lifecycle and loads combined history.
- Root and frontend READMEs describe the actual JavaFX/Spring/FastAPI implementation and its limits.

## 6. Final Architecture

```text
Browser extension -> Spring URL API -> FastAPI model/risk -> Policy -> URL audit table
File watcher ------> Spring monitor API -> File Engine --+
Process poller ----> Spring monitor API -> Process Engine +-> Heuristic Risk -> Policy
                                                               -> Monitor event table
URL + monitor history <- Spring REST <- SQLite <- JavaFX Activity/Threat pages
```

## 7. Data Flow

URL: JavaFX or the optional extension submits a URL to Spring. Spring validates it, calls FastAPI, applies the existing policy mapping, writes a sanitized audit URL, and returns the model result.

File/process: JavaFX observers submit event type, action, basename, and limited numeric metadata to Spring. The appropriate engine emits signals, the heuristic risk engine maps those to a risk level, policy maps the level to a decision, and SQLite stores the result.

## 8. ML System

The validated Python/FastAPI pipeline remains in place. No retraining or threshold change was made. The artifact reports scikit-learn 1.8.0; `requirements-api.txt` now pins 1.8.0 and the local runtime was aligned. Live `/health` verified the configured artifact hash; `/predict` for `https://example.com` returned SAFE with score 0 and threshold 0.15 without the prior version-mismatch warning.

## 9. Spring Boot Backend

Spring Boot remains the main application backend and binds to `127.0.0.1`. Existing URL analyze, health, and policy routes remain. New monitor event routes accept/retrieve file/process metadata. ML connect/read timeouts remain configured.

## 10. Policy Engine

The V1 mapping is unchanged: SAFE -> ALLOW, LOW_RISK -> REVIEW, SUSPICIOUS -> WARN, HIGH_RISK -> BLOCK. Monitor analyses pass only the resulting risk level into policy; the policy engine does not recalculate risk.

## 11. Security Engine

Monitor event orchestration selects the File Engine or Process Engine, requests a risk assessment, applies policy, and persists the result. Monitors themselves do not make final decisions.

## 12. URL Engine

The existing Spring `AnalysisService` remains the URL engine. It validates HTTP/HTTPS URLs and coordinates FastAPI, policy, and logging. Audit persistence removes userinfo, query, fragment, and likely credential/opaque-token path segments. Inference still receives the submitted URL.

## 13. Browser Monitor

`browser-extension/` contains the provider for Chrome and Chromium-based Edge. It observes active-tab HTTP/HTTPS URLs, strips credentials/query/fragment and likely secret path segments, debounces, and submits only to local Spring. It does not read page contents or block navigation. User installation and browser permission behavior are unverified.

## 14. File Engine

The File Engine classifies file creation/modification/rename metadata by extension. Executable/script suffixes receive a high heuristic score; selected macro/image formats receive a suspicious score. It never reads file content.

## 15. File Monitor

Java NIO WatchService monitors existing subdirectories under configured user roots and registers newly created directories. It debounces and sends basename plus file size only. Same-folder delete/create within two seconds is treated as a probable rename. Rename inference is best effort.

## 16. Process Engine

The Process Engine checks an executable basename and action. A small dual-use Windows utility list receives a suspicious heuristic result. No arguments, memory, signatures, or behavior are inspected.

## 17. Process Monitor

Java ProcessHandle polling detects new process IDs at a default two-second interval. It records executable basename and PID. It does not terminate processes. Visibility can vary for protected processes.

## 18. Risk Engine

The URL risk result remains in Python. File/process metadata passes through a distinct Java heuristic Risk Engine using the canonical score bands. A SAFE rule match is not proof that a file/process is safe; a suspicious extension/name is not a malware verdict.

## 19. Security Event Logger

The URL logger validates values, normalizes risk/prediction/decision labels, and uses prepared statements. The monitor event repository also uses prepared statements. Both use `ai-watchdog.security.db-path`.

## 20. SQLite

The URL V1 `security_events` schema remains unchanged. The additive `monitor_events` table stores event type/action, basename, PID/size, risk score/level, decision, and reasons. Customized-path URL round trip and monitor repository persistence were verified.

## 21. JavaFX Dashboard

JavaFX uses Spring REST for URL analysis and event history. It combines URL and monitor records, refreshes asynchronously, and filters by risk and decision. Protection setup starts the file and process services; application shutdown closes them. JavaFX built and tests passed, but visual interaction was unavailable for inspection.

## 22. Security Controls

Loopback binding, pinned model checksum, API timeouts, URL audit redaction, browser URL sanitation, basename-only file/process metadata, no command-line capture, prepared SQL statements, bounded asynchronous event queues, and non-admin monitoring defaults are present. Services have no authentication and are intended for local use only.

## 23. API Endpoints

- FastAPI: `GET /health`, `POST /predict`.
- Spring: `GET /api/v1/health`, `POST /api/v1/analyze`, `POST /api/policy/evaluate`.
- URL history: `GET /api/security-events`, `/risk/{riskLevel}`, `/decision/{decision}`, `/stats`.
- Monitor metadata: `POST /api/monitor-events`, `GET /api/monitor-events?limit=100`.

## 24. Configuration

- ML URL/timeouts and SQLite path: `backend/src/main/resources/application.properties`.
- ML host/port/model path/hash: environment-aware settings in `api/config.py`.
- File roots/exclusions: `AI_WATCHDOG_MONITOR_DIRS`, `AI_WATCHDOG_MONITOR_EXCLUDE`.
- Process polling: `AI_WATCHDOG_PROCESS_POLL_MS` or JVM property `aiwatchdog.process.poll-ms`.
- Browser extension endpoint hosts: manifest entries for localhost and 127.0.0.1.

## 25. Startup Procedure

`start-aiwatchdog.bat` starts FastAPI, waits for health, starts Spring, waits for Spring+ML health, then starts JavaFX. It preserves visible service consoles and prints timeout errors. The full sequence was run successfully; both service health checks passed and the JavaFX process started. Manual steps are in [RUNNING.md](RUNNING.md).

## 26. Test Results (2026-10-01)

- Backend clean test suite: 34 passed, no failures/errors/skips.
- Frontend unit suite: 2 passed after the JavaFX error-message fix.
- Live monitor integration suite: 2 tests passed with FastAPI and Spring running.
- Python feature parity: 4 passed with pinned scikit-learn 1.8.0.
- Browser extension: 2 Node tests passed.
- Total: 44 test executions passed. Backend and frontend builds succeeded; Maven reported six existing JavaFX dependency model warnings. Commands: backend `cd backend; .\mvnw.cmd clean test`; frontend `cd Frontend; mvn test`; monitor integration `cd Frontend; mvn '-Dtest=MonitorServicesIntegrationIT' test`; Python `cd scripts; ..\.venv\Scripts\python.exe -m unittest test_phase5_feature_parity -v`; extension `node --test browser-extension\service-worker.test.cjs`.

## 27. End-to-End Verification

Verified live URL analysis through Spring, FastAPI, policy, configured SQLite, and URL history. Verified file and process observers against a live Spring API, policy engines, monitor SQLite table, and history retrieval. Restarted FastAPI and Spring; health recovered, prediction/analyze worked afterward, and stored monitor events remained. The launcher started JavaFX, but the desktop UI and installed browser extension were not available for interactive end-to-end verification.

## 28. Performance

File events are delivered asynchronously using WatchService. Process metadata polling defaults to two seconds. HTTP event submission uses a bounded queue; under prolonged backend outage or event bursts, oldest queued events may be dropped. No throughput or latency benchmark was run.

## 29. Known Limitations

- File/process decisions are recorded only; operating-system access is not blocked.
- No malware content scan, signature validation, kernel monitoring, EDR, or antivirus behavior.
- Browser extension must be installed by the user and does not enforce decisions.
- JavaFX visual acceptance, controls, filters, and visible monitor status remain unverified because no desktop UI surface was exposed.
- WatchService rename detection is best effort; process metadata may be incomplete.
- Monitor behavior across JavaFX close/reopen and prolonged service outage was not verified.
- No authentication is configured; services bind to loopback, so local user processes can access them.

## 30. Follow-up Checks

Visually verify JavaFX pages and filters, install/review the browser extension in a disposable profile, test prolonged monitor outage behavior and file rename detection, and decide whether local API authentication is needed.

## 31. Git Changes

No commits were created. Initial user changes (deleted `Project image.png`, modified backend event files, deleted a test, untracked `Architecture.jpg` and a test source) were preserved. Maven-generated tracked Frontend target files were restored after verification because they were clean at the start of the work.

## 32. Final Status

**PARTIALLY COMPLETE.** URL analysis and file/process metadata paths are implemented and verified through Spring/SQLite. Browser installation and JavaFX visual acceptance are incomplete. File/process `BLOCK` outcomes are not OS enforcement, and the system must not be represented as antivirus, EDR, or full malware detection.
