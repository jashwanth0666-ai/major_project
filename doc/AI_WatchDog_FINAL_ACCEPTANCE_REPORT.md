# AI WatchDog Final Acceptance Report

Date: 2026-10-01  
Status: **PARTIALLY COMPLETE**

## Summary

The local URL analysis path and file/process metadata paths work through the Spring backend, policy layer, and SQLite. Regression suites passed. The JavaFX process launched, but this environment did not expose a desktop window or browser for interactive acceptance. File/process decisions are audit results only; they do not block Windows operations.

## Verified

- **Backend:** `.\mvnw.cmd clean test` — 34 passed, 0 failed/errors/skipped.
- **Frontend:** `mvn test` — 2 passed. Live `MonitorServicesIntegrationIT` — 2 passed with FastAPI and Spring running.
- **Python:** feature parity suite — 4 passed.
- **Browser source:** Node tests — 2 passed; manifest and worker use loopback endpoints and sanitize URLs.
- **Live URL path:** Spring `/api/v1/analyze` called FastAPI and returned SAFE/ALLOW for `https://example.com`; health, model integrity, and URL history were checked.
- **File/process path:** integration tests observed a controlled file and JVM process through monitor, engine, risk, policy, SQLite, and history.
- **Restart/persistence:** FastAPI and Spring health recovered after restart/unavailability. Stored file/process history remained available after Spring restarted. URL prediction and Spring analysis worked again.
- **Security configuration:** FastAPI and Spring bind to loopback. SQLite operations use prepared statements. URL audit data is sanitized. Process metadata uses executable names without command-line arguments. Monitor submission queues are bounded at 256. No hard-coded credentials were found in the inspected runtime configuration.
- **JavaFX failure handling:** removed raw stack-trace printing from the analysis failure callback; it now shows a short service-unavailable message. Frontend tests passed after this change.

## Dependency compatibility

The existing artifact emitted a warning that it was created with scikit-learn 1.8.0 while the environment used 1.9.1. The API requirements and local Python environment are now pinned to 1.8.0; no model retraining or threshold change was made. After restart, `/health`, `/predict`, and Spring-to-FastAPI analysis succeeded without the version mismatch. The official scikit-learn persistence guidance says loading across versions is unsupported: [Model persistence](https://scikit-learn.org/stable/model_persistence.html).

## JavaFX acceptance

- **Verified:** frontend builds/tests pass; `start-aiwatchdog.bat` launched a JavaFX `MainApp` process.
- **Partially verified:** analysis and history paths were tested via Spring; controller uses background tasks for analysis/history and formats risk/decision filters.
- **Not verified:** dashboard rendering, interaction, visible monitor status, actual filter behavior, and visible error behavior. UI automation exposed no desktop window, so no visual claim is made.

## Browser acceptance

- **Verified:** manifest/worker source, URL sanitization and deduplication tests, loopback endpoint configuration.
- **Not verified:** installation in Chrome/Edge, active-tab runtime observation, browser permissions, or browser-to-JavaFX display. The available environment exposed no browser surface.

## Remaining gaps and limits

- File rename inference and monitor behavior across JavaFX close/reopen or prolonged backend outages were not verified.
- Browser extension installation and JavaFX visual acceptance remain outstanding.
- File/process `BLOCK` results are logged policy outcomes only. No file access is denied and no process is terminated.
- No malware content scanning, kernel monitoring, antivirus, or EDR capability is implemented.
- APIs have no local authentication; loopback binding limits remote exposure, but other local processes can call them.
- Maven reported six existing JavaFX dependency model warnings; builds and tests still succeeded.

## Test totals

| Suite | Passed |
|---|---:|
| Backend | 34 |
| Frontend unit | 2 |
| Live monitor integration | 2 |
| Python feature parity | 4 |
| Browser extension Node tests | 2 |
| **Total executions** | **44** |

No commit was created. Preexisting user changes were preserved.
