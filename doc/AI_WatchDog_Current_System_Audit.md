# AI WatchDog Current System Audit

Audit date: 2026-10-01. Branch `main`; starting commit `bc9a4d3`.

## Current state

- JavaFX calls Spring Boot; Spring coordinates URL inference through FastAPI and stores URL/file/process audit events in SQLite.
- FastAPI loads the checksum-verified calibrated model. Its artifact was serialized with scikit-learn 1.8.0; `requirements-api.txt` and the local environment are now pinned to 1.8.0.
- File and process monitors send basename/PID/size metadata to Spring. File/process risk results are heuristics and are not enforced by Windows.
- Chromium extension source observes sanitized active-tab URLs and posts only to loopback Spring. It is not installed in a browser.
- `start-aiwatchdog.bat` starts FastAPI, Spring, and JavaFX. Health checks and process startup succeeded; the desktop window was not exposed to UI inspection.

## Acceptance checks run

- Backend clean test suite: 34 passed.
- Frontend unit suite: 2 passed; live monitor integration suite: 2 passed.
- Python feature parity: 4 passed with scikit-learn 1.8.0.
- Browser extension Node tests: 2 passed.
- Live URL analysis, file/process monitor routing, Spring/FastAPI restart recovery, and monitor-history persistence were verified.

See [AI_WatchDog_FINAL_ACCEPTANCE_REPORT.md](AI_WatchDog_FINAL_ACCEPTANCE_REPORT.md) for exact scope and remaining checks.
