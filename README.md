# AI WatchDog

AI WatchDog is a local Windows security monitoring prototype with a JavaFX desktop UI, a Spring Boot application backend, and a Python FastAPI phishing URL model. The URL model uses the existing calibrated XGBoost artifact and threshold; this implementation does not retrain or replace it.

## Components

- `Frontend/`: JavaFX UI. It talks to Spring Boot over REST and does not access SQLite or FastAPI directly.
- `backend/`: Spring Boot REST API, URL policy, event history, file/process engines, and SQLite persistence.
- `api/` and `scripts/`: FastAPI inference service and validated model pipeline.
- `browser-extension/`: optional Chromium extension source for active-tab URL analysis.
- `data/phase4/`: calibrated model and its risk configuration.

File and process monitoring use metadata heuristics. The app records ALLOW/REVIEW/WARN/BLOCK policy results; it does not block file access or terminate processes. It is not antivirus, EDR, or a kernel monitor.

## Start on Windows

Prerequisites: Python with dependencies from `requirements-api.txt`, Java 21 for Spring Boot, Java 17 or newer for JavaFX, and Maven for the desktop build.

Run `start-aiwatchdog.bat` from the repository root. It starts FastAPI, waits for model health, starts Spring Boot, waits for backend and ML health, then starts JavaFX. Each service has its own visible console; use Ctrl+C in each to stop it.

For manual startup, see [doc/RUNNING.md](doc/RUNNING.md) and [backend/RUNNING_BACKEND.md](backend/RUNNING_BACKEND.md). For monitor configuration, data handling, and limitations, see [backend/MONITORING.md](backend/MONITORING.md).

To load the optional Chrome or Edge provider, follow [browser-extension/README.md](browser-extension/README.md).

## Verification

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
