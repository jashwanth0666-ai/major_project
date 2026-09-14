# AI WatchDog Launch Guide

## A. Project Overview

AI WatchDog runs as three cooperating services:

```text
JavaFX desktop application
    -> POST http://localhost:8080/api/v1/analyze
Spring Boot backend
    -> POST http://127.0.0.1:8000/predict
FastAPI ML model service
    -> verified data/phase4/xgboost_calibrated.joblib
```

The JavaFX frontend calls only Spring Boot. The backend validates the URL, calls the ML service, evaluates the policy engine, and returns the combined result. The frontend does not call the ML service or access the model/database directly.

## B. Prerequisites

- Windows PowerShell.
- Java 21 or newer for the backend; the verified environment uses Java 24.0.2.
- Java 17 or newer for the frontend; JavaFX dependencies are declared in `Frontend/pom.xml`.
- Maven 3.9 or newer. The backend includes `backend/mvnw.cmd`; the frontend uses installed Maven.
- Python 3.10 or newer; the verified environment uses Python 3.13.12.
- Packages from `requirements-api.txt`: FastAPI, Uvicorn, Pydantic, joblib, scikit-learn, XGBoost, pandas, and NumPy.
- Model file: `data/phase4/xgboost_calibrated.joblib`.
- No password, API key, token, database, or external credential is required by the current configuration.

Configuration:

- ML service: `api/config.py`, default `127.0.0.1:8000`.
- Backend: `backend/src/main/resources/application.properties`, port `8080`, ML URL `http://127.0.0.1:8000`.
- Frontend backend URL: `Frontend/src/main/java/com/aiwatchdog/service/ApiService.java`, `http://localhost:8080/api/v1`.
- ML imports `scripts/phase5_inference.py`, so `PYTHONPATH` must include `scripts`.

## C. Project Structure

```text
major_project/
|-- api/ (config.py, integrity.py, server.py)
|-- backend/ (pom.xml, mvnw.cmd, Spring Boot source and tests)
|-- data/phase4/ (model and risk_engine_config.json)
|-- Frontend/ (pom.xml, JavaFX source, FXML, CSS, icons)
|-- scripts/phase5_inference.py
|-- requirements-api.txt
|-- RUNNING.md
`-- AI_WatchDog_Launch_Guide.md
```

The JavaFX entry point is `com.aiwatchdog.MainApp`. The backend entry point is `com.aiwatchdog.backend.BackendApplication`. The ML entry point is `api.server:app` served by Uvicorn. There is no Dockerfile or Docker Compose configuration in the repository.

## D. First-Time Setup

Open PowerShell at the repository root:

```powershell
cd P:\major_project_final\major_project
python --version
java -version
mvn --version
```

Create and populate a virtual environment once:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-api.txt
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then activate again. Confirm the model artifact exists:

```powershell
Test-Path data\phase4\xgboost_calibrated.joblib
Get-FileHash data\phase4\xgboost_calibrated.joblib -Algorithm SHA256
```

The expected model hash is configured in `api/config.py`. Do not replace the model without updating the intentional model-release configuration.

## E. Launch Instructions

Use three separate terminals so each service keeps its own logs.

### Terminal 1: ML model service

Directory: `P:\major_project_final\major_project`

```powershell
cd P:\major_project_final\major_project
if (Test-Path .venv\Scripts\Activate.ps1) { .\.venv\Scripts\Activate.ps1 }
$env:PYTHONPATH = "$PWD\scripts"
python -m uvicorn api.server:app --host 127.0.0.1 --port 8000
```

Expected readiness: `Application startup complete.` and `Uvicorn running on http://127.0.0.1:8000`.

Service URL: `http://127.0.0.1:8000`

### Terminal 2: Spring Boot backend

Directory: `P:\major_project_final\major_project\backend`

```powershell
cd P:\major_project_final\major_project\backend
.\mvnw.cmd spring-boot:run
```

Expected readiness: `Tomcat started on port 8080` and `Started BackendApplication`.

Service URL: `http://localhost:8080`

### Terminal 3: JavaFX frontend

Directory: `P:\major_project_final\major_project\Frontend`

```powershell
cd P:\major_project_final\major_project\Frontend
mvn clean javafx:run
```

Expected result: a window titled `AI WatchDog | Phishing Detection & Secure Access`. Maven starts `com.aiwatchdog.MainApp`, which loads `resources/fxml/main.fxml` and `resources/css/app.css`.

## F. Recommended Startup Order

1. Start ML and wait for its verified health response.
2. Start Spring Boot. Its health endpoint checks ML availability, and analysis depends on ML.
3. Start JavaFX. The desktop app can open without the APIs, but URL analysis requires both APIs.

## G. Verification

### ML readiness and inference

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health | ConvertTo-Json -Compress
$body = '{"url":"https://example.com"}'
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/predict -ContentType 'application/json' -Body $body | ConvertTo-Json -Depth 8
```

Health must report `status=OK`, `model_loaded=true`, and `model_integrity=VERIFIED`.

### Backend readiness and analysis

```powershell
Invoke-RestMethod http://localhost:8080/api/v1/health | ConvertTo-Json -Compress
$body = '{"url":"https://example.com"}'
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/analyze -ContentType 'application/json' -Body $body | ConvertTo-Json -Depth 8
```

Expected health response:

```json
{ "status": "OK", "spring_boot": "UP", "ml_service": "UP" }
```

The analysis response contains `url`, `phishing_probability`, `risk_score`, `risk_level`, `prediction`, `decision`, `threshold`, and `reasons`. The verified current result for `https://example.com` was benign, risk score `0`, decision `ALLOW`.

### Frontend check

After the JavaFX window opens, start protection, complete setup, open URL Scanner, enter `https://example.com`, and submit it. Confirm the result screen displays the returned decision, risk score, prediction, and reasons. The frontend sends `POST http://localhost:8080/api/v1/analyze` from a background task and displays the returned `AnalyzeResponse`.

### Verified status for this workspace

- ML startup, model health, and direct inference passed.
- Spring Boot startup, ML connectivity, and `/api/v1/analyze` passed.
- JavaFX launched as `com.aiwatchdog.MainApp`; FXML and CSS resources were on the application classpath.
- Automated JavaFX button interaction was not performed in this terminal session. The backend chain was verified directly, and the frontend request path was confirmed from `ApiService` and `MainController`.

## H. Troubleshooting

### Java or Maven not found

Install a compatible JDK and Maven, reopen PowerShell, and confirm with `java -version` and `mvn --version`. Use `backend\\mvnw.cmd` for the backend if needed; the frontend normally uses installed Maven.

### Python dependencies missing

Activate `.venv` and run `python -m pip install -r requirements-api.txt`.

### Model missing or loading fails

Confirm `data\\phase4\\xgboost_calibrated.joblib` exists and its SHA-256 matches `api/config.py`. ML `/health` returns HTTP `503` with the failure detail if loading or integrity verification fails.

### Port already in use

Inspect the owner before stopping anything:

```powershell
Get-NetTCPConnection -LocalPort 8000,8080 -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
Get-Process -Id <PID>
```

Reuse a healthy project process when possible. Do not stop unrelated processes. ML uses `8000`; Spring Boot uses `8080`.

### Spring Boot cannot connect to ML

Check `http://127.0.0.1:8000/health`, start ML from the repository root, and confirm `PYTHONPATH` contains `P:\major_project_final\major_project\scripts`. The backend ML URL is in `backend/src/main/resources/application.properties`.

### JavaFX cannot connect to Spring Boot

Confirm `http://localhost:8080/api/v1/health` returns `status=OK` and that `ApiService.java` points to `http://localhost:8080/api/v1`.

### HTTP 400, 500, or 503

- `400`: send `{"url":"https://example.com"}` with an HTTP or HTTPS URL containing a host.
- `500`: inspect backend and ML logs for an internal or unusable prediction response.
- `503`: check ML `/health`, model integrity, and backend `/api/v1/health`.

### FXML or CSS loading failures

Run from `Frontend` with `mvn clean javafx:run`, and confirm `src/main/resources/fxml/main.fxml`, `src/main/resources/css/app.css`, and the JavaFX dependencies in `Frontend/pom.xml` are present.

## I. Shutdown Instructions

Stop each service from its own terminal with `Ctrl+C`: close the JavaFX window, stop Spring Boot, then stop ML. If a terminal is unavailable, identify the process by its command line and project path before stopping it. Do not terminate an arbitrary process solely because it owns port `8000` or `8080`.

## J. Launch Status

Verified against `P:\major_project_final\major_project` on 2026-09-14:

- Python 3.13.12, Java 24.0.2, and Maven 3.9.14 were available.
- The model existed and matched SHA-256 `B46D8AE98125357A349BC308A9E839A2B1804B2E6BC291931AA72C1E358D69B7`.
- ML startup, readiness, and real `https://example.com` inference passed.
- Spring Boot startup, ML integration, and real `/api/v1/analyze` analysis passed.
- JavaFX startup passed and its application process loaded the declared classpath, FXML, and CSS resources.
- Automated desktop clicking was not available in this session, so the final frontend display step remains a manual confirmation using section G.
