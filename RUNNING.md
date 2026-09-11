# Running AI WatchDog

This repository contains three runnable parts:

- `api`: FastAPI inference service on `http://127.0.0.1:8000`
- `backend`: Spring Boot API on `http://localhost:8080`
- `Frontend`: JavaFX desktop prototype

The commands below are for Windows PowerShell and assume the repository root is `P:\major_project`.

## Prerequisites

Install or make available on `PATH`:

- Python 3.10 or newer
- Java 21 for the Spring Boot backend
- Java 17 or newer for the JavaFX frontend
- Maven 3.9 or newer, unless using the included Maven wrapper for the backend

Check the installed tools:

```powershell
python --version
java -version
mvn --version
```

## 1. Install Python dependencies

Run this once from the repository root:

```powershell
cd P:\major_project
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-api.txt
```

If PowerShell blocks activation, run the following once for the current user, then activate the environment again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## 2. Start the ML API

Open Terminal 1 and run from the repository root. Do not start this command from the `api` directory.

```powershell
cd P:\major_project
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\scripts"
python -m uvicorn api.server:app --host 127.0.0.1 --port 8000
```

Verify that the model loaded and passed integrity verification in another PowerShell window:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

The response should contain `status: OK`, `model_loaded: true`, and `model_integrity: VERIFIED`.

Test a prediction:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/predict `
  -ContentType 'application/json' `
  -Body '{"url":"https://example.com"}'
```

## 3. Start the Spring Boot backend

Open Terminal 2:

```powershell
cd P:\major_project\backend
.\mvnw.cmd spring-boot:run
```

The backend listens on `http://localhost:8080` and uses the ML API at `http://127.0.0.1:8000`.

Run backend tests without starting the service:

```powershell
cd P:\major_project\backend
.\mvnw.cmd test
```

## 4. Start the JavaFX frontend

The frontend is a desktop prototype and can run independently of the backend and ML API.

Open Terminal 3:

```powershell
cd P:\major_project\Frontend
mvn clean javafx:run
```

## Stop the services

In each terminal running a service, press `Ctrl+C`.

## Troubleshooting

### ML API reports `503 NOT_READY`

Start it from `P:\major_project`, confirm that `data\phase4\xgboost_calibrated.joblib` exists, and check that the installed Python packages came from `requirements-api.txt`.

### Backend cannot connect to the ML API

Start the ML API first and verify `http://127.0.0.1:8000/health`. The backend configuration is in `backend\src\main\resources\application.properties`.

### Port already in use

Stop the process using port 8000 or 8080, or change the corresponding service configuration before starting it.

### JavaFX does not start

Confirm that Java 17 or newer is active in the frontend terminal and that Maven is installed. The frontend uses JavaFX dependencies downloaded by Maven.
