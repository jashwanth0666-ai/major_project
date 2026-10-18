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

## Local API credentials

The launch scripts create a per-user credential file at `%APPDATA%\AIWatchDog\auth\api-tokens.json` if it does not exist and restrict its Windows ACL to the current account and SYSTEM. The file contains separate 256-bit bearer tokens for the JavaFX desktop (`desktop`), browser extension (`extension`), and Spring-to-FastAPI service call (`springToMl`). Spring protects every route except `GET /api/v1/health`; the extension credential can call only the two URL assessment endpoints. FastAPI protects `/predict` and the static PE endpoint with the service credential; `GET /health` remains available for startup checks.

The extension token must be configured once in the extension's **Options** page. After starting the services, open the credential file and copy only the `extension` value into the extension settings:

```powershell
Get-Content "$env:APPDATA\AIWatchDog\auth\api-tokens.json" -Raw
```

Do not paste the desktop or service token into the extension. To rotate all three credentials, stop the services and run `.\setup-local-auth.ps1 -Rotate`, then restart the services, recreate the extension token setting, and restart JavaFX so it reloads the desktop credential. Rotation does not modify SQLite data.

For a custom credential location set `AI_WATCHDOG_TOKEN_FILE` before launching every service/client process. The setup script protects the credential file itself and only changes the parent directory ACL for the dedicated default directory. Keep custom parent directories protected by the Windows account ACL.

This bearer-token design protects against unauthenticated callers and limits what the browser extension credential can do. It does not isolate hostile processes running as the same Windows account: those processes can generally read the account's credential file. Keep both services bound to loopback and run as a standard user.

Check the installed tools:

```powershell
python --version
java -version
mvn --version
```

## 1. Install Python dependencies

Run this once from the repository root:

```powershell

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-api.txt
```

If PowerShell blocks activation, run the following once for the current user, then activate the environment again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Before manual service startup, initialize credentials from the repository root. The `start-aiwatchdog.bat` and individual `run-aiwatchdog-*.bat` scripts do this automatically.

```powershell
cd P:\major_project
.\setup-local-auth.ps1
```

## 2. Start the ML API

Open Terminal 1 and run from the repository root. Do not start this command from the `api` directory.

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\scripts"
python -m uvicorn api.server:app --host 127.0.0.1 --port 8000
```

Verify that the model loaded and passed integrity verification in another PowerShell window:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

The response should contain `status: OK`, `model_loaded: true`, and `model_integrity: VERIFIED`.

To enable the local static PE endpoint, configure `AI_WATCHDOG_PE_APPROVED_ROOTS` and `AI_WATCHDOG_PE_MAX_FILE_SIZE_BYTES` before starting FastAPI. See [PE analyzer setup and API details](../api/PE_ANALYZER.md).

Test a prediction:

```powershell
$serviceToken = (Get-Content "$env:APPDATA\AIWatchDog\auth\api-tokens.json" -Raw | ConvertFrom-Json).springToMl
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/predict `
  -Headers @{ Authorization = "Bearer $serviceToken" } `
  -ContentType 'application/json' `
  -Body '{"url":"https://example.com"}'
```

## 3. Start the Spring Boot backend

Open Terminal 2:

```powershell
cd backend
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
cd Frontend
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
