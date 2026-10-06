@echo off
setlocal
set "ROOT=%~dp0"

if not exist "%ROOT%.venv\Scripts\python.exe" (
  echo AI WatchDog Python environment is missing: %ROOT%.venv
  echo See doc\RUNNING.md to install the API requirements.
  exit /b 1
)

echo Starting FastAPI. Its console remains open so startup errors stay visible.
start "AI WatchDog - FastAPI" /D "%ROOT%" cmd.exe /k call run-aiwatchdog-ml.bat
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%wait-aiwatchdog-health.ps1" -Uri "http://127.0.0.1:8000/health" -TimeoutSeconds 60
if errorlevel 1 (
  echo FastAPI did not become healthy within 60 seconds. Check its open console.
  exit /b 1
)

echo Starting Spring Boot. Its console remains open so startup errors stay visible.
start "AI WatchDog - Spring Boot" /D "%ROOT%backend" cmd.exe /k call "%ROOT%run-aiwatchdog-backend.bat"
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%wait-aiwatchdog-health.ps1" -Uri "http://localhost:8080/api/v1/health" -TimeoutSeconds 90 -RequireMl
if errorlevel 1 (
  echo Spring Boot did not become healthy within 90 seconds. Check its open console.
  exit /b 1
)

echo Starting JavaFX desktop console.
start "AI WatchDog - JavaFX" /D "%ROOT%Frontend" cmd.exe /k call "%ROOT%run-aiwatchdog-frontend.bat"
echo Services started. Close each service console with Ctrl+C to stop it.
endlocal
