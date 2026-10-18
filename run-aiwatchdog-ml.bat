@echo off
setlocal
set "ROOT=%~dp0"
cd /d "%ROOT%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%setup-local-auth.ps1"
if errorlevel 1 exit /b 1
"%ROOT%.venv\Scripts\python.exe" -m uvicorn api.server:app --host 127.0.0.1 --port 8000
endlocal
