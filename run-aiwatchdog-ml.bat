@echo off
setlocal
set "ROOT=%~dp0"
cd /d "%ROOT%"
set "PYTHONPATH=%ROOT%scripts"
"%ROOT%.venv\Scripts\python.exe" -m uvicorn api.server:app --host 127.0.0.1 --port 8000
endlocal
