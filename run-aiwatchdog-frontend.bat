@echo off
setlocal
set "ROOT=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%setup-local-auth.ps1"
if errorlevel 1 exit /b 1
cd /d "%ROOT%Frontend"
call mvn javafx:run
endlocal
