@echo off
setlocal
set "ROOT=%~dp0"
cd /d "%ROOT%Frontend"
call mvn javafx:run
endlocal
