@echo off
setlocal
set "ROOT=%~dp0"
cd /d "%ROOT%backend"
call mvnw.cmd spring-boot:run
endlocal
