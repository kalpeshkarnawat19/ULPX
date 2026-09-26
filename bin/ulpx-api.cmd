@echo off
set "SCRIPT_DIR=%~dp0"
if exist "%SCRIPT_DIR%ulpx.cmd" (
    call "%SCRIPT_DIR%ulpx.cmd" api %*
    exit /b %errorlevel%
)
call ulpx api %*
exit /b %errorlevel%
