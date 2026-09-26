@echo off
set "SCRIPT_DIR=%~dp0"
if exist "%SCRIPT_DIR%ulpx.cmd" (
    call "%SCRIPT_DIR%ulpx.cmd" daemon start %*
    exit /b %errorlevel%
)
call ulpx daemon start %*
exit /b %errorlevel%
