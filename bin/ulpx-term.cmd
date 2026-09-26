@echo off
set "SCRIPT_DIR=%~dp0"
if exist "%SCRIPT_DIR%ulpx.cmd" (
    call "%SCRIPT_DIR%ulpx.cmd" watch %*
    exit /b %errorlevel%
)
call ulpx watch %*
exit /b %errorlevel%
