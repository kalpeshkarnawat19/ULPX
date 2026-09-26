@echo off
set "SCRIPT_DIR=%~dp0"
if exist "%SCRIPT_DIR%ulpx.cmd" (
    call "%SCRIPT_DIR%ulpx.cmd" export --format text %*
    exit /b %errorlevel%
)
call ulpx export --format text %*
exit /b %errorlevel%
