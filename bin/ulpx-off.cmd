@echo off
set "SCRIPT_DIR=%~dp0"
if exist "%SCRIPT_DIR%ulpx.cmd" (
    call "%SCRIPT_DIR%ulpx.cmd" daemon stop %*
    exit /b %errorlevel%
)
call ulpx daemon stop %*
exit /b %errorlevel%
