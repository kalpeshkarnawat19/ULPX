@echo off
title ULPF-X Environment Installer
color 0B
cls

echo =======================================================================
echo    ULPF-X Cross-Platform Standalone Environment Setup
echo =======================================================================
echo.

set "SCRIPT_DIR=%~dp0"
set "ROOT_DIR=%SCRIPT_DIR%.."

:: 1. Search for Git Bash
set "GIT_BASH_PATH="
where git-bash.exe >nul 2>&1
if %errorlevel% equ 0 (
    set "GIT_BASH_PATH=git-bash.exe"
) else if exist "C:\Program Files\Git\git-bash.exe" (
    set "GIT_BASH_PATH=C:\Program Files\Git\git-bash.exe"
) else if exist "%LocalAppData%\Programs\Git\git-bash.exe" (
    set "GIT_BASH_PATH=%LocalAppData%\Programs\Git\git-bash.exe"
)

:: 2. Auto-route execution: Git Bash preferred, PowerShell as native fallback
if defined GIT_BASH_PATH (
    echo [INFO] Detected Git Bash environment. Launching installer...
    pushd "%ROOT_DIR%"
    "%GIT_BASH_PATH%" -c "./scripts/install.sh; echo ''; read -p 'Press Enter to exit...' "
    popd
) else (
    echo [INFO] Git Bash not found. Launching native Windows PowerShell installer...
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%install.ps1"
)

if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [ERROR] Installation encountered an error.
    pause
)
