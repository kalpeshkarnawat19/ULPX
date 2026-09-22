@echo off
title ULPF-X Environment Installer
color 0B
cls

echo =======================================================================
echo    ULPF-X Cross-Platform Standalone Environment Setup
echo =======================================================================
echo.

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

:: 2. Execute via Git Bash if available; fallback to native PowerShell
if defined GIT_BASH_PATH (
    echo [INFO] Environment located: Git Bash
    "%GIT_BASH_PATH%" -c "./install.sh; echo ''; read -p 'Press Enter to exit...' "
) else (
    echo [INFO] Git Bash not detected. Launching native PowerShell installer...
    powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\install.ps1"
)

if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [ERROR] Installation hit an unexpected error.
    pause
)