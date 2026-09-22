@echo off
title ULPF-X Environment Installer
echo =================================================
echo   ULPF-X Initial Standalone Environment Setup
echo =================================================
echo.

:: 1. Search common Git Bash paths if not in PATH
set "GIT_BASH_PATH="
where git-bash.exe >nul 2>&1
if %errorlevel% equ 0 (
    set "GIT_BASH_PATH=git-bash.exe"
) else if exist "C:\Program Files\Git\git-bash.exe" (
    set "GIT_BASH_PATH=C:\Program Files\Git\git-bash.exe"
) else if exist "%LocalAppData%\Programs\Git\git-bash.exe" (
    set "GIT_BASH_PATH=%LocalAppData%\Programs\Git\git-bash.exe"
)

:: 2. Execute install.sh via Git Bash or Fallback
if defined GIT_BASH_PATH (
    echo [INFO] Launching installer in Git Bash...
    "%GIT_BASH_PATH%" -c "./install.sh; echo ''; read -p 'Press Enter to exit...' "
) else (
    echo [WARNING] Git Bash launcher not found in standard paths. Trying system bash...
    bash -c "./install.sh; exec bash"
)

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Installation failed or encountered an error.
    pause
)