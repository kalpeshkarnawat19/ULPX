@echo off
title ULPF-X Environment Installer
echo =================================================
echo   ULPF-X Initial Standalone Environment Setup
echo =================================================
echo.

where git-bash.exe >nul 2>&1
if %errorlevel% equ 0 (
    git-bash.exe -c "./install.sh; exec bash"
) else (
    bash -c "./install.sh; exec bash"
)
