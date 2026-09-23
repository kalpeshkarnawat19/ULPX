@echo off
set "SCRIPT_DIR=%~dp0"
set "ENGINE_ROOT=%SCRIPT_DIR%.."
where python >nul 2>&1
if %errorlevel% equ 0 (
    python "%ENGINE_ROOT%\scripts\demo.py" %*
) else (
    where python3 >nul 2>&1
    if %errorlevel% equ 0 (
        python3 "%ENGINE_ROOT%\scripts\demo.py" %*
    ) else (
        echo Error: Python runtime not found in PATH. 1>&2
        exit /b 1
    )
)
