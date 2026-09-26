@echo off
set "SCRIPT_DIR=%~dp0"
set "ENGINE_ROOT=%SCRIPT_DIR%.."

:: Check standard Python PATH execution
python -c "import sys" >nul 2>&1
if %errorlevel% equ 0 (
    python "%ENGINE_ROOT%\scripts\demo.py" %*
    exit /b %errorlevel%
)

:: Check official Windows Python launcher (py.exe)
py -3 -c "import sys" >nul 2>&1
if %errorlevel% equ 0 (
    py -3 "%ENGINE_ROOT%\scripts\demo.py" %*
    exit /b %errorlevel%
)

:: Fallback to python3 if available
python3 -c "import sys" >nul 2>&1
if %errorlevel% equ 0 (
    python3 "%ENGINE_ROOT%\scripts\demo.py" %*
    exit /b %errorlevel%
)

:: Direct fallback for standard Windows installation paths (e.g., C:\Python314\python.exe)
if exist "C:\Python314\python.exe" (
    "C:\Python314\python.exe" "%ENGINE_ROOT%\scripts\demo.py" %*
    exit /b %errorlevel%
)

if exist "C:\Python313\python.exe" (
    "C:\Python313\python.exe" "%ENGINE_ROOT%\scripts\demo.py" %*
    exit /b %errorlevel%
)

echo Error: Python runtime not found in PATH or standard directories. 1>&2
exit /b 1
