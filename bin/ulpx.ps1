# ULPF-X Main Engine PowerShell Launcher
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$EngineRoot = Split-Path -Parent $ScriptDir

# 1. Virtualenv check
if (Test-Path "$EngineRoot\venv\Scripts\python.exe") {
    & "$EngineRoot\venv\Scripts\python.exe" "$EngineRoot\scripts\cli.py" @args
    exit $LASTEXITCODE
}

# 2. Python discovery
$PythonCmd = $null
if (Get-Command "python" -ErrorAction SilentlyContinue) {
    $PythonCmd = "python"
} elseif (Get-Command "py" -ErrorAction SilentlyContinue) {
    $PythonCmd = "py"
} elseif (Get-Command "python3" -ErrorAction SilentlyContinue) {
    $PythonCmd = "python3"
}

if ($PythonCmd) {
    & $PythonCmd "$EngineRoot\scripts\cli.py" @args
    exit $LASTEXITCODE
}

Write-Error "Error: Python runtime not found in PATH or virtual environment."
exit 1
