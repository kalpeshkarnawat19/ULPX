# scripts/install.ps1
$ErrorActionPreference = "Stop"

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  ULPF-X Windows Native Standalone Environment Setup" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

$TargetDir = "$ENV:USERPROFILE\.ulpx"

# Determine repository root reliably
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RootDir = Split-Path -Parent $ScriptDir
if (-not (Test-Path "$RootDir\scripts\audit.py")) {
    $RootDir = (Get-Item -Path ".\").FullName
}

# 1. Create target engine directory
if (-not (Test-Path -Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    Write-Host "[SUCCESS] Created engine home at $TargetDir" -ForegroundColor Green
}

# 2. Mirror source files into .ulpx
Write-Host "[INFO] Synchronizing engine core files..." -ForegroundColor Yellow
Get-ChildItem -Path $RootDir -Exclude "*.zip", ".git*", "dist", ".pytest_cache", "venv" | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination $TargetDir -Recurse -Force
}

# 3. Add ~/.ulpx/bin to Windows User PATH
$BinPath = "$TargetDir\bin"
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")

if ($UserPath -notlike "*$BinPath*") {
    $NewPath = "$UserPath;$BinPath"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Write-Host "[SUCCESS] Registered $BinPath into Windows User PATH." -ForegroundColor Green
} else {
    Write-Host "[INFO] PATH already configured in Environment." -ForegroundColor Yellow
}

# 4. Verify and install Python dependencies
Write-Host "[INFO] Verifying Python runtime and dependencies..." -ForegroundColor Yellow
$PythonCmd = $null
if (Get-Command "python" -ErrorAction SilentlyContinue) {
    $PythonCmd = "python"
} elseif (Get-Command "py" -ErrorAction SilentlyContinue) {
    $PythonCmd = "py"
} elseif (Get-Command "python3" -ErrorAction SilentlyContinue) {
    $PythonCmd = "python3"
}

if ($PythonCmd) {
    $WheelsDir = "$TargetDir\wheels"
    if (Test-Path "$WheelsDir") {
        Write-Host "[INFO] Installing offline wheel dependencies from $WheelsDir..." -ForegroundColor Yellow
        & $PythonCmd -m pip install --no-index --find-links="$WheelsDir" rich psutil pytest --quiet
    } else {
        Write-Host "[INFO] Installing required dependencies (rich, psutil, pytest)..." -ForegroundColor Yellow
        & $PythonCmd -m pip install rich psutil pytest --quiet
    }
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[SUCCESS] Python dependencies verified and ready." -ForegroundColor Green
    } else {
        Write-Host "[WARNING] Automatic pip install failed. Please manually run: pip install rich psutil pytest" -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARNING] Python was not found in PATH. Please install Python 3.9+ and run 'pip install rich psutil pytest'." -ForegroundColor Yellow
}

Write-Host "`n[✔] ULPF-X standalone installation complete!" -ForegroundColor Green
Write-Host "Please restart your PowerShell or Terminal window, then run 'ulpx-test'." -ForegroundColor Yellow
Write-Host "=======================================================" -ForegroundColor Cyan