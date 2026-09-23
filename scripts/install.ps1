# scripts/install.ps1
$ErrorActionPreference = "Stop"

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  ULPF-X PowerShell Native Standalone Installer" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

$TargetDir = "$ENV:USERPROFILE\.ulpx"

# 1. Create ~/.ulpx directory
if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    Write-Host "[SUCCESS] Created engine folder at $TargetDir" -ForegroundColor Green
}

# 2. Sync files into .ulpx
Copy-Item -Path ".\*" -Destination $TargetDir -Recurse -Force
Write-Host "[SUCCESS] Synchronized engine core files." -ForegroundColor Green

# 3. Register user PATH variable natively
$BinPath = "$TargetDir\bin"
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")

if ($UserPath -notlike "*$BinPath*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$BinPath", "User")
    Write-Host "[SUCCESS] Registered $BinPath into Windows User PATH." -ForegroundColor Green
} else {
    Write-Host "[INFO] PATH already configured in Windows Environment." -ForegroundColor Yellow
}

Write-Host "`n[✔] ULPF-X standalone installation complete!" -ForegroundColor Green
Write-Host "Please restart your PowerShell or Terminal window, then run 'ulpx-test'." -ForegroundColor Yellow
Write-Host "=======================================================" -ForegroundColor Cyan