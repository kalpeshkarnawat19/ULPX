# scripts/install.ps1
$ErrorActionPreference = "Stop"

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  ULPF-X Windows Native Standalone Environment Setup" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

$TargetDir = "$ENV:USERPROFILE\.ulpx"

# 1. Create target engine directory
if (-not (Test-Path -Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    Write-Host "[SUCCESS] Created engine home at $TargetDir" -ForegroundColor Green
}

# 2. Mirror source files into .ulpx
Write-Host "[INFO] Synchronizing engine core files..." -ForegroundColor Yellow
Get-ChildItem -Path ".\" -Exclude "*.zip", ".git*" | ForEach-Object {
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

Write-Host "`n[✔] ULPF-X standalone installation complete!" -ForegroundColor Green
Write-Host "Please restart your PowerShell or Terminal window, then run 'ulpx-test'." -ForegroundColor Yellow
Write-Host "=======================================================" -ForegroundColor Cyan