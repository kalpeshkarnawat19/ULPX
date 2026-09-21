$ErrorActionPreference = "Stop"
$INSTALL_DIR = "$env:USERPROFILE\.ulpx"

Write-Host "📦 Registering ULPF-X Engine globally at: $INSTALL_DIR" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
Copy-Item -Recurse -Force -Path ".*", "*" -Destination $INSTALL_DIR

# 1. Register with Windows CMake Registry
$RegPath = "HKCU:\Software\Kitware\CMake\Packages\ulpx"
if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
New-ItemProperty -Path $RegPath -Name "ULPX" -Value $INSTALL_DIR -PropertyType String -Force | Out-Null
Write-Host "  ✓ Registered with Windows CMake Registry" -ForegroundColor Green

# 2. Add scripts folder to User Path
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$INSTALL_DIR\scripts*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$INSTALL_DIR\scripts", "User")
}

# 3. Create persistent aliases in PowerShell Profile
if (-not (Test-Path $PROFILE)) { New-Item -Type File -Path $PROFILE -Force | Out-Null }
$Hook = "`n# ULPF-X Global Hook`n`$env:ULPX_HOME = '$INSTALL_DIR'`nSet-Alias ulpx 'python `$env:ULPX_HOME\scripts\demo.py'`nSet-Alias ulpx-test 'python `$env:ULPX_HOME\scripts\audit.py'`n"
if ((Get-Content $PROFILE -Raw) -notlike "*ULPX_HOME*") {
    Add-Content -Path $PROFILE -Value $Hook
    Write-Host "  ✓ Injected persistent hook into PowerShell Profile" -ForegroundColor Green
}

Write-Host "`n✅ ULPF-X is active across all terminals and CMake contexts!" -ForegroundColor Green
