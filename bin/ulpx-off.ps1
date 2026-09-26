$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (Test-Path "$ScriptDir\ulpx.ps1") {
    & "$ScriptDir\ulpx.ps1" daemon stop @args
    exit $LASTEXITCODE
}
& ulpx daemon stop @args
exit $LASTEXITCODE
