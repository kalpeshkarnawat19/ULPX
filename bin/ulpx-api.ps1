$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (Test-Path "$ScriptDir\ulpx.ps1") {
    & "$ScriptDir\ulpx.ps1" api @args
    exit $LASTEXITCODE
}
& ulpx api @args
exit $LASTEXITCODE
