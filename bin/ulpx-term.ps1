$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (Test-Path "$ScriptDir\ulpx.ps1") {
    & "$ScriptDir\ulpx.ps1" watch @args
    exit $LASTEXITCODE
}
& ulpx watch @args
exit $LASTEXITCODE
