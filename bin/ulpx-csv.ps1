$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (Test-Path "$ScriptDir\ulpx.ps1") {
    & "$ScriptDir\ulpx.ps1" export --format csv @args
    exit $LASTEXITCODE
}
& ulpx export --format csv @args
exit $LASTEXITCODE
