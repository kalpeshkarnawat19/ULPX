# Reset only generated non-frontend demo output. Fixtures and source code remain immutable.
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$demoWork = Join-Path $projectRoot 'work\demo'
if (Test-Path -LiteralPath $demoWork) {
    Remove-Item -LiteralPath $demoWork -Recurse -Force
}
New-Item -ItemType Directory -Path $demoWork -Force | Out-Null
