$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$appPath = Join-Path $repoRoot "sbom_ui\app.py"

if (-not (Test-Path $appPath)) {
  throw "Missing UI backend at: $appPath"
}

# Prefer clean URL without :5000
$env:HOST = "0.0.0.0"
$env:PORT = "80"

Write-Host "Starting SBOM UI on http://127.0.0.1 (port 80)..."
Write-Host "If port 80 is in use, stop that process or set `$env:PORT=5000 and run again."

python $appPath
