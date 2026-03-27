# One command: Mission Control UI (Windows). Keep this window open. Then open the URL it prints.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:HOST = "0.0.0.0"
if (-not $env:PORT) { $env:PORT = "5000" }
Write-Host ""
Write-Host "Keep this window OPEN while you use the UI." -ForegroundColor Yellow
Write-Host "Browser: http://127.0.0.1:$($env:PORT)/   or   http://www.sbomcontrol.com:$($env:PORT)/" -ForegroundColor Cyan
Write-Host ""
python .\sbom_ui\app.py
