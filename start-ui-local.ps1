param(
  # Explicit port (e.g. 8765). Default: pick first free port from -TryPorts.
  [int]$Port = 0,
  # Prefer these ports in order when $Port is 0 and $env:PORT is not set.
  [int[]]$TryPorts = @(5000, 5001, 5002, 8765, 8080, 9090, 5500, 18080)
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$appPath = Join-Path $repoRoot "sbom_ui\app.py"

if (-not (Test-Path $appPath)) {
  throw "Missing UI backend at: $appPath"
}

function Test-PortFree([int]$p) {
  try {
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $p)
    $l.Start()
    $l.Stop()
    return $true
  } catch {
    return $false
  }
}

function Get-FirstFreePort([int[]]$candidates) {
  foreach ($p in $candidates) {
    if (Test-PortFree $p) { return $p }
  }
  for ($p = 49152; $p -le 49200; $p++) {
    if (Test-PortFree $p) { return $p }
  }
  throw "No free TCP port found (tried common ports and 49152–49200)."
}

if ($env:PORT -and $Port -eq 0) {
  $chosen = [int]$env:PORT
  if (-not (Test-PortFree $chosen)) {
    throw "Port $chosen (`$env:PORT) is already in use. Use another: `$env:PORT=8765` or run with -Port 8765"
  }
} elseif ($Port -gt 0) {
  if (-not (Test-PortFree $Port)) {
    throw "Port $Port is already in use. Pick another: -Port 8765"
  }
  $chosen = $Port
} else {
  $chosen = Get-FirstFreePort $TryPorts
}

$env:PORT = "$chosen"

# 0.0.0.0 listens on all interfaces — works for 127.0.0.1, localhost, and hosts-file names (e.g. sbomcontrol.com).
# For stricter local-only: `$env:HOST='127.0.0.1'
if (-not $env:HOST) {
  $env:HOST = "0.0.0.0"
}

$url = "http://127.0.0.1:$chosen"
Write-Host ""
Write-Host "SBOM Mission Control — open this URL in your browser:" -ForegroundColor Green
Write-Host "  $url/" -ForegroundColor Cyan
Write-Host ""
Write-Host "If you use a hosts entry for sbomcontrol.com, use:" -ForegroundColor DarkGray
Write-Host "  http://www.sbomcontrol.com:$chosen/" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Override port:  pwsh -File .\start-ui-local.ps1 -Port 8765" -ForegroundColor DarkGray
Write-Host "Listen on LAN:  `$env:HOST='0.0.0.0'; `$env:PORT='$chosen'; python `"$appPath`"" -ForegroundColor DarkGray
Write-Host "UI stuck / wrong API?  Open: $url/?reset_api=1  (clears saved API base, then reload)" -ForegroundColor DarkGray
Write-Host ""

python $appPath
