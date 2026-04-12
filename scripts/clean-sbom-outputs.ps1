param(
  [Parameter(Mandatory = $true)]
  [string]$SbomPath,
  [Parameter(Mandatory = $true)]
  [string]$ReportPath
)
$ErrorActionPreference = "Stop"

if (Test-Path $ReportPath) {
  Get-ChildItem -LiteralPath $ReportPath -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
}
if (-not (Test-Path $ReportPath)) { New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null }

if (Test-Path $SbomPath) {
  Get-ChildItem -LiteralPath $SbomPath -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in @(".json", ".tar") } |
    Remove-Item -Force
}
