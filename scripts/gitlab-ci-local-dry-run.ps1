<#
.SYNOPSIS
  Native PowerShell wrapper for local GitLab CI stage emulation.

.DESCRIPTION
  Wraps scripts/gitlab-ci-local-dry-run.sh and forwards mode + environment overrides.
  Use this to avoid calling bash manually from Windows PowerShell.

.EXAMPLE
  pwsh -File .\scripts\gitlab-ci-local-dry-run.ps1 -Mode dry-run
  pwsh -File .\scripts\gitlab-ci-local-dry-run.ps1 -Mode smoke
  pwsh -File .\scripts\gitlab-ci-local-dry-run.ps1 -Mode full -AppDir example-app
#>

[CmdletBinding()]
param(
  [ValidateSet("dry-run", "smoke", "full")]
  [string]$Mode = "dry-run",
  [string]$AppDir = "example-app",
  [string]$AppMetadata = "example-app/app-metadata.json",
  [string]$SbomDir = "sbom",
  [string]$ReportDir = "reports",
  [string]$TrivyImage = "aquasec/trivy:0.69.3",
  [string]$SyftImage = "anchore/syft:latest",
  [string]$CycloneDxImage = "cyclonedx/cyclonedx-cli:latest",
  [string]$HopprImage = "hoppr/hopctl:latest",
  [string]$GrypeImage = "anchore/grype:latest"
)

$ErrorActionPreference = "Stop"

function Get-BashCommand {
  if (Get-Command bash -ErrorAction SilentlyContinue) { return "bash" }
  if (Get-Command "C:\Program Files\Git\bin\bash.exe" -ErrorAction SilentlyContinue) { return "C:\Program Files\Git\bin\bash.exe" }
  throw "bash is required. Install Git for Windows (Git Bash) or WSL."
}

function Convert-ToPosixPath {
  param([Parameter(Mandatory = $true)][string]$WindowsPath)
  $p = $WindowsPath -replace "\\", "/"
  if ($p -match "^[A-Za-z]:/") {
    $drive = $p.Substring(0,1).ToLowerInvariant()
    $rest = $p.Substring(2)
    return "/mnt/$drive$rest"
  }
  return $p
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$helperScript = Join-Path $repoRoot "scripts/gitlab-ci-local-dry-run.sh"
if (-not (Test-Path $helperScript)) {
  throw "Missing helper script: $helperScript"
}

$env:APP_DIR = $AppDir
$env:APP_METADATA = $AppMetadata
$env:SBOM_DIR = $SbomDir
$env:REPORT_DIR = $ReportDir
$env:TRIVY_IMAGE = $TrivyImage
$env:SYFT_IMAGE = $SyftImage
$env:CYCLONEDX_IMAGE = $CycloneDxImage
$env:HOPPR_IMAGE = $HopprImage
$env:GRYPE_IMAGE = $GrypeImage

$modeArg = switch ($Mode) {
  "dry-run" { "--dry-run" }
  "smoke" { "--smoke" }
  "full" { "--full" }
  default { "--dry-run" }
}

$bashCmd = Get-BashCommand
$repoRootPosix = Convert-ToPosixPath -WindowsPath $repoRoot
$bashLine = "cd '$repoRootPosix' && ./scripts/gitlab-ci-local-dry-run.sh $modeArg"
Push-Location $repoRoot
try {
  & $bashCmd -lc $bashLine
  if ($LASTEXITCODE -ne 0) {
    throw "Local GitLab CI helper failed with exit code $LASTEXITCODE"
  }
}
finally {
  Pop-Location
}
