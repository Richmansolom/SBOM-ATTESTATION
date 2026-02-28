<#
.SYNOPSIS
  Generate SBOM for native or containerized applications. Validates against NTIA Minimum Elements (check-ntia.ps1 + Hoppr).

.DESCRIPTION
  Supports both native OS (directory scan) and containerized (Docker/Podman image) applications.
  NTIA validation via check-ntia.ps1 and Hoppr.

.EXAMPLE
  pwsh ./generate-sbom.ps1 -Mode native
  pwsh ./generate-sbom.ps1 -Mode container
#>
param(
  [ValidateSet("container", "native")]
  [string]$Mode = "native",
  [ValidateSet("auto", "docker", "podman")]
  [string]$ContainerRuntime = "auto",
  [string]$SourcePath = "example-app",
  [string]$ImageName = "sbom-demo-app",
  [string]$ImageTag = "1.0",
  [string]$SbomDir = "sbom",
  [string]$ReportDir = "reports",
  [string]$AppMetadataPath = "example-app/app-metadata.json",
  [switch]$RunSign
)

$ErrorActionPreference = "Stop"
$repoRoot = Get-Location

function Resolve-ContainerRuntime([string]$requested) {
  if ($requested -eq "docker" -or $requested -eq "podman") {
    if (-not (Get-Command $requested -ErrorAction SilentlyContinue)) { throw "Missing: $requested" }
    return $requested
  }
  if (Get-Command docker -ErrorAction SilentlyContinue) { return "docker" }
  if (Get-Command podman -ErrorAction SilentlyContinue) { return "podman" }
  throw "Missing: docker or podman"
}

$containerCmd = Resolve-ContainerRuntime $ContainerRuntime
$sbomPath = Join-Path $repoRoot $SbomDir
$reportPath = Join-Path $repoRoot $ReportDir
$appMeta = Join-Path $repoRoot $AppMetadataPath
$mergeScript = Join-Path $repoRoot "merge-sbom.ps1"
$ntiaScript = Join-Path $repoRoot "check-ntia.ps1"

foreach ($dir in $sbomPath, $reportPath) {
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
}
if (-not (Test-Path $appMeta)) { throw "Missing app-metadata.json at $appMeta" }
if (-not (Test-Path $mergeScript)) { throw "Missing merge-sbom.ps1" }

# SBOM file names
$rawSbom = Join-Path $sbomPath $(if ($Mode -eq "container") { "sbom-image.json" } else { "sbom-source.json" })
$enrichedSbom = Join-Path $sbomPath $(if ($Mode -eq "container") { "sbom-image.enriched.json" } else { "sbom-source.enriched.json" })
$rawLeaf = Split-Path $rawSbom -Leaf
$enrichedLeaf = Split-Path $enrichedSbom -Leaf

Write-Host "==> Mode: $Mode | Runtime: $containerCmd"
Write-Host "==> Pull Syft"
& $containerCmd pull anchore/syft:latest 2>&1 | Out-Host

if ($Mode -eq "container") {
  $appDir = Join-Path $repoRoot $SourcePath
  $image = "${ImageName}:${ImageTag}"
  Write-Host "==> Build image: $image (from $SourcePath)"
  Push-Location $appDir
  try {
    & $containerCmd build -t $image . 2>&1 | Out-Host
  } finally { Pop-Location }
  Write-Host "==> Generate SBOM from image"
  $rawContent = & $containerCmd run --rm -v "/var/run/docker.sock:/var/run/docker.sock" anchore/syft:latest $image -o cyclonedx-json 2>&1
  if ($containerCmd -eq "podman") {
    $imageTar = Join-Path $sbomPath "image.tar"
    & $containerCmd save $image -o $imageTar 2>&1 | Out-Host
    $rawContent = & $containerCmd run --rm -v "${sbomPath}:/data" anchore/syft:latest "oci-archive:/data/image.tar" -o cyclonedx-json 2>&1
  }
  [System.IO.File]::WriteAllText($rawSbom, $rawContent, (New-Object System.Text.UTF8Encoding $false))
} else {
  $resolvedSource = (Resolve-Path (Join-Path $repoRoot $SourcePath)).Path
  Write-Host "==> Generate SBOM from directory: $resolvedSource"
  $rawContent = & $containerCmd run --rm -v "${resolvedSource}:/src" anchore/syft:latest dir:/src -o cyclonedx-json 2>&1
  [System.IO.File]::WriteAllText($rawSbom, $rawContent, (New-Object System.Text.UTF8Encoding $false))
}

Write-Host "==> Enrich SBOM with app metadata"
& pwsh -ExecutionPolicy Bypass -File $mergeScript -InputSbom $rawSbom -AppMetadata $appMeta -OutputSbom $enrichedSbom 2>&1 | Out-Host

Write-Host "==> NTIA Minimum Elements (check-ntia.ps1)"
& pwsh -ExecutionPolicy Bypass -File $ntiaScript -SbomFile $enrichedSbom 2>&1 | Out-Host
$ntiaExit = $LASTEXITCODE

Write-Host "==> NTIA validation with Hoppr"
& $containerCmd pull hoppr/hopctl:latest 2>&1 | Out-Host
$hopprLog = Join-Path $reportPath "hoppr-ntia.log"
& $containerCmd run --rm -v "${repoRoot}:/data" -w /data hoppr/hopctl validate sbom --sbom "$SbomDir/$enrichedLeaf" --profile ntia --log-file "/data/$ReportDir/hoppr-ntia.log" --verbose 2>&1 | Tee-Object -FilePath (Join-Path $reportPath "hoppr-console.txt")
$hopprExit = $LASTEXITCODE

Write-Host ""
Write-Host "========================="
Write-Host "SBOM Requirements Summary"
Write-Host "========================="
Write-Host "NTIA (check-ntia.ps1): $([int]$ntiaExit -eq 0 ? 'PASS' : 'FAIL')"
Write-Host "Hoppr NTIA:           $([int]$hopprExit -eq 0 ? 'PASS' : 'WARN')"
Write-Host ""
Write-Host "Outputs:"
Write-Host "  Raw SBOM:     $rawSbom"
Write-Host "  Enriched:     $enrichedSbom"
Write-Host "  Hoppr log:    $hopprLog"

if ($RunSign -and (Test-Path (Join-Path $repoRoot "scripts/sign-sbom.sh"))) {
  Write-Host "==> Sign SBOM (requires bash - run in Git Bash or WSL)"
  Write-Host "    bash scripts/sign-sbom.sh `"$enrichedSbom`" `"$sbomPath/sbom-signed.json`" `"$sbomPath/pki`""
}
