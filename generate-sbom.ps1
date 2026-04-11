<#
.SYNOPSIS
  Generate holistic SBOMs for native or containerized C/C++ applications.

.DESCRIPTION
  Uses COTS tools (Syft, Trivy, Distro2SBOM, CycloneDX-CLI, Hoppr) plus custom metadata enrichment
  to produce a single SBOM containing both third-party/COTS and custom application components.
  Supports native OS (directory scan) and containerized (Docker/Podman image) workflows.

.EXAMPLE
  pwsh ./generate-sbom.ps1 -Mode native
  pwsh ./generate-sbom.ps1 -Mode container
#>
param(
  # Accepts native/container; strips accidental concatenation (e.g. -Mode nativehttp://... from a bad paste).
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

$rawMode = [string]$Mode
$trimMode = $rawMode.Trim()
if ($trimMode.StartsWith("container", [System.StringComparison]::OrdinalIgnoreCase)) {
  $runMode = "container"
} elseif ($trimMode.StartsWith("native", [System.StringComparison]::OrdinalIgnoreCase)) {
  $runMode = "native"
} else {
  $runMode = "native"
}
if ($trimMode -notin @("native", "container")) {
  Write-Warning "Mode was normalized from '$rawMode' to '$runMode'. Use a space after the mode (e.g. -Mode native) and do not paste a URL on the same token."
}

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

# After clearing images, Docker must pull again. Using a pinned tag avoids occasional
# docker.io resolution failures on :latest. Override: $env:TRIVY_IMAGE = "aquasec/trivy:0.69.3"
# Alternate registry: ghcr.io/aquasecurity/trivy:0.69.3
$trivyImage = if ($env:TRIVY_IMAGE) { $env:TRIVY_IMAGE } else { "aquasec/trivy:0.69.3" }
# CycloneDX SBOM steps are inventory-only; Grype/Trivy vuln scans run later on the enriched SBOM.
# Use --quiet (Trivy 0.69+ has no global --log-level; --quiet suppresses progress + most logs).
$trivyQuiet = @("--quiet")

$sbomPath = Join-Path $repoRoot $SbomDir
$reportPath = Join-Path $repoRoot $ReportDir
$appMeta = Join-Path $repoRoot $AppMetadataPath
$mergeScript = Join-Path $repoRoot "merge-sbom.ps1"
$ntiaScript = Join-Path $repoRoot "check-ntia.ps1"

foreach ($dir in $sbomPath, $reportPath) {
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
}
if (-not (Test-Path $appMeta)) { throw "Missing app metadata file at $appMeta (JSON, CSV, or XML — see merge-sbom.ps1)" }
if (-not (Test-Path $mergeScript)) { throw "Missing merge-sbom.ps1" }

# SBOM file names
$syftSbom = Join-Path $sbomPath $(if ($runMode -eq "container") { "sbom-image-syft.json" } else { "sbom-source-syft.json" })
$trivySbom = Join-Path $sbomPath $(if ($runMode -eq "container") { "sbom-image-trivy.json" } else { "sbom-source-trivy.json" })
$distroSbom = Join-Path $sbomPath "sbom-distro2sbom.json"
$rawSbom = Join-Path $sbomPath $(if ($runMode -eq "container") { "sbom-image.cots-merged.json" } else { "sbom-source.cots-merged.json" })
$enrichedSbom = Join-Path $sbomPath $(if ($runMode -eq "container") { "sbom-image.enriched.json" } else { "sbom-source.enriched.json" })
$rawLeaf = Split-Path $rawSbom -Leaf
$enrichedLeaf = Split-Path $enrichedSbom -Leaf
$syftLeaf = Split-Path $syftSbom -Leaf
$trivyLeaf = Split-Path $trivySbom -Leaf
$distroLeaf = Split-Path $distroSbom -Leaf

Write-Host "==> Mode: $runMode | Runtime: $containerCmd"
Write-Host "==> Trivy image: $trivyImage"
Write-Host "==> Pull COTS SBOM tool images (Syft, Trivy, CycloneDX, Hoppr)"
& $containerCmd pull anchore/syft:latest 2>&1 | Out-Host
& $containerCmd pull $trivyImage 2>&1 | Out-Host
& $containerCmd pull cyclonedx/cyclonedx-cli:latest 2>&1 | Out-Host
& $containerCmd pull hoppr/hopctl:latest 2>&1 | Out-Host
& $containerCmd pull anchore/grype:latest 2>&1 | Out-Host

if ($runMode -eq "container") {
  $appDir = Join-Path $repoRoot $SourcePath
  $image = "${ImageName}:${ImageTag}"
  $imageTar = Join-Path $sbomPath "image.tar"
  Write-Host "==> Build image: $image (from $SourcePath)"
  Push-Location $appDir
  try {
    & $containerCmd build -t $image . 2>&1 | Out-Host
  } finally { Pop-Location }
  if ($LASTEXITCODE -ne 0) { throw "Container build failed for image $image" }

  Write-Host "==> Generate COTS SBOM from image (Syft)"
  & $containerCmd save $image -o $imageTar 2>&1 | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "Failed to export image tar for $image" }
  & $containerCmd run --rm -v "${sbomPath}:/data" anchore/syft:latest "docker-archive:/data/image.tar" -o "cyclonedx-json=/data/$syftLeaf" 2>&1 | Out-Host
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $syftSbom)) {
    throw "Syft failed to generate image SBOM ($syftSbom) from docker archive."
  }

  Write-Host "==> Generate COTS SBOM from image (Trivy)"
  $trivyOutput = & $containerCmd run --rm -v "${sbomPath}:/data" $trivyImage @trivyQuiet image --input "/data/image.tar" --format cyclonedx --output "/data/$trivyLeaf" 2>&1
  $trivyOutput | Out-Host
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $trivySbom)) {
    Write-Warning "Trivy image scan via oci-archive failed; falling back to exported rootfs filesystem scan."
    $rootfsTar = Join-Path $sbomPath "image-rootfs.tar"
    $rootfsDir = Join-Path $sbomPath "image-rootfs"
    if (Test-Path $rootfsTar) { Remove-Item $rootfsTar -Force -ErrorAction SilentlyContinue }
    if (Test-Path $rootfsDir) { Remove-Item $rootfsDir -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $rootfsDir -Force | Out-Null

    $tmpContainerId = ""
    try {
      $tmpContainerId = (& $containerCmd create $image).Trim()
      if (-not $tmpContainerId) { throw "Failed to create temporary container from $image" }
      & $containerCmd export $tmpContainerId -o $rootfsTar 2>&1 | Out-Host
      if ($LASTEXITCODE -ne 0 -or -not (Test-Path $rootfsTar)) {
        throw "Failed to export rootfs tar from container $tmpContainerId"
      }
    } finally {
      if ($tmpContainerId) { & $containerCmd rm $tmpContainerId 2>&1 | Out-Null }
    }

    & $containerCmd run --rm -v "${sbomPath}:/data" alpine:3.20 sh -lc "mkdir -p /data/image-rootfs && tar -xf /data/image-rootfs.tar -C /data/image-rootfs" 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Failed to unpack exported rootfs tar for Trivy fallback." }

    & $containerCmd run --rm -v "${rootfsDir}:/scan" -v "${sbomPath}:/data" $trivyImage @trivyQuiet filesystem --format cyclonedx --output "/data/$trivyLeaf" /scan 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $trivySbom)) {
      throw "Trivy failed in both image and filesystem fallback modes ($trivySbom)."
    }
  }
} else {
  $resolvedSource = (Resolve-Path (Join-Path $repoRoot $SourcePath)).Path
  Write-Host "==> Generate COTS SBOM from directory (Syft): $resolvedSource"
  $rawContent = & $containerCmd run --rm -v "${resolvedSource}:/src" anchore/syft:latest dir:/src -o cyclonedx-json 2>$null
  if (-not $rawContent) { throw "Syft failed to generate source SBOM from $resolvedSource" }
  [System.IO.File]::WriteAllText($syftSbom, $rawContent, (New-Object System.Text.UTF8Encoding $false))

  Write-Host "==> Generate COTS SBOM from directory (Trivy): $resolvedSource"
  & $containerCmd run --rm -v "${resolvedSource}:/src" -v "${repoRoot}:/work" $trivyImage @trivyQuiet filesystem --format cyclonedx --output "/work/$SbomDir/$trivyLeaf" /src 2>&1 | Out-Host
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $trivySbom)) {
    throw "Trivy failed to generate filesystem SBOM ($trivySbom)."
  }
}

Write-Host "==> Generate distro package SBOM (Distro2SBOM)"
& $containerCmd run --rm -v "${repoRoot}:/work" python:3.12-slim bash -lc "export PIP_ROOT_USER_ACTION=ignore PIP_DISABLE_PIP_VERSION_CHECK=1; pip install --no-cache-dir distro2sbom >/dev/null && python -m distro2sbom.cli --distro auto --system --sbom cyclonedx --format json --product-type operating-system --product-name sbom-runtime --product-version 1.0 --output-file /work/$SbomDir/$distroLeaf" 2>&1 | Out-Host

Write-Host "==> Merge Syft + Trivy + Distro2SBOM via CycloneDX-CLI"
& $containerCmd run --rm -v "${repoRoot}:/data" cyclonedx/cyclonedx-cli:latest merge --input-files "/data/$SbomDir/$syftLeaf" "/data/$SbomDir/$trivyLeaf" "/data/$SbomDir/$distroLeaf" --output-file "/data/$SbomDir/$rawLeaf" --output-format json 2>&1 | Out-Host

Write-Host "==> Enrich SBOM with app metadata"
& pwsh -ExecutionPolicy Bypass -File $mergeScript -InputSbom $rawSbom -AppMetadata $appMeta -OutputSbom $enrichedSbom 2>&1 | Out-Host

Write-Host "==> Validate CycloneDX schema (CycloneDX-CLI)"
& $containerCmd run --rm -v "${repoRoot}:/data" cyclonedx/cyclonedx-cli:latest validate --input-file "/data/$SbomDir/$enrichedLeaf" 2>&1 | Tee-Object -FilePath (Join-Path $reportPath "cyclonedx-validate.txt")
$cyclonedxExit = $LASTEXITCODE

Write-Host "==> NTIA Minimum Elements (check-ntia.ps1)"
& pwsh -ExecutionPolicy Bypass -File $ntiaScript -SbomFile $enrichedSbom 2>&1 | Out-Host
$ntiaExit = $LASTEXITCODE

Write-Host "==> NTIA validation with Hoppr"
$hopprLog = Join-Path $reportPath "hoppr-ntia.log"
& $containerCmd run --rm -v "${repoRoot}:/data" -w /data hoppr/hopctl validate sbom --sbom "$SbomDir/$enrichedLeaf" --profile ntia --log "/data/$ReportDir/hoppr-ntia.log" --output-file "/data/$ReportDir/hoppr-ntia-results.json" --basic-term 2>&1 | Tee-Object -FilePath (Join-Path $reportPath "hoppr-console.txt")
$hopprExit = $LASTEXITCODE

Write-Host ""
Write-Host "========================="
Write-Host "SBOM Requirements Summary"
Write-Host "========================="
Write-Host "CycloneDX schema:      $([int]$cyclonedxExit -eq 0 ? 'PASS' : 'FAIL')"
Write-Host "NTIA (check-ntia.ps1): $([int]$ntiaExit -eq 0 ? 'PASS' : 'FAIL')"
Write-Host "Hoppr NTIA:           $([int]$hopprExit -eq 0 ? 'PASS' : 'WARN')"
Write-Host ""
Write-Host "Outputs:"
Write-Host "  Syft SBOM:       $syftSbom"
Write-Host "  Trivy SBOM:      $trivySbom"
Write-Host "  Distro2SBOM:     $distroSbom"
Write-Host "  Merged COTS:     $rawSbom"
Write-Host "  Enriched SBOM:   $enrichedSbom"
Write-Host "  Hoppr log:       $hopprLog"

$unsignedV16 = Join-Path $sbomPath "$(Split-Path $enrichedSbom -LeafBase).unsigned.v16.json"
$unsignedV16Leaf = Split-Path $unsignedV16 -Leaf

Write-Host "==> Convert enriched SBOM to CycloneDX v1.6 for scanner compatibility"
& $containerCmd run --rm -v "${repoRoot}:/data" cyclonedx/cyclonedx-cli:latest convert --input-file "/data/$SbomDir/$enrichedLeaf" --output-file "/data/$SbomDir/$unsignedV16Leaf" --output-format json --output-version v1_6 2>&1 | Out-Host

Write-Host "==> Vulnerability scan with Grype (plus DB evidence)"
$grypeImage = if ($env:GRYPE_IMAGE) { $env:GRYPE_IMAGE } else { "anchore/grype:latest" }
# Mount a single explicit DB dir so Grype does not write under /.cache when HOME is unset (fixes "database does not exist" on the mounted volume).
$grypeCacheDir = Join-Path $repoRoot ".cache\grype-db"
if (-not (Test-Path $grypeCacheDir)) { New-Item -ItemType Directory -Path $grypeCacheDir -Force | Out-Null }
$grypeDbVol = @("-e", "GRYPE_DB_CACHE_DIR=/grype-db", "-v", "${grypeCacheDir}:/grype-db")
& $containerCmd run --rm @grypeDbVol $grypeImage db update 2>&1 | Tee-Object -FilePath (Join-Path $reportPath "grype-db-update.txt")
& $containerCmd run --rm @grypeDbVol $grypeImage db status 2>&1 | Tee-Object -FilePath (Join-Path $reportPath "grype-db-status.txt")
& $containerCmd run --rm @grypeDbVol $grypeImage db providers 2>&1 | Tee-Object -FilePath (Join-Path $reportPath "grype-db-providers.txt")
& $containerCmd run --rm -v "${repoRoot}:/data" @grypeDbVol $grypeImage "sbom:/data/$SbomDir/$unsignedV16Leaf" -o json 2> (Join-Path $reportPath "grype-report.stderr.log") | Set-Content -Path (Join-Path $reportPath "grype-report.json") -Encoding UTF8
& $containerCmd run --rm -v "${repoRoot}:/data" @grypeDbVol $grypeImage "sbom:/data/$SbomDir/$unsignedV16Leaf" -o table 2>&1 | Set-Content -Path (Join-Path $reportPath "grype-report.txt") -Encoding UTF8

Write-Host "==> Secondary vulnerability scan with Trivy SBOM (NVD/GHSA/OSV sources) — image: $trivyImage"
& $containerCmd run --rm -v "${repoRoot}:/data" $trivyImage sbom --scanners vuln --vuln-severity-source nvd,ghsa,osv --format json --output "/data/$ReportDir/trivy-sbom-report.json" "/data/$SbomDir/$unsignedV16Leaf" 2>&1 | Out-Host
& $containerCmd run --rm -v "${repoRoot}:/data" $trivyImage sbom --scanners vuln --vuln-severity-source nvd,ghsa,osv --format table --output "/data/$ReportDir/trivy-sbom-report.txt" "/data/$SbomDir/$unsignedV16Leaf" 2>&1 | Out-Host

Write-Host "==> Build combined vulnerability summary"
$grypeJson = Join-Path $reportPath "grype-report.json"
$trivyJson = Join-Path $reportPath "trivy-sbom-report.json"
if ((Test-Path $grypeJson) -and (Test-Path $trivyJson)) {
  $grype = Get-Content $grypeJson -Raw | ConvertFrom-Json
  $trivy = Get-Content $trivyJson -Raw | ConvertFrom-Json
  $gMatches = @($grype.matches)
  $tVulns = @()
  foreach ($r in @($trivy.Results)) { $tVulns += @($r.Vulnerabilities) }
  @(
    "Vulnerability Analysis Summary"
    "=============================="
    "Grype total: $($gMatches.Count)"
    "Trivy total: $($tVulns.Count)"
    ""
    "Trivy severity breakdown:"
    "Critical: $(@($tVulns | Where-Object { $_.Severity -eq 'CRITICAL' }).Count)"
    "High: $(@($tVulns | Where-Object { $_.Severity -eq 'HIGH' }).Count)"
    "Medium: $(@($tVulns | Where-Object { $_.Severity -eq 'MEDIUM' }).Count)"
    "Low: $(@($tVulns | Where-Object { $_.Severity -eq 'LOW' }).Count)"
  ) | Set-Content -Path (Join-Path $reportPath "vulnerability-analysis.txt") -Encoding UTF8
}

if ($RunSign -and (Test-Path (Join-Path $repoRoot "scripts/sign-sbom.sh"))) {
  Write-Host "==> Sign SBOM (requires bash - run in Git Bash or WSL)"
  Write-Host "    bash scripts/sign-sbom.sh `"$enrichedSbom`" `"$sbomPath/sbom-signed.json`" `"$sbomPath/pki`""
}
