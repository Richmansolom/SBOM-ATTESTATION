param(
  [Parameter(Mandatory = $true)]
  [string]$SbomFile
)

Write-Host "NTIA SBOM Minimum Elements Check"
Write-Host "--------------------------------"

if (-not (Test-Path $SbomFile)) {
  Write-Error "SBOM file not found: $SbomFile"
  exit 1
}

$sbom = Get-Content $SbomFile -Raw | ConvertFrom-Json
$errors = @()

function Get-RootComponent($sbomObj) {
  if ($sbomObj.metadata -and $sbomObj.metadata.component) {
    return $sbomObj.metadata.component
  }
  if ($sbomObj.components) {
    $app = $sbomObj.components | Where-Object { $_.type -eq "application" } | Select-Object -First 1
    if ($app) { return $app }
    return $sbomObj.components | Select-Object -First 1
  }
  return $null
}

function Get-SupplierName($sbomObj, $component) {
  if ($component -and $component.supplier -and $component.supplier.name) {
    return $component.supplier.name
  }
  if ($sbomObj.metadata -and $sbomObj.metadata.supplier -and $sbomObj.metadata.supplier.name) {
    return $sbomObj.metadata.supplier.name
  }
  return $null
}

$root = Get-RootComponent $sbom

if ([string]::IsNullOrWhiteSpace((Get-SupplierName $sbom $root))) {
  $errors += "supplier missing"
} else { Write-Host "supplier present" }

$name = $null
if ($root) { $name = $root.name }
if ([string]::IsNullOrWhiteSpace($name)) {
  $errors += "name missing"
} else { Write-Host "name present" }

$version = $null
if ($root) { $version = $root.version }
if ([string]::IsNullOrWhiteSpace($version)) {
  $errors += "version missing"
} else { Write-Host "version present" }

if ([string]::IsNullOrWhiteSpace($sbom.metadata.timestamp)) {
  $errors += "timestamp missing"
} else { Write-Host "timestamp present" }

$type = $null
if ($root) { $type = $root.type }
if ([string]::IsNullOrWhiteSpace($type)) {
  $errors += "component type missing"
} else { Write-Host "component type present" }

if (-not $sbom.dependencies -or $sbom.dependencies.Count -eq 0) {
  $errors += "dependencies missing"
} else { Write-Host "dependencies present" }

Write-Host ""

if ($errors.Count -gt 0) {
  Write-Host "FAIL: SBOM does NOT meet NTIA Minimum Elements"
  $errors | ForEach-Object { Write-Host " - $_" }
  exit 1
} else {
  Write-Host "PASS: SBOM meets NTIA Minimum Elements."
  exit 0
}
