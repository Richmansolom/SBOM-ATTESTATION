param(
  [Parameter(Mandatory=$true)]
  [string]$InputSbom,

  [Parameter(Mandatory=$true)]
  [string]$AppMetadata,

  [Parameter(Mandatory=$true)]
  [string]$OutputSbom
)

$ErrorActionPreference = "Stop"

function SafeStr($v) {
  if ($null -eq $v -or [string]::IsNullOrWhiteSpace([string]$v)) { return "unknown" }
  return [string]$v
}

function Write-Utf8NoBom([string]$path, [string]$content) {
  [System.IO.File]::WriteAllText(
    $path,
    $content,
    (New-Object System.Text.UTF8Encoding $false)
  )
}

function Get-DefaultSupplier($component) {
  $purl = [string]$component.purl
  if ([string]::IsNullOrWhiteSpace($purl)) { return "Unknown" }
  if ($purl -match "pkg:deb/ubuntu/") { return "Canonical Ltd." }
  if ($purl -match "pkg:deb/debian/") { return "Debian Project" }
  return "Unknown"
}

function Ensure-LicensingField($licEntry) {
  if (-not $licEntry.PSObject.Properties.Name -contains "licensing") {
    $licEntry | Add-Member -MemberType NoteProperty -Name licensing -Value @{} -Force
  }
}

function Normalize-ComponentLicenses($component) {
  if (-not $component) { return }
  if (-not $component.supplier -or -not $component.supplier.name) {
    $supplierName = Get-DefaultSupplier $component
    $supplierObj = @{ name = $supplierName; url = @() }
    if ($component.PSObject.Properties.Name -contains "supplier") {
      $component.supplier = $supplierObj
    } else {
      $component | Add-Member -MemberType NoteProperty -Name supplier -Value $supplierObj
    }
  }
  if (-not $component.licenses -or $component.licenses.Count -eq 0) {
    $licensesValue = @(@{ license = @{ name = "unknown" }; licensing = @{} })
    if ($component.PSObject.Properties.Name -contains "licenses") {
      $component.licenses = $licensesValue
    } else {
      $component | Add-Member -MemberType NoteProperty -Name licenses -Value $licensesValue
    }
    return
  }
  $normalized = @()
  foreach ($lic in @($component.licenses)) {
    if ($null -eq $lic) { continue }
    if ($lic -is [string]) {
      $normalized += @{ license = @{ name = [string]$lic }; licensing = @{} }
      continue
    }
    if ($lic.PSObject.Properties.Name -contains "expression") {
      Ensure-LicensingField $lic
      $normalized += $lic
      continue
    }
    $licenseObj = $lic.license
    if ($licenseObj -is [string]) { $licenseObj = @{ name = [string]$licenseObj } }
    elseif (-not $licenseObj) { $licenseObj = @{ name = "unknown" } }
    if (-not ($licenseObj.PSObject.Properties.Name -contains "name") -or [string]::IsNullOrWhiteSpace([string]$licenseObj.name)) {
      $licenseObj | Add-Member -MemberType NoteProperty -Name name -Value "unknown" -Force
    }
    Ensure-LicensingField $lic
    $normalized += $lic
  }
  $component.licenses = $normalized
}

if (-not (Test-Path $InputSbom)) { throw "Input SBOM not found: $InputSbom" }
if (-not (Test-Path $AppMetadata)) { throw "App metadata not found: $AppMetadata" }

$sbomRaw = Get-Content $InputSbom -Raw
if ([string]::IsNullOrWhiteSpace($sbomRaw)) { throw "Input SBOM is empty." }

try { $sbom = $sbomRaw | ConvertFrom-Json }
catch { throw "Input SBOM is not valid JSON." }

$app = Get-Content $AppMetadata -Raw | ConvertFrom-Json

if (-not ($sbom.PSObject.Properties.Name -contains "metadata") -or $null -eq $sbom.metadata) {
  $sbom | Add-Member -MemberType NoteProperty -Name metadata -Value ([ordered]@{})
}

$sbom.metadata.timestamp = (Get-Date).ToString("o")

$supplierName = SafeStr $app.supplier.name
$supplierUrls = @()
foreach ($item in @($app.supplier.url)) {
  if ($null -ne $item -and $item -ne "") { $supplierUrls += [string]$item }
}
$supplierUrls = [object[]]$supplierUrls

if ($sbom.metadata.PSObject.Properties.Name -contains "supplier") {
  $sbom.metadata.supplier = @{ name = $supplierName; url = $supplierUrls }
} else {
  $sbom.metadata | Add-Member -MemberType NoteProperty -Name supplier -Value @{ name = $supplierName; url = $supplierUrls }
}

$appLicense = SafeStr $app.license
$licensesValue = @(@{ license = @{ name = $appLicense }; licensing = @{} })
$meta = $sbom.metadata
if (-not $meta.licenses -or $meta.licenses.Count -eq 0) {
  $meta | Add-Member -MemberType NoteProperty -Name licenses -Value $licensesValue -Force
}

$appName = SafeStr $app.name
$appVersion = SafeStr $app.version
$appBomRef = "pkg:generic/$($appName)@$($appVersion)"

$customComponent = @{
  "bom-ref"   = $appBomRef
  type        = "application"
  name        = $appName
  version     = $appVersion
  description = SafeStr $app.description
  publisher   = $supplierName
  supplier    = @{ name = $supplierName; url = $supplierUrls }
  licenses    = @(@{ license = @{ name = SafeStr $app.license }; licensing = @{} })
  externalReferences = @(@{ type = "vcs"; url = SafeStr $app.repository })
  properties = @(
    @{ name = "language"; value = SafeStr $app.language },
    @{ name = "author"; value = SafeStr $app.author },
    @{ name = "build_system"; value = SafeStr $app.build_system },
    @{ name = "entry_point"; value = SafeStr $app.entry_point },
    @{ name = "source_file"; value = SafeStr $app.source_file }
  )
}

if (-not $sbom.components) { $sbom | Add-Member -MemberType NoteProperty -Name components -Value @() }

$already = $false
foreach ($c in $sbom.components) {
  if ($c.name -eq $appName -and $c.version -eq $appVersion) { $already = $true; break }
}
if (-not $already) { $sbom.components += $customComponent }

$sbom.metadata.component = $customComponent

foreach ($c in $sbom.components) { Normalize-ComponentLicenses $c }

if (-not $sbom.dependencies) { $sbom | Add-Member -MemberType NoteProperty -Name dependencies -Value @() }

foreach ($c in $sbom.components) {
  if (-not $c.'bom-ref') {
    $c | Add-Member -MemberType NoteProperty -Name 'bom-ref' -Value ("anon:" + [guid]::NewGuid().ToString())
  }
}

$depRefs = @()
foreach ($c in $sbom.components) {
  if ($c.'bom-ref' -ne $appBomRef) { $depRefs += $c.'bom-ref' }
}

$rootIndex = -1
for ($i = 0; $i -lt $sbom.dependencies.Count; $i++) {
  if ($sbom.dependencies[$i].ref -eq $appBomRef) { $rootIndex = $i; break }
}

$rootDep = @{ ref = $appBomRef; dependsOn = $depRefs }
if ($rootIndex -ge 0) { $sbom.dependencies[$rootIndex] = $rootDep }
else { $sbom.dependencies += $rootDep }

$sbomJson = $sbom | ConvertTo-Json -Depth 40
Write-Utf8NoBom -path $OutputSbom -content $sbomJson
Write-Host "Enriched SBOM written to $OutputSbom"
