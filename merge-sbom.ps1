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

function Get-Slug($s) {
  if ([string]::IsNullOrWhiteSpace($s)) { return "unknown" }
  $slug = [string]$s -replace '[^a-zA-Z0-9]+', '_' -replace '^_|_$', ''
  if ([string]::IsNullOrWhiteSpace($slug)) { return "unknown" }
  return $slug.ToLowerInvariant()
}

function Get-PurlFromApp($app) {
  $purl = $app.purl
  if (-not [string]::IsNullOrWhiteSpace($purl)) { return $purl.Trim() }
  $repo = [string]$app.repository
  if ($repo -match 'github\.com[/:]([^/]+)/([^/\.]+)') {
    $org = $Matches[1]; $proj = $Matches[2]
    return "pkg:github/$org/$proj@$($app.version)"
  }
  $slug = Get-Slug $app.name
  return "pkg:generic/$slug@$($app.version)"
}

function Get-CpeFromApp($app) {
  $cpe = $app.cpe
  if (-not [string]::IsNullOrWhiteSpace($cpe)) { return $cpe.Trim() }
  $vendorName = "unknown"
  if ($app.supplier -and $app.supplier.name) { $vendorName = $app.supplier.name }
  $vendor = Get-Slug $vendorName
  $product = Get-Slug $app.name
  $ver = [string]$app.version
  if ([string]::IsNullOrWhiteSpace($ver)) { $ver = "0" }
  return "cpe:2.3:a:$($vendor):$($product):$($ver):*:*:*:*:*:*:*"
}

function Get-CpeFromSubComponent($name, $version, $supplierName) {
  $vendor = Get-Slug $supplierName
  $product = Get-Slug $name
  $ver = [string]$version
  if ([string]::IsNullOrWhiteSpace($ver)) { $ver = "0" }
  return "cpe:2.3:a:$($vendor):$($product):$($ver):*:*:*:*:*:*:*"
}

# --- Load app metadata: JSON (extended), CSV, or XML ---
function Read-AppMetadataJson([string]$raw) {
  $app = $raw | ConvertFrom-Json
  if (-not $app.supplier) { throw "app-metadata JSON: missing supplier" }
  if (-not $app.supplier.name) { throw "app-metadata JSON: missing supplier.name" }
  return $app
}

function Read-AppMetadataCsv([string]$path) {
  $rows = Import-Csv -Path $path
  if (-not $rows -or $rows.Count -eq 0) { throw "CSV metadata is empty: $path" }
  $appRow = $null
  foreach ($r in $rows) {
    $k = SafeStr $r.Kind
    if ($k -eq "Application") { $appRow = $r; break }
  }
  if (-not $appRow) { throw "CSV metadata must include one row with Kind=Application" }

  $supplierUrls = @()
  $su = $appRow.SupplierUrl
  if (-not [string]::IsNullOrWhiteSpace($su)) {
    foreach ($part in ($su -split '[|;]')) {
      $t = $part.Trim()
      if ($t) { $supplierUrls += $t }
    }
  }

  $custom = @()
  foreach ($r in $rows) {
    $k = SafeStr $r.Kind
    if ($k -ne "Library") { continue }
    $deps = @()
    $do = $r.DependsOn
    if (-not [string]::IsNullOrWhiteSpace($do)) {
      foreach ($part in ($do -split '[;,]')) {
        $t = $part.Trim()
        if ($t) { $deps += $t }
      }
    }
    $custom += [ordered]@{
      ref          = SafeStr $r.Ref
      name         = SafeStr $r.Name
      version      = SafeStr $r.Version
      type         = if ([string]::IsNullOrWhiteSpace($r.Type)) { "library" } else { $r.Type.Trim() }
      description  = SafeStr $r.Description
      license      = SafeStr $r.License
      depends_on   = $deps
      source_file  = if ($r.PSObject.Properties.Name -contains "SourceFile") { SafeStr $r.SourceFile } else { "" }
    }
  }

  $appPurlCsv = $null
  if ($appRow.PSObject.Properties.Name -contains 'Ref' -and $appRow.Ref -and "$($appRow.Ref)".Trim()) {
    $appPurlCsv = "$($appRow.Ref)".Trim()
  }

  return [ordered]@{
    name            = SafeStr $appRow.Name
    version         = SafeStr $appRow.Version
    description     = SafeStr $appRow.Description
    language        = SafeStr $appRow.Language
    author          = SafeStr $appRow.Author
    license         = SafeStr $appRow.License
    build_system    = SafeStr $appRow.BuildSystem
    entry_point     = SafeStr $appRow.EntryPoint
    source_file     = SafeStr $appRow.SourceFile
    repository      = SafeStr $appRow.Repository
    purl            = $appPurlCsv
    supplier        = @{ name = SafeStr $appRow.SupplierName; url = $supplierUrls }
    custom_components = [array]$custom
  }
}

function Read-AppMetadataXml([string]$path) {
  [xml]$x = Get-Content -Path $path -Encoding UTF8
  $root = $x.AppMetadata
  if (-not $root) { throw "XML metadata: root element must be AppMetadata" }
  $sup = $root.Supplier
  if (-not $sup) { throw "XML metadata: missing Supplier" }
  $supplierUrls = @()
  foreach ($u in $sup.Url) {
    if ($u -and "$u".Trim()) { $supplierUrls += "$u".Trim() }
  }
  $a = $root.Application
  if (-not $a) { throw "XML metadata: missing Application" }

  $custom = @()
  $ccRoot = $root.CustomComponents
  if ($ccRoot -and $ccRoot.Component) {
    foreach ($node in $ccRoot.Component) {
      $deps = @()
      if ($node.DependsOn) {
        foreach ($d in $node.DependsOn) {
          $refAttr = $d.Ref
          if ($refAttr) { $deps += "$refAttr".Trim() }
        }
      }
      $custom += [ordered]@{
        ref          = "$($node.Ref)".Trim()
        name         = "$($node.Name)".Trim()
        version      = "$($node.Version)".Trim()
        type         = if ($node.Type) { "$($node.Type)".Trim() } else { "library" }
        description  = if ($node.Description) { "$($node.Description)".Trim() } else { "unknown" }
        license      = if ($node.License) { "$($node.License)".Trim() } else { "" }
        depends_on   = $deps
        source_file  = if ($node.SourceFile) { "$($node.SourceFile)".Trim() } else { "" }
      }
    }
  }

  $appPurlXml = $null
  if ($a.Purl) { $appPurlXml = "$($a.Purl)".Trim() }

  return [ordered]@{
    name            = "$($a.Name)".Trim()
    version         = "$($a.Version)".Trim()
    description     = if ($a.Description) { "$($a.Description)".Trim() } else { "unknown" }
    language        = if ($a.Language) { "$($a.Language)".Trim() } else { "unknown" }
    author          = if ($a.Author) { "$($a.Author)".Trim() } else { "unknown" }
    license         = if ($a.License) { "$($a.License)".Trim() } else { "unknown" }
    build_system    = if ($a.BuildSystem) { "$($a.BuildSystem)".Trim() } else { "unknown" }
    entry_point     = if ($a.EntryPoint) { "$($a.EntryPoint)".Trim() } else { "unknown" }
    source_file     = if ($a.SourceFile) { "$($a.SourceFile)".Trim() } else { "unknown" }
    repository      = if ($a.Repository) { "$($a.Repository)".Trim() } else { "unknown" }
    purl            = $appPurlXml
    supplier        = @{ name = "$($sup.Name)".Trim(); url = $supplierUrls }
    custom_components = [array]$custom
  }
}

function Read-AppMetadataFile([string]$path) {
  if (-not (Test-Path $path)) { throw "App metadata not found: $path" }
  $ext = [System.IO.Path]::GetExtension($path).ToLowerInvariant()
  switch ($ext) {
    '.json' { return Read-AppMetadataJson (Get-Content -Path $path -Raw -Encoding UTF8) }
    '.csv'  { return Read-AppMetadataCsv $path }
    '.xml'  { return Read-AppMetadataXml $path }
    default { throw "Unsupported app metadata extension '$ext' for $path - use .json, .csv, or .xml" }
  }
}

function Get-DependsOnList($cc) {
  $raw = $null
  if ($cc.PSObject.Properties.Name -contains 'depends_on') { $raw = $cc.depends_on }
  elseif ($cc.PSObject.Properties.Name -contains 'dependsOn') { $raw = $cc.dependsOn }
  if ($null -eq $raw) { return @() }
  if ($raw -is [string]) {
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
    return @($raw -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  }
  return @($raw)
}

function Get-CustomRootRefs([object[]]$customList) {
  if (-not $customList -or $customList.Count -eq 0) { return @() }
  $depended = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($cc in $customList) {
    foreach ($d in (Get-DependsOnList $cc)) { [void]$depended.Add($d) }
  }
  $top = @()
  foreach ($cc in $customList) {
    $r = SafeStr $cc.ref
    if ([string]::IsNullOrWhiteSpace($r)) { continue }
    if (-not $depended.Contains($r)) { $top += $r }
  }
  return $top
}

# SPDX license id -> { name, url } for proper CycloneDX licensing structure
$script:SPDX_LICENSES = @{
  "MIT" = @{ name = "MIT License"; url = "https://spdx.org/licenses/MIT.html" }
  "Apache-2.0" = @{ name = "Apache License 2.0"; url = "https://spdx.org/licenses/Apache-2.0.html" }
  "Apache-1.1" = @{ name = "Apache Software License 1.1"; url = "https://spdx.org/licenses/Apache-1.1.html" }
  "BSD-2-Clause" = @{ name = "BSD 2-Clause License"; url = "https://spdx.org/licenses/BSD-2-Clause.html" }
  "BSD-3-Clause" = @{ name = "BSD 3-Clause License"; url = "https://spdx.org/licenses/BSD-3-Clause.html" }
  "GPL-2.0-only" = @{ name = "GNU General Public License v2.0 only"; url = "https://spdx.org/licenses/GPL-2.0-only.html" }
  "GPL-2.0" = @{ name = "GNU General Public License v2.0"; url = "https://spdx.org/licenses/GPL-2.0.html" }
  "GPL-3.0" = @{ name = "GNU General Public License v3.0"; url = "https://spdx.org/licenses/GPL-3.0.html" }
  "GPL-3.0-only" = @{ name = "GNU General Public License v3.0 only"; url = "https://spdx.org/licenses/GPL-3.0-only.html" }
  "LGPL-2.1" = @{ name = "GNU Lesser General Public License v2.1"; url = "https://spdx.org/licenses/LGPL-2.1.html" }
  "LGPL-3.0" = @{ name = "GNU Lesser General Public License v3.0"; url = "https://spdx.org/licenses/LGPL-3.0.html" }
  "MPL-2.0" = @{ name = "Mozilla Public License 2.0"; url = "https://spdx.org/licenses/MPL-2.0.html" }
  "ISC" = @{ name = "ISC License"; url = "https://spdx.org/licenses/ISC.html" }
  "Unlicense" = @{ name = "The Unlicense"; url = "https://spdx.org/licenses/Unlicense.html" }
}

function ToCycloneDxLicenseEntry($licenseInput) {
  $raw = [string]$licenseInput
  if ([string]::IsNullOrWhiteSpace($raw) -or $raw -eq "unknown") {
    return @{ license = @{ name = "unknown" } }
  }
  $id = $raw.Trim()
  if ($script:SPDX_LICENSES.ContainsKey($id)) {
    return @{ license = @{ id = $id } }
  }
  if ($id -notmatch '\s' -and $id -match '^[A-Za-z0-9.+_\-]+$') {
    return @{ license = @{ id = $id } }
  }
  return @{ license = @{ name = $id } }
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
    $licensesValue = @(ToCycloneDxLicenseEntry "unknown")
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
      $normalized += ToCycloneDxLicenseEntry [string]$lic
      continue
    }
    if ($lic.PSObject.Properties.Name -contains "expression") {
      $normalized += @{ expression = [string]$lic.expression }
      continue
    }
    $licenseObj = $lic.license
    $licId = $null
    if ($licenseObj -is [string]) { $licId = [string]$licenseObj }
    elseif ($licenseObj -and $licenseObj.id) { $licId = [string]$licenseObj.id }
    elseif ($licenseObj -and $licenseObj.name) { $licId = [string]$licenseObj.name }
    if ($licId) {
      $normalized += ToCycloneDxLicenseEntry $licId
    } else {
      $normalized += ToCycloneDxLicenseEntry "unknown"
    }
  }
  $component.licenses = $normalized
}

if (-not (Test-Path $InputSbom)) { throw "Input SBOM not found: $InputSbom" }

$sbomRaw = Get-Content $InputSbom -Raw
if ([string]::IsNullOrWhiteSpace($sbomRaw)) { throw "Input SBOM is empty." }

try { $sbom = $sbomRaw | ConvertFrom-Json }
catch { throw "Input SBOM is not valid JSON." }

$app = Read-AppMetadataFile $AppMetadata

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
$licensesValue = @(ToCycloneDxLicenseEntry $appLicense)
$meta = $sbom.metadata
if ($meta.PSObject.Properties.Name -contains "licenses") {
  $meta.licenses = $licensesValue
} else {
  $meta | Add-Member -MemberType NoteProperty -Name licenses -Value $licensesValue
}

$appName = SafeStr $app.name
$appVersion = SafeStr $app.version
$appPurl = Get-PurlFromApp $app
$appCpe = Get-CpeFromApp $app
$appBomRef = $appPurl

$customList = @()
if ($app.PSObject.Properties.Name -contains 'custom_components' -and $app.custom_components) {
  $customList = @($app.custom_components)
}

$customComponent = @{
  "bom-ref"   = $appBomRef
  type        = "application"
  name        = $appName
  version     = $appVersion
  description = SafeStr $app.description
  publisher   = $supplierName
  supplier    = @{ name = $supplierName; url = $supplierUrls }
  purl        = $appPurl
  cpe         = $appCpe
  licenses    = @(ToCycloneDxLicenseEntry (SafeStr $app.license))
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
$rootBomRef = $appBomRef
foreach ($c in $sbom.components) {
  if ($c.name -eq $appName -and $c.version -eq $appVersion) {
    $already = $true
    $rootBomRef = $c.'bom-ref'
    if (-not $c.purl) { $c | Add-Member -MemberType NoteProperty -Name purl -Value $appPurl -Force }
    if (-not $c.cpe) { $c | Add-Member -MemberType NoteProperty -Name cpe -Value $appCpe -Force }
    break
  }
}
if (-not $already) { $sbom.components += $customComponent }

$sbom.metadata.component = $customComponent

# --- COTS component refs before adding internal custom libraries ---
$cotsBomRefs = @()
foreach ($c in $sbom.components) {
  $br = $c.'bom-ref'
  if ($br -and $br -ne $rootBomRef) { $cotsBomRefs += $br }
}

# --- Additional custom components (holistic SBOM: multiple in-house parts + dependency graph) ---
$customRefs = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($cc in $customList) {
  $ref = SafeStr $cc.ref
  if ([string]::IsNullOrWhiteSpace($ref)) { throw "custom_components entry missing ref" }
  [void]$customRefs.Add($ref)

  $ccName = SafeStr $cc.name
  $ccVer = SafeStr $cc.version
  if ($ccVer -eq "unknown") { $ccVer = $appVersion }
  $ccType = SafeStr $cc.type
  if ($ccType -eq "unknown") { $ccType = "library" }
  $ccDesc = SafeStr $cc.description
  $ccLicRaw = $null
  if ($cc.PSObject.Properties.Name -contains 'license' -and $cc.license -and "$($cc.license)".Trim()) {
    $ccLicRaw = SafeStr $cc.license
  } else {
    $ccLicRaw = $appLicense
  }
  $ccCpe = Get-CpeFromSubComponent $ccName $ccVer $supplierName

  $props = @()
  if ($cc.PSObject.Properties.Name -contains 'source_file' -and $cc.source_file -and "$($cc.source_file)".Trim() -ne "unknown") {
    $props += @{ name = "source_file"; value = SafeStr $cc.source_file }
  }

  $sub = @{
    "bom-ref"   = $ref
    type        = $ccType
    name        = $ccName
    version     = $ccVer
    description = $ccDesc
    publisher   = $supplierName
    supplier    = @{ name = $supplierName; url = $supplierUrls }
    purl        = $ref
    cpe         = $ccCpe
    licenses    = @(ToCycloneDxLicenseEntry $ccLicRaw)
    externalReferences = @(@{ type = "vcs"; url = SafeStr $app.repository })
    properties  = $props
  }

  $dup = $false
  foreach ($c in $sbom.components) {
    if ($c.'bom-ref' -eq $ref) { $dup = $true; break }
  }
  if (-not $dup) { $sbom.components += $sub }
}

foreach ($c in $sbom.components) { Normalize-ComponentLicenses $c }
if ($sbom.metadata -and $sbom.metadata.component) {
  Normalize-ComponentLicenses $sbom.metadata.component
}

foreach ($c in $sbom.components) {
  if (-not $c.'bom-ref') {
    $c | Add-Member -MemberType NoteProperty -Name 'bom-ref' -Value ("anon:" + [guid]::NewGuid().ToString())
  }
}

if (-not $sbom.dependencies) { $sbom | Add-Member -MemberType NoteProperty -Name dependencies -Value @() }

# Build dependency graph
$newDeps = @()
foreach ($d in @($sbom.dependencies)) {
  if (-not $d.ref) { continue }
  if ($d.ref -eq $rootBomRef) { continue }
  if ($customRefs.Contains([string]$d.ref)) { continue }
  $newDeps += $d
}

foreach ($cc in $customList) {
  $ref = SafeStr $cc.ref
  $depOn = @(Get-DependsOnList $cc)
  $newDeps += @{ ref = $ref; dependsOn = $depOn }
}

$overrideTop = $null
if ($app.PSObject.Properties.Name -contains 'root_depends_on_custom' -and $app.root_depends_on_custom) {
  $overrideTop = @($app.root_depends_on_custom)
}

[string[]]$rootDependsOn = @()
if ($customList.Count -eq 0) {
  foreach ($c in $sbom.components) {
    if ($c.'bom-ref' -ne $rootBomRef) { $rootDependsOn += $c.'bom-ref' }
  }
} else {
  $rootDependsOn = @($cotsBomRefs)
  if ($overrideTop -and $overrideTop.Count -gt 0) {
    $rootDependsOn += $overrideTop
  } else {
    $rootDependsOn += (Get-CustomRootRefs $customList)
  }
}

$seen = New-Object 'System.Collections.Generic.HashSet[string]'
$deduped = @()
foreach ($r in $rootDependsOn) {
  if (-not $seen.Contains($r)) {
    [void]$seen.Add($r)
    $deduped += $r
  }
}
$newDeps += @{ ref = $rootBomRef; dependsOn = $deduped }

$sbom.dependencies = $newDeps

$sbomJson = $sbom | ConvertTo-Json -Depth 40
Write-Utf8NoBom -path $OutputSbom -content $sbomJson
Write-Host "Enriched SBOM written to $OutputSbom"

