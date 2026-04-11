param(
  [Parameter(Mandatory=$true)]
  [string]$InputSbom,

  [Parameter(Mandatory=$false)]
  [string]$AppMetadata = "",

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
  # CycloneDX JSON schema (1.6/1.7): each license choice is oneOf SPDX id, named license, or expression.
  # Do not combine id + name + url + licensing on the same object — CycloneDX-CLI validation will fail.
  $raw = [string]$licenseInput
  if ([string]::IsNullOrWhiteSpace($raw) -or $raw -eq "unknown") {
    return @{ license = @{ name = "unknown" } }
  }
  $id = $raw.Trim()
  if ($script:SPDX_LICENSES.ContainsKey($id)) {
    return @{ license = @{ id = $id } }
  }
  # Heuristic: SPDX IDs are typically identifier-like (no spaces; may include -, +, .)
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

function Normalize-AppMetadataFlat([hashtable]$lc) {
  $name = SafeStr ($lc['name'])
  if ([string]::IsNullOrWhiteSpace($name) -or $name -eq 'unknown') {
    $cn = [string]$lc['component_name']
    if (-not [string]::IsNullOrWhiteSpace($cn)) { $name = $cn.Trim() }
  }
  if ([string]::IsNullOrWhiteSpace($name)) { $name = 'custom-cpp-app' }

  $ver = SafeStr ($lc['version'])
  if ($ver -eq 'unknown') { $ver = '1.0.0' }

  $desc = [string]$lc['description']
  if ([string]::IsNullOrWhiteSpace($desc)) { $desc = "$name (app metadata)" }

  $supplierName = SafeStr ($lc['supplier_name'])
  if ($supplierName -eq 'unknown' -or [string]::IsNullOrWhiteSpace($supplierName)) {
    $supplierName = SafeStr ($lc['supplier'])
  }
  if ($supplierName -eq 'unknown' -or [string]::IsNullOrWhiteSpace($supplierName)) { $supplierName = 'Unknown' }

  $urlCell = [string]($lc['supplier_url'])
  if ([string]::IsNullOrWhiteSpace($urlCell)) { $urlCell = [string]$lc['supplier_urls'] }
  $urls = @()
  if (-not [string]::IsNullOrWhiteSpace($urlCell)) {
    foreach ($p in ($urlCell -split '[|;,\n]+')) {
      $t = $p.Trim()
      if ($t) { $urls += $t }
    }
  }

  $repoVal = [string]$lc['repository']
  if ([string]::IsNullOrWhiteSpace($repoVal)) { $repoVal = [string]$lc['repo'] }
  if ($null -eq $repoVal) { $repoVal = '' }

  $out = [ordered]@{
    name = $name
    component_type = SafeStr ($lc['component_type'])
    version = $ver
    description = $desc
    language = if ([string]::IsNullOrWhiteSpace([string]$lc['language'])) { 'C++' } else { [string]$lc['language'].Trim() }
    author = if ([string]::IsNullOrWhiteSpace([string]$lc['author'])) { 'Unknown' } else { [string]$lc['author'].Trim() }
    license = if ([string]::IsNullOrWhiteSpace([string]$lc['license'])) { 'MIT' } else { [string]$lc['license'].Trim() }
    build_system = $({
        $bs = [string]$lc['build_system']
        if ([string]::IsNullOrWhiteSpace($bs)) { $bs = [string]$lc['build'] }
        if ([string]::IsNullOrWhiteSpace($bs)) { 'unknown' } else { $bs.Trim() }
      })
    entry_point = if ([string]::IsNullOrWhiteSpace([string]$lc['entry_point'])) { 'main' } else { [string]$lc['entry_point'].Trim() }
    source_file = if ([string]::IsNullOrWhiteSpace([string]$lc['source_file'])) { 'src/main.cpp' } else { [string]$lc['source_file'].Trim() }
    repository = $repoVal
    supplier = [pscustomobject]@{ name = $supplierName; url = [object[]]$urls }
  }
  if ($out['component_type'] -eq 'unknown' -or [string]::IsNullOrWhiteSpace($out['component_type'])) {
    $out['component_type'] = 'application'
  }
  $purl = [string]$lc['purl']
  if (-not [string]::IsNullOrWhiteSpace($purl)) { $out['purl'] = $purl.Trim() }
  $cpe = [string]$lc['cpe']
  if (-not [string]::IsNullOrWhiteSpace($cpe)) { $out['cpe'] = $cpe.Trim() }
  return [pscustomobject]$out
}

function Read-AppMetadataFromFile([string]$MetaPath) {
  $ext = [System.IO.Path]::GetExtension($MetaPath).ToLowerInvariant()
  if ($ext -eq '.json') {
    return Get-Content $MetaPath -Raw | ConvertFrom-Json
  }
  if ($ext -eq '.csv') {
    $rows = Import-Csv -LiteralPath $MetaPath
    if (-not $rows -or $rows.Count -eq 0) { throw "CSV metadata has no data rows: $MetaPath" }
    $r = $rows[0]
    $lc = @{}
    foreach ($p in $r.PSObject.Properties) {
      $lc[$p.Name.Trim().ToLowerInvariant()] = [string]$p.Value
    }
    return Normalize-AppMetadataFlat $lc
  }
  if ($ext -eq '.xml') {
    [xml]$x = Get-Content $MetaPath -Raw
    $root = $x.DocumentElement
    $lc = @{}
    foreach ($n in $root.ChildNodes) {
      if ($n.NodeType -ne 'Element') { continue }
      $tag = $n.LocalName.ToLowerInvariant()
      if ($tag -eq 'supplier') {
        $sn = ''
        $urlParts = @()
        foreach ($c in $n.ChildNodes) {
          if ($c.NodeType -ne 'Element') { continue }
          $ct = $c.LocalName.ToLowerInvariant()
          if ($ct -eq 'name') { $sn = [string]$c.InnerText.Trim() }
          elseif ($ct -eq 'url') { $urlParts += [string]$c.InnerText.Trim() }
        }
        if ($n.HasAttribute('name')) { $sn = [string]$n.GetAttribute('name') }
        if ($n.HasAttribute('url')) { $urlParts += [string]$n.GetAttribute('url') }
        $lc['supplier_name'] = $sn
        if ($urlParts.Count -gt 0) { $lc['supplier_url'] = ($urlParts -join '|') }
        continue
      }
      $txt = [string]$n.InnerText.Trim()
      if ($txt) { $lc[$tag.Replace('-', '_')] = $txt }
    }
    if ($root.HasAttribute('name')) { $lc['name'] = [string]$root.GetAttribute('name') }
    if ($root.HasAttribute('version')) { $lc['version'] = [string]$root.GetAttribute('version') }
    if ($root.HasAttribute('license')) { $lc['license'] = [string]$root.GetAttribute('license') }
    if ($root.HasAttribute('language')) { $lc['language'] = [string]$root.GetAttribute('language') }
    if ($root.HasAttribute('author')) { $lc['author'] = [string]$root.GetAttribute('author') }
    return Normalize-AppMetadataFlat $lc
  }
  throw "Unsupported app metadata extension '$ext' (use .json, .csv, or .xml): $MetaPath"
}

if (-not (Test-Path $InputSbom)) { throw "Input SBOM not found: $InputSbom" }

$sbomRaw = Get-Content $InputSbom -Raw
if ([string]::IsNullOrWhiteSpace($sbomRaw)) { throw "Input SBOM is empty." }

try { $sbom = $sbomRaw | ConvertFrom-Json }
catch { throw "Input SBOM is not valid JSON." }

$app = $null
if (-not [string]::IsNullOrWhiteSpace($AppMetadata) -and (Test-Path $AppMetadata)) {
  try {
    $app = Read-AppMetadataFromFile $AppMetadata
  } catch {
    throw "App metadata could not be read ($AppMetadata): $($_.Exception.Message)"
  }
}

if ($null -eq $app) {
  $rootName = "unknown-app"
  $rootVersion = "0.0.0"
  if ($sbom.metadata -and $sbom.metadata.component) {
    if ($sbom.metadata.component.name) { $rootName = [string]$sbom.metadata.component.name }
    if ($sbom.metadata.component.version) { $rootVersion = [string]$sbom.metadata.component.version }
  }
  $app = [pscustomobject]@{
    name = $rootName
    version = $rootVersion
    description = "Auto-generated metadata (app-metadata.json not provided)"
    language = "C++"
    author = "Unknown"
    repository = ""
    build_system = "unknown"
    entry_point = "main"
    source_file = "unknown"
    license = "unknown"
    supplier = [pscustomobject]@{
      name = "Unknown"
      url = @()
    }
  }
}

if (-not $app.supplier) {
  $app | Add-Member -MemberType NoteProperty -Name supplier -Value ([pscustomobject]@{ name = "Unknown"; url = @() }) -Force
}
if (-not $app.supplier.name) { $app.supplier.name = "Unknown" }
if (-not $app.supplier.url) { $app.supplier.url = @() }

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
# Always set root metadata licenses from app — merged COTS SBOMs may carry invalid license shapes for CycloneDX 1.7.
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

if (-not ($sbom.PSObject.Properties.Name -contains "components")) {
  $sbom | Add-Member -MemberType NoteProperty -Name components -Value @()
} elseif ($null -eq $sbom.components) {
  $sbom.components = @()
}

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

foreach ($c in $sbom.components) { Normalize-ComponentLicenses $c }
# When an existing root component matched, $customComponent may not appear in components[]; normalize metadata root anyway.
if ($sbom.metadata -and $sbom.metadata.component) {
  Normalize-ComponentLicenses $sbom.metadata.component
}

if (-not ($sbom.PSObject.Properties.Name -contains "dependencies")) {
  $sbom | Add-Member -MemberType NoteProperty -Name dependencies -Value @()
} elseif ($null -eq $sbom.dependencies) {
  $sbom.dependencies = @()
}

foreach ($c in $sbom.components) {
  if (-not $c.'bom-ref') {
    $c | Add-Member -MemberType NoteProperty -Name 'bom-ref' -Value ("anon:" + [guid]::NewGuid().ToString())
  }
}

$depRefs = @()
foreach ($c in $sbom.components) {
  if ($c.'bom-ref' -ne $rootBomRef) { $depRefs += $c.'bom-ref' }
}

$rootIndex = -1
for ($i = 0; $i -lt $sbom.dependencies.Count; $i++) {
  if ($sbom.dependencies[$i].ref -eq $rootBomRef) { $rootIndex = $i; break }
}

$rootDep = @{ ref = $rootBomRef; dependsOn = $depRefs }
if ($rootIndex -ge 0) { $sbom.dependencies[$rootIndex] = $rootDep }
else { $sbom.dependencies += $rootDep }

$sbomJson = $sbom | ConvertTo-Json -Depth 40
Write-Utf8NoBom -path $OutputSbom -content $sbomJson
Write-Host "Enriched SBOM written to $OutputSbom"
