param(
    [Parameter(Mandatory = $true)]
    [string]$Tag,
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$productVersion = $Tag.Trim().TrimStart('v', 'V')
if ($productVersion -notmatch '^(\d+)\.(\d+)\.(\d+)(?:\.\d+)?$') {
    throw "Tag '$Tag' does not map to a valid MSI product version (expected vX.Y.Z)."
}

Write-Host "Building MSI for tag $Tag (ProductVersion=$productVersion)..." -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'build-msi.ps1') -Configuration $Configuration -Runtime $Runtime -ProductVersion $productVersion

$msiPath = Join-Path $repoRoot "artifacts\installer\SecKey-$Configuration-$Runtime.msi"
if (-not (Test-Path $msiPath)) {
    throw "Expected MSI not found: $msiPath"
}

$localHash = (Get-FileHash $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "Uploading MSI to release $Tag..." -ForegroundColor Cyan
gh release upload $Tag $msiPath --clobber | Out-Null

$release = gh release view $Tag --json assets | ConvertFrom-Json
$asset = $release.assets | Where-Object { $_.name -eq (Split-Path $msiPath -Leaf) } | Select-Object -First 1
if ($null -eq $asset) {
    throw "Guardrail failure: uploaded MSI asset not found on release $Tag."
}

$remoteDigest = ($asset.digest -replace '^sha256:', '').ToLowerInvariant()
if ($remoteDigest -ne $localHash) {
    throw "Guardrail failure: remote digest mismatch. Local=$localHash Remote=$remoteDigest"
}

Write-Host "Release asset verified." -ForegroundColor Green
Write-Host "Asset: $($asset.name)" -ForegroundColor Green
Write-Host "SHA256: $localHash" -ForegroundColor Green
Write-Host "URL: $($asset.url)" -ForegroundColor Green
