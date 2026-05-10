param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [string]$ProductVersion = ""
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$workspaceRoot = Split-Path -Parent $repoRoot
$publishDir = Join-Path $repoRoot "artifacts\publish\SecKey.App"
$outDir = Join-Path $repoRoot "artifacts\installer"
$wixFile = Join-Path $PSScriptRoot "wix\SecKey.Product.wxs"

function Resolve-ProductVersion {
    param([string]$Requested)

    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        $normalized = $Requested.Trim().TrimStart('v', 'V')
        if ($normalized -match '^(\d+)\.(\d+)\.(\d+)(?:\.\d+)?$') {
            return "$($Matches[1]).$($Matches[2]).$($Matches[3])"
        }

        throw "Invalid ProductVersion '$Requested'. Expected semantic version like 1.0.2 or v1.0.2."
    }

    $tag = ""
    try {
        $tag = (& git -C $repoRoot describe --tags --abbrev=0 2>$null).Trim()
    }
    catch {
        $tag = ""
    }

    if (-not [string]::IsNullOrWhiteSpace($tag)) {
        $normalizedTag = $tag.Trim().TrimStart('v', 'V')
        if ($normalizedTag -match '^(\d+)\.(\d+)\.(\d+)(?:\.\d+)?$') {
            return "$($Matches[1]).$($Matches[2]).$($Matches[3])"
        }
    }

    return "1.0.0"
}

function Resolve-HeadCommitTimeUtc {
    try {
        $commitIso = (& git -C $repoRoot log -1 --format=%cI 2>$null).Trim()
        if (-not [string]::IsNullOrWhiteSpace($commitIso)) {
            return [DateTimeOffset]::Parse($commitIso).UtcDateTime
        }
    }
    catch {
        # ignore and fall back
    }

    return (Get-Date).ToUniversalTime().AddYears(-1)
}

$resolvedProductVersion = Resolve-ProductVersion -Requested $ProductVersion
$headCommitUtc = Resolve-HeadCommitTimeUtc

Write-Host "Using MSI ProductVersion: $resolvedProductVersion" -ForegroundColor Cyan

New-Item -ItemType Directory -Path $publishDir -Force | Out-Null
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

Write-Host "Publishing SecKey.App..." -ForegroundColor Cyan
dotnet publish (Join-Path $repoRoot "SecKey.App\SecKey.App.csproj") -c $Configuration -r $Runtime --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $publishDir

# Stage deployment content into publish output so MSI installs required manifests/assets.
$contentFolders = @("JSON", "IntuneApps", "RemediationScripts")
foreach ($folder in $contentFolders) {
    $src = Join-Path $workspaceRoot $folder
    if (-not (Test-Path $src)) {
        $src = Join-Path $repoRoot $folder
    }

    if (-not (Test-Path $src)) {
        continue
    }

    $dst = Join-Path $publishDir $folder
    if (Test-Path $dst) {
        Remove-Item -LiteralPath $dst -Recurse -Force
    }

    Write-Host "Staging content folder: $folder" -ForegroundColor Cyan
    Copy-Item -Path $src -Destination $dst -Recurse -Force
}

Write-Host "Ensuring WiX tool is installed..." -ForegroundColor Cyan
dotnet tool update --global wix --version 4.* | Out-Null

$env:PublishDir = $publishDir
$msiOut = Join-Path $outDir "SecKey-$Configuration-$Runtime.msi"

Write-Host "Building MSI..." -ForegroundColor Cyan
wix build $wixFile -d PublishDir=$publishDir -d ProductVersion=$resolvedProductVersion -arch x64 -o $msiOut

if (-not (Test-Path $msiOut)) {
    throw "MSI file was not produced: $msiOut"
}

$msi = Get-Item $msiOut
if ($msi.LastWriteTimeUtc -lt $headCommitUtc) {
    throw "Guardrail failure: MSI appears older than HEAD commit. Rebuild aborted."
}

$hash = (Get-FileHash $msiOut -Algorithm SHA256).Hash.ToLowerInvariant()

Write-Host "MSI created: $msiOut" -ForegroundColor Green
Write-Host "MSI SHA256: $hash" -ForegroundColor Green
