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
$versionPropsPath = Join-Path $repoRoot "Directory.Build.props"

function Get-ConfiguredVersion {
    if (-not (Test-Path $versionPropsPath)) {
        return "1.0.0.8"
    }

    $props = [xml](Get-Content $versionPropsPath -Raw)
    $versionNode = $props.Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($versionNode)) {
        return "1.0.0.8"
    }

    return $versionNode.Trim()
}

function Set-ConfiguredVersion {
    param([Parameter(Mandatory = $true)][string]$Version)

    if (-not (Test-Path $versionPropsPath)) {
        throw "Version file not found: $versionPropsPath"
    }

    $propsContent = Get-Content $versionPropsPath -Raw
    foreach ($elementName in @('Version', 'FileVersion', 'AssemblyVersion', 'InformationalVersion')) {
        $propsContent = $propsContent -replace "<$elementName>[^<]+</$elementName>", "<$elementName>$Version</$elementName>"
    }

    Set-Content -Path $versionPropsPath -Value $propsContent -NoNewline
}

function Increment-Version {
    param([Parameter(Mandatory = $true)][string]$Version)

    $parts = $Version.Trim().TrimStart('v', 'V').Split('.')
    if ($parts.Count -lt 4) {
        $parts = @($parts[0], $parts[1], $parts[2], '0')
    }

    $major = [int]$parts[0]
    $minor = [int]$parts[1]
    $build = [int]$parts[2]
    $revision = [int]$parts[3]
    $revision++

    return "$major.$minor.$build.$revision"
}

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

    return Get-ConfiguredVersion
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

$currentConfiguredVersion = Get-ConfiguredVersion
if (-not [string]::IsNullOrWhiteSpace($ProductVersion)) {
    $resolvedProductVersion = Resolve-ProductVersion -Requested $ProductVersion
    Set-ConfiguredVersion -Version $resolvedProductVersion
} else {
    $resolvedProductVersion = Increment-Version -Version $currentConfiguredVersion
    Set-ConfiguredVersion -Version $resolvedProductVersion
}
$headCommitUtc = Resolve-HeadCommitTimeUtc

Write-Host "Current configured version: $currentConfiguredVersion" -ForegroundColor Gray
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
