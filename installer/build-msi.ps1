param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$publishDir = Join-Path $repoRoot "artifacts\publish\SecKey.App"
$outDir = Join-Path $repoRoot "artifacts\installer"
$wixFile = Join-Path $PSScriptRoot "wix\SecKey.Product.wxs"

New-Item -ItemType Directory -Path $publishDir -Force | Out-Null
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

Write-Host "Publishing SecKey.App..." -ForegroundColor Cyan
dotnet publish (Join-Path $repoRoot "SecKey.App\SecKey.App.csproj") -c $Configuration -r $Runtime --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $publishDir

Write-Host "Ensuring WiX tool is installed..." -ForegroundColor Cyan
dotnet tool update --global wix --version 4.* | Out-Null

$env:PublishDir = $publishDir
$msiOut = Join-Path $outDir "SecKey-$Configuration-$Runtime.msi"

Write-Host "Building MSI..." -ForegroundColor Cyan
wix build $wixFile -d PublishDir=$publishDir -arch x64 -o $msiOut

Write-Host "MSI created: $msiOut" -ForegroundColor Green
