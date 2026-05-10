@echo off
setlocal
set CONFIG=Release
set RUNTIME=win-x64
set PRODUCT_VERSION=%~3

if not "%~1"=="" set CONFIG=%~1
if not "%~2"=="" set RUNTIME=%~2

if "%PRODUCT_VERSION%"=="" (
	for /f %%i in ('git describe --tags --abbrev=0 2^>nul') do set PRODUCT_VERSION=%%i
)

if /i "%PRODUCT_VERSION:~0,1%"=="v" set PRODUCT_VERSION=%PRODUCT_VERSION:~1%
if "%PRODUCT_VERSION%"=="" set PRODUCT_VERSION=1.0.0

echo Publishing SecKey.App...
dotnet publish SecKey.App\SecKey.App.csproj -c %CONFIG% -r %RUNTIME% --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o artifacts\publish\SecKey.App
if errorlevel 1 exit /b 1

echo Ensuring WiX CLI is installed...
dotnet tool update --global wix --version 4.*

echo Building MSI...
wix build installer\wix\SecKey.Product.wxs -d PublishDir=artifacts\publish\SecKey.App -d ProductVersion=%PRODUCT_VERSION% -arch x64 -o artifacts\installer\SecKey-%CONFIG%-%RUNTIME%.msi
if errorlevel 1 exit /b 1

echo Done. MSI at artifacts\installer\SecKey-%CONFIG%-%RUNTIME%.msi
