@echo off
setlocal
set CONFIG=Release
set RUNTIME=win-x64

if not "%~1"=="" set CONFIG=%~1
if not "%~2"=="" set RUNTIME=%~2

echo Publishing SecKey.App...
dotnet publish SecKey.App\SecKey.App.csproj -c %CONFIG% -r %RUNTIME% --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o artifacts\publish\SecKey.App
if errorlevel 1 exit /b 1

echo Ensuring WiX CLI is installed...
dotnet tool update --global wix --version 4.*

echo Building MSI...
wix build installer\wix\SecKey.Product.wxs -d PublishDir=artifacts\publish\SecKey.App -arch x64 -o artifacts\installer\SecKey-%CONFIG%-%RUNTIME%.msi
if errorlevel 1 exit /b 1

echo Done. MSI at artifacts\installer\SecKey-%CONFIG%-%RUNTIME%.msi
