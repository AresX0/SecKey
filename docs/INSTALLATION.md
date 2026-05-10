# SecKey Installation Guide

## 1) Prerequisites

- Windows 11 x64 (recommended), Windows 10 x64 supported.
- .NET 10 SDK (for source build).
- Microsoft Graph app registration with required permissions.
- Intune admin permissions for policy/app operations.

## 2) Install from MSI (recommended)

1. Build or obtain `artifacts\\installer\\SecKey-Release-win-x64.msi`.
2. Run MSI as Administrator.
3. Install to default path: `C:\\Program Files\\SecKey`.
4. Launch `SecKey.App.exe` from Start Menu or install folder.

Silent install:

```bat
msiexec /i SecKey-Release-win-x64.msi /qn /norestart
```

Silent uninstall:

```bat
msiexec /x SecKey-Release-win-x64.msi /qn /norestart
```

## 3) Build from source

```bat
cd source
dotnet restore
dotnet build SecKey.slnx -c Release
```

Run WPF app:

```bat
dotnet run --project SecKey.App
```

Run CLI:

```bat
dotnet run --project SecKey.Cli -- list-apps
```

## 4) Build MSI from source

PowerShell:

```powershell
pwsh -ExecutionPolicy Bypass -File .\\installer\\build-msi.ps1
```

Command prompt:

```bat
installer\\build-msi.cmd
```

## 5) Authentication setup

### Delegated (interactive/device)

- Tenant ID: your Entra tenant ID (or `common`).
- Client ID: public client app ID.
- Required delegated scopes include:
  - `Directory.ReadWrite.All`
  - `Group.ReadWrite.All`
  - `User.ReadWrite.All`
  - `Policy.ReadWrite.ConditionalAccess`
  - `DeviceManagementApps.ReadWrite.All`
  - `DeviceManagementConfiguration.ReadWrite.All`
  - `DeviceManagementServiceConfig.ReadWrite.All`

### App-only (client credentials)

Set environment variables before running CLI:

```bat
set SECKEY_TENANT=<tenant-guid>
set SECKEY_CLIENT=<app-client-id>
set SECKEY_SECRET=<client-secret>
```

Required application permissions should map to the same Graph domains and be admin-consented.

## 6) Post-install verification

- Open app and sign in successfully.
- Load Dashboard and verify tenant objects are listed.
- CLI smoke test:

```bat
seckey list-apps
seckey list-groups
```

## 7) Troubleshooting

- `NU1903` warning is from transitive Kiota advisory; monitor Graph SDK/Kiota updates.
- If sign-in fails, verify redirect URI and Graph permission consent.
- If Intune upload fails, verify `IntuneWinAppUtil.exe` path and app folder structure.

## 8) Logs

Default log file:

- `%LocalAppData%\\Microsoft\\SecKey\\SecKey.log`
