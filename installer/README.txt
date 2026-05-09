Build MSI:
  pwsh -ExecutionPolicy Bypass -File .\installer\build-msi.ps1

Notes:
  - The generated MSI is configured as a per-user install (no admin elevation required).
  - Files are installed under the current user's LocalAppData folder.

Output:
  .\artifacts\installer\SecKey-Release-win-x64.msi
