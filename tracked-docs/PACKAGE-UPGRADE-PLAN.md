# Package Upgrade Plan

Last updated: 2026-05-09

## Goal
Reduce known package vulnerabilities and compatibility warnings with a controlled, low-regression rollout.

## Current warning themes
- NU1902: System.DirectoryServices.Protocols 4.7.0 vulnerability advisory.
- NU1903: Microsoft.Kiota.Abstractions 1.18.0 vulnerability advisory.
- NU1904: System.Drawing.Common 4.7.0 vulnerability advisory.
- NU1701 and NU1603: System.Management fallback/compatibility warnings.

## Strategy
1. Inventory all transitive and direct package versions per project.
2. Upgrade in rings: low-risk packages first, high-impact auth/graph packages second.
3. Validate with automated test suite and full build between each ring.
4. Keep a rollback checkpoint (tag/branch) after each ring.

## Ring 1 (low-risk and direct warnings)
- Upgrade System.DirectoryServices.Protocols to latest stable supported by net10.0.
- Upgrade System.Drawing.Common to latest stable supported by net10.0.
- Rebuild and run tests.

## Ring 2 (Graph/Kiota chain)
- Upgrade Microsoft.Graph and Microsoft.Graph.Beta to aligned, current stable/pinned versions.
- Upgrade Microsoft.Kiota.Abstractions to a non-vulnerable version compatible with chosen Graph packages.
- Rebuild and run tests.
- Validate auth and core list/deploy command paths in a non-production tenant.

## Ring 3 (compatibility cleanup)
- Replace or remove dependency on System.Management 3.0.0 fallback path where feasible.
- Prefer net-compatible versions and APIs to eliminate NU1603/NU1701 warnings.
- Rebuild and run tests.

## Validation gates per ring
- dotnet build SecKey.slnx -v minimal
- dotnet test SecKey.Tests/SecKey.Tests.csproj -v minimal
- Manual smoke run: app launch, sign-in, dashboard load, one deploy dry-run command.

## Rollback plan
- Commit/package-lock checkpoint before each ring.
- If a ring fails, revert only that ring and continue with smaller scoped updates.

## Exit criteria
- Vulnerability warnings reduced to accepted residual list.
- No new build errors or critical runtime regressions.
- All smoke and integration tests passing.
