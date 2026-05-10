# PAW Control Matrix

Last updated: 2026-05-09
Scope: SecKey privileged administration app and deployment workflows.

## Decision Inputs Confirmed
- Device and session gate behavior in-app: warning-only for initial rollout.
- Signed settings import enforcement: not required in initial rollout.
- Just-in-time privileged checks before privileged write operations: required.

## Verification Of Missing Features
- Checked authoritative open work list in `source/docs/WORK-INVENTORY.md`.
- Checked parity inventory in `source/tracked-docs/SECURITY-PORTING-CHECKLIST.md`.
- Checked runtime validation status in `source/tracked-docs/RUNTIME-VALIDATION-MATRIX.md`.
- Result: no additional missing features were identified beyond the existing documented items.

## Control Matrix

| PAW Control Area | Requirement | Current State | Status | Evidence | Gap | Required Action |
|---|---|---|---|---|---|---|
| Clean source principle | Privileged paths validate trusted source before high-impact actions | Graph auth checks sign-in and permission outcomes, but no mandatory local trust gate | Partial | `source/SecKey.App/ViewModels/GraphPageViewModel.cs` | Missing explicit trust evaluation before privileged commands | Add preflight trust evaluator and show warning-only block reasons in initial phase |
| Interface known/trusted/allowed | Privileged interface should evaluate account and device trust on inbound session | Conditional Access enforcement is assumed externally; app does not enforce local trust assertions | Partial | `source/SecKey.App/ViewModels/LoginViewModel.cs`, `source/SecKey.App/ViewModels/InfrastructureViewModel.cs` | In-app interface trust checks not centralized | Add reusable trust preflight service and call it for all privileged write commands |
| Least privilege access | Request least privilege and escalate only when needed | Broad delegated scopes are requested by default for delegated sign-in | Gap | `source/SecKey.App/App.xaml.cs`, `source/SecKey.App/ViewModels/LoginViewModel.cs` | Over-privileged default scope set | Split read and write profiles and trigger scope escalation only for write workflows |
| JIT privileged activation | Privileged operations must verify JIT readiness and role activation | No explicit JIT activation check before deployment operations | Gap | `source/SecKey.App/ViewModels/InfrastructureViewModel.cs` | Missing required JIT control | Add required JIT check before privileged writes and deployment execution |
| Privileged account hygiene | Dedicated privileged accounts and strong auth are required | Sign-in and access probe guidance exists, but dedicated account enforcement is external | Partial | `source/SecKey.App/ViewModels/LoginViewModel.cs` | App does not validate account classification | Add optional account profile check and warning telemetry for non-dedicated accounts |
| Device assurance | Privileged operations should originate from compliant managed devices | No explicit local device compliance check in privileged commands | Partial | `source/SecKey.App/ViewModels/InfrastructureViewModel.cs` | Device assurance not evaluated in-app | Add device assurance probe and warning-only enforcement for phase 1 |
| Import trust boundary | High-impact settings import should validate integrity and allowed content | Settings import deserializes and applies values directly | Gap | `source/SecKey.App/Services/AppSettingsExchangeService.cs`, `source/SecKey.App/ViewModels/MainViewModel.cs` | No signature validation and no strict schema allowlist | Add strict schema and allowlist validation; keep signature support optional in phase 1 |
| Secret storage at rest | Secrets should be protected at rest with platform controls | Credential and vault content use DPAPI current user protection | Pass | `source/SecKey.App/ViewModels/CredentialManagerViewModel.cs`, `source/SecKey.App/Services/NativeSecurityPortService.cs` | Vault master verifier uses unsalted SHA-256 | Replace verifier with Argon2id or PBKDF2 plus salt and work factor |
| Crypto integrity | File encryption should ensure confidentiality and integrity | AES plus PBKDF2 is present, but authenticated encryption semantics are not explicit | Partial | `source/SecKey.App/ViewModels/FileEncryptionToolViewModel.cs` | Missing AEAD tag validation pattern | Move to AES-GCM or ChaCha20-Poly1305 with versioned format |
| Logging and error hygiene | Sensitive internals should be redacted in user-visible output | Many operations print raw exception messages to status text | Gap | `source/SecKey.App/ViewModels/GraphPageViewModel.cs`, `source/SecKey.App/ViewModels/LoginViewModel.cs` | Potential information leakage in UI | Add centralized error sanitizer and secure diagnostic logging channel |
| Monitoring and response | High-risk administrative actions should be auditable | Deployment history exists in UI but no centralized immutable audit stream | Partial | `source/SecKey.App/ViewModels/InfrastructureViewModel.cs` | Incomplete operational audit trail | Add structured security audit events for auth, import, and deployment actions |

## Release Readiness Summary For This Matrix
- Solution build status: pass with warnings.
- Automated test status: pass for current app settings and JSON baseline integration tests.
- Manual module validation status: pending per matrix in `source/tracked-docs/RUNTIME-VALIDATION-MATRIX.md`.
- Known open work remains in `source/docs/WORK-INVENTORY.md` and should be treated as post-release backlog for this documentation-focused release.

## Immediate Next Security Iteration
1. Implement required JIT preflight checks for privileged write and deployment operations.
2. Add in-app trust preflight service with warning-only rollout for device and risk signals.
3. Replace broad default delegated scopes with operation-scoped escalation.
4. Harden import pipeline with strict schema and key allowlist checks.
5. Upgrade vault master verifier to salted memory-hard derivation.