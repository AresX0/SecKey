# Runtime Validation Matrix

Last updated: 2026-05-09

## Scope
Validation matrix for security/intune modules and core app runtime checks.

## Automated checks completed in this pass
- Full solution build.
- Unit/integration test execution for settings export/import and JSON live-edit baseline reset.
- App launch process verification (startup smoke).

## Module status
- Dashboard: PASS-STATIC
- AD Security Analysis: PASS-STATIC
- System Hardening: PASS-STATIC
- Reboot Analyzer: PASS-STATIC
- File Integrity: PASS-STATIC
- Intune Backup: PASS-STATIC
- Certificate Manager: PASS-STATIC
- Credential Manager: PASS-STATIC
- SSH Key Manager: PASS-STATIC
- Encrypted Clipboard: PASS-STATIC
- File Encryption Tool: PASS-STATIC
- Security Vault: PASS-STATIC
- Network Traffic: PASS-STATIC
- Hash Scanner: PASS-STATIC
- YARA Scanner: PASS-STATIC
- CVE Search: PASS-STATIC
- Forensics Analyzer: PASS-STATIC
- Advanced Forensics: PASS-STATIC
- Global Secure Access: PASS-STATIC
- WDAC / AppLocker: PASS-STATIC
- System Audit: PASS-STATIC
- Secure Wipe: PASS-STATIC

## Remaining manual validation
- Interactive click-through in an active desktop session for each module page.
- Manual execution of one representative action per module to confirm behavior in tenant-integrated runtime.

## Sign-off checklist (manual)
1. Launch app and authenticate.
2. Open each module page at least once.
3. Trigger one non-destructive action per page.
4. Confirm no runtime exceptions or blocked commands.
5. Record pass/fail with notes and timestamp.
