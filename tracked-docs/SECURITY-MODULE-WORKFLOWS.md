# Security Module Workflows

Last updated: 2026-05-09

This document provides concise operator workflows for new security and backup modules.

## Security Analyzer
1. Open Security Analyzer from the sidebar.
2. Enter target domain and DC (or discover automatically).
3. Run full analysis.
4. Review critical/high findings first.
5. Export findings for audit records.

## System Hardening
1. Open System Hardening.
2. Run full audit.
3. Review failed controls by severity.
4. Apply one-click fix where available.
5. Re-run audit to verify remediation.

## Reboot Analyzer
1. Open Reboot Analyzer.
2. Set days to analyze.
3. Run analysis.
4. Inspect unexpected reboot, BSOD, and crash tabs.
5. Use root-cause summary for triage actions.

## File Integrity
1. Open File Integrity.
2. Select directory and create baseline.
3. Save baseline.
4. Later, compare current state to baseline.
5. Investigate added/modified/deleted file lists.

## Intune Backup
1. Open Intune Backup.
2. Set project root and tenant.
3. Create backup.
4. Use backup compare or baseline compare.
5. Generate cross-tenant import plan when needed.

## Certificate Manager
1. Open Certificate Manager.
2. Filter by store or search term.
3. Inspect certificate details and status.
4. Export or copy details/thumbprint as needed.

## Secure Wipe
1. Open Secure Wipe.
2. Select target file/folder.
3. Choose wipe level and confirmation options.
4. Execute wipe and monitor log/progress.
5. Optionally wipe free space after operation.

## Network Traffic
1. Open Network Traffic.
2. Start capture/analysis.
3. Filter suspicious destinations or ports.
4. Save evidence and summary for incident response.

## Hash Scanner
1. Open Hash Scanner.
2. Select file/folder targets.
3. Run scan.
4. Compare generated hashes against expected indicators.
5. Export results for chain-of-custody records.

## Credential Manager
1. Open Credential Manager.
2. Create/update secure entries.
3. Load selected credential for operations.
4. Delete stale credentials.

## Encrypted Clipboard
1. Open Encrypted Clipboard.
2. Encrypt sensitive clipboard payload.
3. Paste securely where needed.
4. Clear clipboard immediately after use.

## SSH Key Manager
1. Open SSH Key Manager.
2. Generate or import keys.
3. Review key inventory and metadata.
4. Export public keys for target systems.

## File Encryption Tool
1. Open File Encryption Tool.
2. Select input and output paths.
3. Encrypt or decrypt using approved key material.
4. Validate output integrity.

## Security Vault
1. Open Security Vault.
2. Store sensitive secrets/artifacts.
3. Retrieve only for approved operations.
4. Rotate and remove outdated secrets.

## YARA Scanner
1. Open YARA Scanner.
2. Load rule set.
3. Select scan targets.
4. Run scan and triage matches.
5. Export findings.

## CVE Search
1. Open CVE Search.
2. Query by product, package, or CVE ID.
3. Review severity and affected versions.
4. Track remediation actions.

## Forensics Analyzer
1. Open Forensics Analyzer.
2. Collect targeted host artifacts.
3. Review timeline and anomaly indicators.
4. Export case bundle.

## Advanced Forensics
1. Open Advanced Forensics.
2. Execute specialized collection commands.
3. Correlate memory/filesystem/network evidence.
4. Preserve and export investigation package.

## Global Secure Access
1. Open Global Secure Access.
2. Load configuration preview.
3. Validate policy intent and limits.
4. Export reviewed configuration if required.

## WDAC / AppLocker
1. Open WDAC / AppLocker.
2. Load policy/profile.
3. Decode and inspect effective rules.
4. Export reviewed policy artifacts.

## System Audit
1. Open System Audit.
2. Run grouped audit tasks.
3. Review findings and remediation guidance.
4. Re-run after remediation to confirm status.
