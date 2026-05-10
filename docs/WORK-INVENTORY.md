# SecKey Work Inventory

Last updated: 2026-05-09

## Objective
Consolidate all active/uncommitted platform work into one deployable, documented release state.

## Core Deployment And Policy Work
- Native deployment settings service and per-scope settings inventory in app.
- Live JSON policy settings editor backend and dashboard integration.
- Baseline snapshot and reset flow for managed JSON policy files.
- Native/override source tagging in settings grids.
- Expanded deployment orchestration support through existing manifest pipeline.

## New App Modules Added
- Advanced Forensics
- Forensics Analyzer
- Security Analyzer
- System Audit
- System Hardening
- Reboot Analyzer
- File Integrity
- Secure Wipe
- Hash Scanner
- YARA Scanner
- Network Traffic
- Certificate Manager
- Credential Manager
- Security Vault
- SSH Key Manager
- File Encryption Tool
- Encrypted Clipboard
- CVE Search
- Global Secure Access
- Intune Backup
- Preferences

## New Core Services Added
- AD security analysis and threat-hunting support.
- Security analysis database service for persisted findings.
- Certificate management service.
- File integrity baseline/compare service.
- Intune backup and restore service.
- Reboot and crash analysis service.
- Secure wipe service with multiple sanitization levels.
- Expanded system audit service and auto-remediation paths.

## New Graph/Entra Services Added
- Entra ID security analysis service.
- Privileged role and PIM assignment analysis.
- Risky app permission analysis.
- IR conditional access policy deployment helpers.
- Tenant takeback and incident-response operations.

## UI And App Infrastructure Updates
- Main navigation and page composition updates.
- New views and corresponding view-model wiring.
- Additional converters and helper command abstractions.
- Dashboard and page-level deployment UX improvements.

## Validation Status
- Full solution build: passing.
- Known warnings remain (NuGet vulnerability/compatibility warnings).
- Runtime launch behavior can vary by host terminal/session state; app process launch validated during this pass.

## Priority Next Pass (Post-Commit)
- Add targeted smoke tests for newly added modules.
- Add integration tests for JSON live edit -> deploy pipeline.
- Address vulnerable package warnings with controlled upgrade plan.
- Add module-level docs for each new security tool workflow.

## Authoritative Open Items
This section is the single release-readiness source of truth for remaining work.

1. Complete runtime click-through validation for all security/intune module pages still marked PASS-STATIC or PENDING-RUNTIME in parity tracking.
2. Implement non-placeholder Export Settings and Import Settings menu workflows.
3. Add targeted smoke tests for newly added modules.
4. Add integration tests for JSON live edit -> deploy pipeline.
5. Address vulnerable/compatibility package warnings with a controlled upgrade plan.
6. Expand module-level docs for each new security workflow.

## Tracking Notes
- Use this file for open/unfinished work status.
- Other docs (README, deliverables, parity checklists) provide context and should not be treated as authoritative for release readiness.
