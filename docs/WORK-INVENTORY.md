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

1. Complete manual runtime click-through validation for all security/intune module pages still marked PASS-STATIC.
2. Expand smoke test coverage beyond settings workflow into module-specific service paths.
3. Expand integration tests from local JSON workflow to tenant-integrated deploy pipeline in a non-production tenant.
4. Execute package upgrade rings from the controlled plan and validate each ring.

## Completed In This Pass
- Implemented non-placeholder app settings Export/Import workflow wiring through a dedicated exchange service and included native deployment setting override round-trip.
- Added automated smoke/integration tests for settings export/import and JSON live-edit baseline reset.
- Added controlled package upgrade plan document.
- Added consolidated module-level workflow documentation.
- Added runtime validation matrix and manual sign-off checklist.

## Tracking Notes
- Use this file for open/unfinished work status.
- Other docs (README, deliverables, parity checklists) provide context and should not be treated as authoritative for release readiness.
