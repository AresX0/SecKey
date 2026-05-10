# Security Feature Porting Checklist

This is the living checklist for porting Platypus/PAW security features into SecKey.

## Already in SecKey
- Intune Backup
- Certificate Manager
- SSH Key Manager
- File Encryption
- System Hardening
- Network Traffic
- Encrypted Clipboard
- Credential Manager
- System Audit
- Reboot Analyzer / Crash Analysis
- Secure Wipe
- Hash Scanner
- AD Security Analyzer
- File Integrity Monitor
- Security Analyzer / Entra PIM analysis
- Security Vault
- YARA Scanner
- CVE Search
- Advanced Forensics
- Forensics Analyzer
- Global Secure Access / web content filtering
- WDAC / AppLocker UI

## Partial or Needs Parity Review
- AD Security Analysis (surface naming/workflow parity)
- Intune Backup
- Certificate Manager (workflow parity)
- SSH Key Manager (workflow parity)
- File Encryption
- Encrypted Clipboard
- Credential Manager
- YARA Scanner (window vs view parity)
- Security Analyzer / Entra PIM workflow

## Missing or Not Yet Ported
- Auto-remediation / one-click fix flows
- PIM approval / workflow automation
- Delta backup / incremental backup
- Backup compression
- Memory dump export
- Real-time file integrity monitoring
- Packet capture / advanced network forensics

## Authoritative Tracking
- Current open engineering items are tracked in `source/docs/WORK-INVENTORY.md` under "Authoritative Open Items".
- Treat this checklist as feature-parity context and inventory, not as the release readiness source of truth.

## Legacy Source Map
- Legacy feature source lives under `archive/newPaw/PAWCSM/source/public`, `archive/newPaw/PAWCSM/source/private`, and `archive/newPaw/PAWCSM/IntuneApps`.
- Current SecKey implementations live under `source/SecKey.App`, `source/SecKey.Core`, and `source/SecKey.Graph`.

## Current Focus
- Finish Intune Backup parity first.
- Continue porting the remaining security-tab tools until every legacy feature is matched or explicitly marked missing.
