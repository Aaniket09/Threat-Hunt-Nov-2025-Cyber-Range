# Threat Hunt Report: Ghost Support

**Analyst:** Aniket Agarwal  
**Date Completed:** 2025-11-13  
**Environment Investigated:** gab-intern-vm  
**Timeframe:** November 14, 2025  

---

## Executive Summary

This threat hunt investigated anomalous activity on the virtual machine **gab-intern-vm** within the timeframe of **October 1–15, 2025**. The purpose was to uncover early signs of malicious activity, reconnaissance, persistence mechanisms, and potential data exfiltration attempts.

Key findings include detection of:
- Initial execution points
- Tampering attempts
- Rapid data probes
- Host and session reconnaissance
- Storage enumeration
- Network checks
- Staging of artifacts
- Outbound connection attempts

Evidence suggests a structured attack with clear preparation, reconnaissance, and staged persistence.

---

## Hunt Scope

- **Host Monitored:** gab-intern-vm  
- **Data Sources:**
  - DeviceProcessEvents
  - DeviceFileEvents
  - DeviceNetworkEvents
  - DeviceRegistryEvents  
- **Timeframe:** 2025-10-01 to 2025-10-15  
- **Objective:** Detect initial compromise indicators, attacker reconnaissance, persistence, and exfiltration attempts.

---

## Timeline of Key Events

| Date | Event |
|------|-------|
| 2025-10-09 12:20–13:10 | Reconnaissance, storage and session discovery commands executed |
| 2025-10-09 12:50–13:10 | Staging of artifacts, outbound connectivity, persistence mechanisms initiated |
| 2025-10-09 12:58 | Compressed artifacts created for potential exfiltration |
| 2025-10-09 12:58–13:10 | Outbound connection attempts to non-standard destinations |

---

## Investigation Narrative

Initial analysis focused on identifying the first execution point on the host. Subsequent activities revealed attempts to simulate security tampering, enumerate system and session details, probe clipboard and storage, and stage artifacts. Outbound connection attempts and persistence mechanisms were identified, demonstrating a coordinated attempt to maintain access and exfiltrate sensitive information.

---

## Flag Analysis

### Flag 1 – Initial Execution Point
- **Objective:** Identify the first CLI parameter used during initial execution.
- **Hypothesis:** Malicious actors often launch scripts with non-default execution policies.
- **Evidence Collected:** `-ExecutionPolicy` in CLI
- **Final Finding:** The attack began with PowerShell launched from Downloads using the `-ExecutionPolicy` argument.

### Flag 2 – Defense Disabling
- **Objective:** Identify files related to simulated security posture changes.
- **Hypothesis:** Creation of tamper artifacts indicates intent to bypass defenses.
- **Evidence Collected:** `DefenderTamperArtifact.lnk`
- **Final Finding:** Malicious actor staged a tamper artifact to simulate security changes.

### Flag 3 – Quick Data Probe
- **Objective:** Detect opportunistic access to sensitive data sources.
- **Hypothesis:** Short-lived clipboard probes are common pre-collection steps.
- **Evidence Collected:** `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`
- **Final Finding:** Early-stage reconnaissance probed clipboard content.

### Flag 4 – Host Context Recon
- **Objective:** Identify basic host and user context collection.
- **Hypothesis:** Actors gather environment and account information before further actions.
- **Evidence Collected:** 2025-10-09T12:51:44.3425653Z
- **Final Finding:** Host context enumeration occurred on 2025-10-09.

### Flag 5 – Storage Surface Mapping
- **Objective:** Detect discovery of local/network storage.
- **Hypothesis:** Enumeration of storage locations precedes collection.
- **Evidence Collected:** `"cmd.exe" /c wmic logicaldisk get name,freespace,size`
- **Final Finding:** Local storage enumeration detected.

### Flag 6 – Connectivity & Name Resolution Check
- **Objective:** Detect outward connectivity and DNS checks.
- **Hypothesis:** Actors validate egress before exfiltration.
- **Evidence Collected:** `RuntimeBroker.exe`
- **Final Finding:** Connectivity validation performed via RuntimeBroker.

### Flag 7 – Interactive Session Discovery
- **Objective:** Detect enumeration of active user sessions.
- **Hypothesis:** Actors gather active session info to guide attack timing.
- **Evidence Collected:** `2533274790397065`
- **Final Finding:** PowerShell process uniquely identified for session enumeration.

### Flag 8 – Runtime Application Inventory
- **Objective:** Detect enumeration of running processes/services.
- **Hypothesis:** Process inventory informs potential collection targets.
- **Evidence Collected:** `tasklist.exe`
- **Final Finding:** Runtime application inventory confirmed.

### Flag 9 – Privilege Surface Check
- **Objective:** Detect privilege discovery attempts.
- **Hypothesis:** Mapping privileges informs subsequent escalation strategy.
- **Evidence Collected:** 2025-10-09T12:52:14.3135459Z
- **Final Finding:** Privilege enumeration detected via PowerShell.

### Flag 10 – Proof-of-Access & Egress Validation
- **Objective:** Detect outbound reachability validation and host state capture.
- **Hypothesis:** Actors combine network checks with host artifacts before exfiltration.
- **Evidence Collected:** First outbound: `www.msftconnecttest.com`
- **Final Finding:** Outbound reachability confirmed post-artifact creation.

### Flag 11 – Bundling / Staging Artifacts
- **Objective:** Detect consolidation of artifacts for transfer.
- **Hypothesis:** Staging simplifies exfiltration and correlates with prior recon.
- **Evidence Collected:** `C:\Users\Public\ReconArtifacts.zip`
- **Final Finding:** Malicious artifacts staged for exfiltration.

### Flag 12 – Outbound Transfer Attempt (Simulated)
- **Objective:** Detect attempts to move data off-host.
- **Hypothesis:** Outbound transfer tests reveal egress paths.
- **Evidence Collected:** `100.29.147.161`
- **Final Finding:** Last outbound connection simulated egress testing.

### Flag 13 – Scheduled Re-Execution Persistence
- **Objective:** Detect mechanisms for repeated execution.
- **Hypothesis:** Scheduled tasks maintain access beyond initial session.
- **Evidence Collected:** `SupportToolUpdater`
- **Final Finding:** Persistent scheduled task created for ongoing execution.

### Flag 14 – Autorun Fallback Persistence
- **Objective:** Detect lightweight autorun persistence entries.
- **Hypothesis:** Backup autorun entries improve access resilience.
- **Evidence Collected:** `RemoteAssistUpdater`
- **Final Finding:** Fallback autorun mechanism identified.

### Flag 15 – Planted Narrative / Cover Artifact
- **Objective:** Identify narrative or misdirection artifacts.
- **Hypothesis:** Text or link files may explain malicious actions falsely.
- **Evidence Collected:** `SupportChat_log.lnk`
- **Final Finding:** Planted narrative created as misdirection.

---

## Indicators of Compromise (IoCs)

| IoC Type | Value |
|----------|-------|
| Files | `DefenderTamperArtifact.lnk`, `ReconArtifacts.zip`, `SupportTool.ps1`, `SupportToolUpdater`, `SupportChat_log.lnk` |
| Outbound IP | `100.29.147.161` |
| Outbound Domain | `www.msftconnecttest.com` |
| Process | `RuntimeBroker.exe`, `powershell.exe`, `tasklist.exe` |
| Scheduled Task | `SupportToolUpdater` |

---

## Recommendations

1. **Contain & Isolate** affected endpoints to prevent further artifact staging.
2. **Remove Persistent Tasks & Autorun Entries** like `SupportToolUpdater` and `RemoteAssistUpdater`.
3. **Audit Outbound Connections** to suspicious IPs and domains.
4. **Perform Full Artifact Analysis** on staged files for exfiltration impact.
5. **Enhance Monitoring** for rapid data probes and privilege checks.
6. **User Education** on downloading/executing files from untrusted sources.
