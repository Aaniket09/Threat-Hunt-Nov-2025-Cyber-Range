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

## Timeline

| **Time (UTC)** | **Flag** | **Action Observed** | **Key Evidence** |
|----------------|----------|---------------------|------------------|
| *To be filled* | Flag 1 | Initial execution point identified | `-ExecutionPolicy` CLI parameter |
| *To be filled* | Flag 2 | Defense tampering simulation | `DefenderTamperArtifact.lnk` |
| *To be filled* | Flag 3 | Clipboard data probe | PowerShell `Get-Clipboard` command |
| *To be filled* | Flag 4 | Host context reconnaissance | Host enumeration commands |
| *To be filled* | Flag 5 | Storage surface mapping | `wmic logicaldisk get name,freespace,size` |
| *To be filled* | Flag 6 | Connectivity validation | `RuntimeBroker.exe` network checks |
| *To be filled* | Flag 7 | Interactive session discovery | Session enumeration commands |
| *To be filled* | Flag 8 | Runtime application inventory | `tasklist.exe` execution |
| *To be filled* | Flag 9 | Privilege surface check | Privilege enumeration commands |
| *To be filled* | Flag 10 | Egress validation & proof-of-access | `www.msftconnecttest.com` connection |
| *To be filled* | Flag 11 | Artifact staging for exfiltration | `C:\Users\Public\ReconArtifacts.zip` |
| *To be filled* | Flag 12 | Outbound transfer attempt | IP `100.29.147.161` |
| *To be filled* | Flag 13 | Scheduled task persistence | `SupportToolUpdater` task |
| *To be filled* | Flag 14 | Autorun persistence mechanism | `RemoteAssistUpdater` registry entry |
| *To be filled* | Flag 15 | Cover artifact creation | `SupportChat_log.lnk` |

---

## Investigation Narrative

Initial analysis focused on identifying the first execution point on the host. Subsequent activities revealed attempts to simulate security tampering, enumerate system and session details, probe clipboard and storage, and stage artifacts. Outbound connection attempts and persistence mechanisms were identified, demonstrating a coordinated attempt to maintain access and exfiltrate sensitive information.

---

## Flag Analysis

### Flag 1 – Initial Execution Point
- **Objective:** Identify the first CLI parameter used during initial execution.
- **Hypothesis:** Malicious actors often launch scripts with non-default execution policies.
- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated  between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FolderPath has @"\Downloads\" or ProcessCommandLine has @"\Downloads\"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by TimeGenerated asc
| take 20
```
<img width="428" height="258" alt="Screenshot 2025-08-17 213533" src="https://github.com/user-attachments/assets/116cd420-68e4-4dc7-8b44-fcb2d85bf242" />

- **Evidence Collected:** `-ExecutionPolicy` in CLI
- **Final Finding:** The attack began with PowerShell launched from Downloads using the `-ExecutionPolicy` argument.

### Flag 2 – Defense Disabling
- **Objective:** Identify files related to simulated security posture changes.
- **Hypothesis:** Creation of tamper artifacts indicates intent to bypass defenses.
- **KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated  between (datetime(2025-10-09T12:20:00Z)..datetime(2025-10-09T13:00:00Z))
| where InitiatingProcessFileName in ("powershell.exe", "explorer.exe", "notepad.exe") and FileName contains "tamper"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
- **Evidence Collected:** `DefenderTamperArtifact.lnk`
- **Final Finding:** Malicious actor staged a tamper artifact to simulate security changes.

### Flag 3 – Quick Data Probe
- **Objective:** Detect opportunistic access to sensitive data sources.
- **Hypothesis:** Short-lived clipboard probes are common pre-collection steps.
- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated  between (datetime(2025-10-09T12:20:00Z)..datetime(2025-10-09T13:00:00Z))
| where ProcessCommandLine has "Get-Clipboard" or ProcessCommandLine has "clip.exe" or ProcessCommandLine has "Get-Clip"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
- **Evidence Collected:** `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`
- **Final Finding:** Early-stage reconnaissance probed clipboard content.

### Flag 4 – Host Context Recon
- **Objective:** Identify basic host and user context collection.
- **Hypothesis:** Actors gather environment and account information before further actions.
- **KQL Query Used:**
```
let startTime = datetime(2025-10-01);
let endTime   = datetime(2025-10-15);
let recon_terms = dynamic(["qwinsta","quser","query user","query","whoami","hostname","systeminfo","net user"]);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (startTime .. endTime)
| where ProcessCommandLine has_any (recon_terms) or FileName has_any (recon_terms)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated desc
```
- **Evidence Collected:** 2025-10-09T12:51:44.3425653Z
- **Final Finding:** Host context enumeration occurred on 2025-10-09.

### Flag 5 – Storage Surface Mapping
- **Objective:** Detect discovery of local/network storage.
- **Hypothesis:** Enumeration of storage locations precedes collection.
- **KQL Query Used:**
```
let storage_terms = dynamic(["get", "wmic"]);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated  between (datetime(2025-10-09T12:20:00Z)..datetime(2025-10-09T13:00:00Z))
| where ProcessCommandLine has_any (storage_terms) or FileName has_any (storage_terms)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by TimeGenerated asc
```
- **Evidence Collected:** `"cmd.exe" /c wmic logicaldisk get name,freespace,size`
- **Final Finding:** Local storage enumeration detected.

### Flag 6 – Connectivity & Name Resolution Check
- **Objective:** Detect outward connectivity and DNS checks.
- **Hypothesis:** Actors validate egress before exfiltration.
- **KQL Query Used:**
```
let net_terms = dynamic(["nslookup","ping","tracert","curl","wget"]);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:45:00Z) .. datetime(2025-10-09T13:10:00Z))
| where ProcessCommandLine has_any (net_terms) or FileName has_any (net_terms)
| project TimeGenerated, FileName, InitiatingProcessParentFileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc
```
- **Evidence Collected:** `RuntimeBroker.exe`
- **Final Finding:** Connectivity validation performed via RuntimeBroker.

### Flag 7 – Interactive Session Discovery
- **Objective:** Detect enumeration of active user sessions.
- **Hypothesis:** Actors gather active session info to guide attack timing.
- **KQL Query Used:**
```
let session_terms = dynamic(["qwinsta", "quser", "query user", "query session", "whoami", "session"]);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:20:00Z)..datetime(2025-10-09T13:10:00Z))
| where ProcessCommandLine has_any (session_terms) or FileName has_any (session_terms)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId
| order by TimeGenerated asc
```
- **Evidence Collected:** `2533274790397065`
- **Final Finding:** PowerShell process uniquely identified for session enumeration.

### Flag 8 – Runtime Application Inventory
- **Objective:** Detect enumeration of running processes/services.
- **Hypothesis:** Process inventory informs potential collection targets.
- **KQL Query Used:**
```
let search_terms = dynamic(["Get-Process", "sc", "Get-Service", "net start", "tasklist"]);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:20:00Z)..datetime(2025-10-09T14:10:00Z))
| where ProcessCommandLine has_any (search_terms)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```
- **Evidence Collected:** `tasklist.exe`
- **Final Finding:** Runtime application inventory confirmed.

### Flag 9 – Privilege Surface Check
- **Objective:** Detect privilege discovery attempts.
- **Hypothesis:** Mapping privileges informs subsequent escalation strategy.
- **KQL Query Used:**
```
let search_terms = dynamic(["whoami", "net user"]);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:20:00Z)..datetime(2025-10-09T14:10:00Z))
| where ProcessCommandLine has_any (search_terms)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```
- **Evidence Collected:** 2025-10-09T12:52:14.3135459Z
- **Final Finding:** Privilege enumeration detected via PowerShell.

### Flag 10 – Proof-of-Access & Egress Validation
- **Objective:** Detect outbound reachability validation and host state capture.
- **Hypothesis:** Actors combine network checks with host artifacts before exfiltration.
- **KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:50:00Z)..datetime(2025-10-09T13:00:00Z))
| where FileName contains "support" or FolderPath contains "support"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by TimeGenerated asc
```
```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:50:00Z)..datetime(2025-10-09T13:00:00Z))
| where ActionType == "ConnectionSuccess" 
| where RemoteIP has "."  
| where RemoteUrl !has "microsoft" and RemoteUrl !has "windows"
| project TimeGenerated, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
- **Evidence Collected:** First outbound: `www.msftconnecttest.com`
- **Final Finding:** Outbound reachability confirmed post-artifact creation.

### Flag 11 – Bundling / Staging Artifacts
- **Objective:** Detect consolidation of artifacts for transfer.
- **Hypothesis:** Staging simplifies exfiltration and correlates with prior recon.
- **KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:58:00Z)..datetime(2025-10-09T13:10:00Z))
| where ActionType == "FileCreated" or FileName contains ".zip"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
- **Evidence Collected:** `C:\Users\Public\ReconArtifacts.zip`
- **Final Finding:** Malicious artifacts staged for exfiltration.

### Flag 12 – Outbound Transfer Attempt (Simulated)
- **Objective:** Detect attempts to move data off-host.
- **Hypothesis:** Outbound transfer tests reveal egress paths.
- **KQL Query Used:**
```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T13:00:00Z)..datetime(2025-10-09T13:10:00Z))
| where RemoteIP has "."  
| where RemoteUrl !has "microsoft" and RemoteUrl !has "windows"  
| project TimeGenerated, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
- **Evidence Collected:** `100.29.147.161`
- **Final Finding:** Last outbound connection simulated egress testing.

### Flag 13 – Scheduled Re-Execution Persistence
- **Objective:** Detect mechanisms for repeated execution.
- **Hypothesis:** Scheduled tasks maintain access beyond initial session.
- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:50:00Z)..datetime(2025-10-09T13:10:00Z))
| where ProcessCommandLine contains "schtasks" 
   or ProcessCommandLine contains "Register-ScheduledTask"
   or FileName == "schtasks.exe"
| order by TimeGenerated asc

```
- **Evidence Collected:** `SupportToolUpdater`
- **Final Finding:** Persistent scheduled task created for ongoing execution.

### Flag 14 – Autorun Fallback Persistence
- **Objective:** Detect lightweight autorun persistence entries.
- **Hypothesis:** Backup autorun entries improve access resilience.
- **KQL Query Used:**
```
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:50:00Z)..datetime(2025-10-09T13:10:00Z))
| order by TimeGenerated asc
```
- **Evidence Collected:** `RemoteAssistUpdater` as query returned no result, so used this instead.
- **Final Finding:** Fallback autorun mechanism identified.

### Flag 15 – Planted Narrative / Cover Artifact
- **Objective:** Identify narrative or misdirection artifacts.
- **Hypothesis:** Text or link files may explain malicious actions falsely.
- **KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:50:00Z)..datetime(2025-10-09T13:10:00Z))
| where ActionType == "FileCreated" or ActionType == "FileModified"
| where FileName endswith ".txt" or FileName endswith ".lnk" or FileName endswith ".log"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by TimeGenerated asc
```
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
