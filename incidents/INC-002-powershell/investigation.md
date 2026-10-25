# INC-002 — Suspicious PowerShell Investigation

## Incident Overview

| Field | Details |
|---|---|
| Case ID | INC-002 |
| Date | October 24, 2026 |
| Endpoint | SOC-WINDOWS — 192.168.245.20 |
| Remote Server | Kali Linux — 192.168.245.30:8088 |
| Data Sources | Sysmon, Wazuh, Kali HTTP Server |
| Classification | Benign True Positive |
| Case Severity | Low — Authorized Lab |
| Status | Investigation Completed |

## 1. Scenario

A controlled simulation reproduced suspicious PowerShell activity initiated through a desktop shortcut.

The PowerShell process used an encoded command to retrieve and execute a benign diagnostic script from a Kali HTTP server.

The script performed system and local-account discovery and saved its output locally.

The simulation did not involve real phishing, exploitation, credential theft, or persistence.

## 2. Detection Evidence

| Rule ID | Event ID | Finding |
|---|---|---|
| 100110 | Sysmon 1 | Encoded PowerShell execution |
| 92213 | Sysmon 11 | Temporary PowerShell file creation |
| 92213 | Sysmon 11 | Downloaded diagnostic script created |
| 100100 | Sysmon 1 | whoami.exe /all execution |
| 92033 | Sysmon 1 | net.exe user execution |
| 92031 | Sysmon 1 | net1.exe user execution |
| 100160 | Sysmon 3 | PowerShell TCP connection to Kali |

An additional `dllhost.exe` alert (Rule 61638) appeared in the investigated time window, but no causal relationship with the simulated activity was established.

## 3. Process Tree Reconstruction

The activity was reconstructed using Sysmon ProcessGuid and ParentProcessGuid fields.

```text
explorer.exe
└── powershell.exe -EncodedCommand ...
    ├── TCP connection → 192.168.245.30:8088
    ├── INC002-diagnostics.ps1 (file created)
    ├── __PSScriptPolicyTest_*.ps1 (temporary file)
    ├── whoami.exe /all
    └── net.exe user
        └── net1.exe user
```

### Process Correlation

| Process | ProcessGuid (abbreviated) | Parent |
|---|---|---|
| powershell.exe | d9b9-6adc-3b03 | explorer.exe |
| whoami.exe | d9bc-6adc-3e03 | powershell.exe |
| net.exe | d9bc-6adc-4103 | powershell.exe |
| net1.exe | d9bc-6adc-4203 | net.exe |

The second-generation `net1.exe` process was identified by pivoting from the `net.exe` ProcessGuid to matching ParentProcessGuid records.

This demonstrates multi-level process-tree reconstruction rather than timestamp-only correlation.

## 4. Network and File Evidence

The Kali HTTP server recorded a successful request from the Windows endpoint:

```text
192.168.245.20 - "GET /diagnostics.ps1 HTTP/1.1" 200
```

Sysmon also recorded creation of:

- `INC002-diagnostics.ps1` — the downloaded diagnostic script.
- `__PSScriptPolicyTest_*.ps1` — a temporary script consistent with PowerShell execution-policy checks.

The Windows endpoint contained a generated `INC002-discovery.txt` report with user, hostname, network, and local-account discovery sections.

These independent observations support the same execution scenario.

## 5. Timeline Validation

The timestamps below are from the Wazuh Manager and Sysmon records, in UTC.

| Event | Wazuh Timestamp | Sysmon UtcTime |
|---|---|---|
| PowerShell creation | 16:15:56.295 | 16:15:53.435 |
| PowerShell network event | 16:15:59.396 | 16:15:37.378 |

**Important discrepancy:** The Sysmon network event's `UtcTime` precedes the creation time of the same PowerShell process by approximately 16 seconds.

Windows Event SystemTime instead places the process-creation record before the network-event record.

The root cause of this discrepancy was not established. Exact network chronology should therefore not be inferred solely from these timestamps.

Process linkage remains supported by matching ProcessGuid values and independent host/network evidence.

## 6. MITRE ATT&CK Mapping

| Technique | Observed Behavior |
|---|---|
| T1059.001 — PowerShell | Encoded PowerShell execution |
| T1033 — System Owner/User Discovery | whoami.exe /all |
| T1087.001 — Local Account Discovery | net user |
| T1016 — System Network Configuration Discovery | ipconfig within the script |

These mappings describe behaviors simulated in the lab, not confirmed malicious use.

## 7. Incident Assessment

The execution chain resembles potentially suspicious activity involving encoded scripting, remote script retrieval, and local reconnaissance.

However:

- The activity was explicitly authorized.
- The remote server was controlled by the lab operator.
- The retrieved script contained known diagnostic commands.
- No credential theft, persistence, or exfiltration was established within the investigated scenario.

**Final classification:** Benign True Positive.

**Severity:** Low in the authorized lab context.

**Response decision:** No host containment required.

In an enterprise environment, the same behavioral sequence from an untrusted source would justify deeper investigation and potential escalation.

## 8. Evidence Screenshots

### Figure 1 — Detection Timeline

![INC-002 Detection Timeline](/screenshots/28-inc002-detection-timeline.png)

*Wazuh alerts showing encoded PowerShell execution, file creation, system discovery, and network activity.*

### Figure 2 — Process Tree Reconstruction

![INC-002 Process Tree](/screenshots/29-inc002-process-tree.png)

*Sysmon ProcessGuid and ParentProcessGuid evidence linking PowerShell with its child processes.*

### Figure 3 — File Creation Evidence

![INC-002 File Evidence](/screenshots/30-inc002-file-evidence.png)

*Sysmon Event ID 11 showing the downloaded diagnostic script and temporary PowerShell files.*

### Figure 4 — Timestamp Validation

![INC-002 Timestamp Validation](/screenshots/31-inc002-timestamp-validation.png)

*Comparison of Wazuh timestamps and Sysmon event timestamps, documenting the observed discrepancy.*
## 9. Cleanup

The following artifacts were removed from SOC-WINDOWS:

- `INC002-diagnostics.ps1`
- `INC002-discovery.txt`
- `INC002-LAB-Diagnostics.lnk`

Post-cleanup checks returned `False` for all three artifact paths.

The temporary Kali HTTP server was stopped, and no listener was observed on TCP port 8088.

Security logs were retained as investigation evidence.

## 10. Lessons Learned

- Reconstruct process trees using ProcessGuid and ParentProcessGuid.
- Investigate second-generation child processes.
- Correlate endpoint, SIEM, and network-server evidence.
- Distinguish downloaded scripts from temporary PowerShell files.
- Validate timestamp reliability before asserting an exact chronology.
- Separate suspicious technical behavior from confirmed malicious activity.
- Document investigation limitations instead of hiding uncertainty.

## Conclusion

INC-002 demonstrated an end-to-end investigation of an authorized suspicious-PowerShell simulation.

The investigation successfully correlated encoded PowerShell execution, network access, file creation, system discovery, and nested process activity while identifying a genuine timestamp-consistency limitation.
