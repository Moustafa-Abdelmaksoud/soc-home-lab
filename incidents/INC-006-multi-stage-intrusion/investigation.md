# INC-006 — Multi-Stage Intrusion Investigation

| Field | Details |
|---|---|
| Incident ID | INC-006 |
| Date | October 28, 2026 |
| Scenario | Authorized multi-stage attack simulation in an isolated VirtualBox SOC lab |
| Endpoint | `SOC-WINDOWS` — `192.168.245.20` (Windows 11 Pro) |
| Source | Kali — `192.168.245.30` |
| SIEM | Wazuh manager — `192.168.245.10`, Windows agent `001` |
| Disposition | Controlled simulation; multiple true-positive detections |
| Status | **Closed — containment and seven core recovery checks verified** |

## Executive Summary

INC-006 reconstructed an end-to-end intrusion: full TCP reconnaissance, limited RDP password guessing, standard-user access, deliberate Windows service misconfiguration abuse, SYSTEM-level command execution, administrative account persistence, registry hive acquisition, and transfer of three sensitive hive copies to Kali over SMB.

The lab-only service executable was writable by the low-privilege user, who could also start and stop the service. After binary replacement, Sysmon correlated `LabService.exe → cmd.exe → net.exe → net1.exe` executing as `NT AUTHORITY\SYSTEM`. Windows Security events confirmed creation of a new local administrative account. Wazuh detected the password-guessing sequence, service-binary integrity change, account activity, and SAM hive save. Windows Security 5145 auditing independently corroborated file-level SMB access.

**Scope and limitations:** This was an authorized experiment, not a real-world compromise. The evidence demonstrates SYSTEM **code execution**, **not** an interactive SYSTEM shell. Registry hives were copied, but extraction of plaintext passwords, NTLM hashes, or LSA secrets was **not** demonstrated.

## Intrusion Timeline

| Stage | Observation | Key evidence |
|---|---|---|
| 1. Reconnaissance | Nmap scanned all 65,535 TCP ports. Open: `135`, `445`, `3389`, `7680`, `49668`. | Full TCP and service-version scan |
| 2. Initial access | Limited failed RDP authentication attempts followed by successful access as `inc006_employee`. | Security `4625` / `4624`; Wazuh `100120` (level 10), `92653` (type 10 RDP) |
| 3. Discovery | Low-privilege `inc006_employee` had Medium integrity, without Administrators membership. | `whoami /user`, `/priv`, `/groups`; OS and service enumeration |
| 4. Privilege escalation | A deliberately weak service allowed the standard user to modify its binary and start/stop it. | NTFS `Modify` ACE; file-write test; service configuration |
| 5. SYSTEM execution | A replaced service binary executed as SYSTEM and spawned command and account-management processes. | Wazuh FIM `550`; Sysmon Event `1`, ProcessGuid lineage |
| 6. Persistence | SYSTEM-context commands created local `hacker`, added it to Administrators, and an elevated High-integrity session was observed. | Security `4720`, `4732`; Wazuh `60109`, `60154`; elevated token evidence |
| 7. Credential-store acquisition | `reg.exe save` produced local copies of SAM, SECURITY, and SYSTEM. | Command completion; Sysmon Event `1`; Wazuh SAM-save alert |
| 8. SMB transfer | `TempShare` exposed `C:\Temp`; Kali `smbclient` reported three successful downloads. | SMB client results; Windows Security `5145` for each filename |
| 9. Response | Access paths closed, accounts and weak service removed, temporary files deleted, and original RDP/firewall/FIM settings restored. | Containment and recovery verification |

**Timestamp caveat:** Windows local-event times, Sysmon UTC times, and Wazuh dashboard displays used different clock representations. These observations are correlated by identifiers and sequence, not by assuming a single normalized timezone.

### Reconnaissance and RDP Evidence

![Figure 49 — Full TCP Nmap scan of SOC-WINDOWS showing five open ports.](/screenshots/49-inc006-full-tcp-scan.png)

*Figure 49. Full TCP Nmap scan of SOC-WINDOWS showing five open ports.*

![Figure 50 — Wazuh correlation of failed logons and successful RDP activity for the test account.](/screenshots/50-inc006-rdp-detection.png)

*Figure 50. Wazuh correlation of failed logons and successful RDP activity for the test account.*

## Key Forensic Findings

### Service Binary Hijacking and Process Correlation

The specially created service `SOC-LAB-INC006-WeakSvc` ran as `LocalSystem`. Its executable was `C:\ProgramData\SOC-LAB\INC006\WeakService\LabService.exe`. The test user had inherited `Modify` rights and successfully opened it for writing without changing the original baseline. A separate test confirmed that the same user could start and stop the service.

The original binary SHA-256 was `14F34919D7E5518C5109938AF4BE229D0E9F5A1DE9CC6E6B0B28DD2CA3FFF4AD`. Subsequent replacement was detected by **Wazuh FIM rule 550**, `syscheck.event=modified`, with a different file hash.

Sysmon Event 1 recorded the following process tree around **07:12:38–39, October 28 (Windows local display)**:

```text
LabService.exe                     NT AUTHORITY\SYSTEM
└── cmd.exe                        NT AUTHORITY\SYSTEM
    ├── net.exe → net1.exe         NT AUTHORITY\SYSTEM
    └── net.exe → net1.exe         NT AUTHORITY\SYSTEM
```

The `cmd.exe` ParentProcessGuid matched the service ProcessGuid; the two `net.exe` children matched the `cmd.exe` ProcessGuid, and the corresponding `net1.exe` processes matched their `net.exe` parents. Additional `net.exe/net1.exe` events at 07:12:56–57 under `inc006_employee` had a **different** lineage and are excluded from the SYSTEM chain.

Security `4720` and `4732` confirmed creation of the test account and Administrators membership. The subsequent `hacker` session showed **High Mandatory Level**, an enabled Administrators group, and `SeDebugPrivilege`; this proves elevated administrator access, **not** an interactive SYSTEM shell.

### Service Hijacking and Administrative Persistence Evidence

![Figure 51 — Wazuh FIM rule 550 reports modification of the service executable.](/screenshots/51-inc006-service-fim.png)

*Figure 51. Wazuh FIM rule 550 reports modification of the service executable.*

![Figure 52 — Sysmon ProcessGuid and ParentProcessGuid lineage confirms SYSTEM-level service-to-command execution.](/screenshots/52-inc006-system-process-tree.png)

*Figure 52. Sysmon ProcessGuid and ParentProcessGuid lineage confirms SYSTEM-level service-to-command execution.*

![Figure 53 — Wazuh detects creation of the test account and its addition to the local Administrators group.](/screenshots/53-inc006-account-persistence.png)

*Figure 53. Wazuh detects creation of the test account and its addition to the local Administrators group.*

### Credential Store Collection and SMB Transfer

`reg.exe save` successfully acquired three registry hive copies under `C:\Temp`. Wazuh produced a process-creation alert describing a SAM hive dump. Equivalent alerts for every hive save were not independently verified.

Windows Event `5145` captured access to the three filenames through `TempShare` from `192.168.245.30` as `SOC-WINDOWS\hacker`, all associated with Logon ID `0x2313BCF`:

| Windows local time | Relative target | Access mask |
|---|---|---|
| 09:36:55 | `SAM.save` | `0x120089` |
| 09:37:03 | `SECURITY.save` | `0x120089` |
| 09:37:11 | `SYSTEM.save` | `0x120089` |

Event 5145 proves a share access check permitting read-related access, **not** that every byte was transferred. The separate `smbclient get` completion messages support the transfer conclusion. No recovered credentials or secrets are included.

### Credential-Store Acquisition and SMB Evidence

![Figure 54 — Wazuh detects reg.exe saving the SAM registry hive.](/screenshots/54-inc006-hive-detection.png)

*Figure 54. Wazuh detects reg.exe saving the SAM registry hive.*

![Figure 55 — Kali smbclient reports completion of three registry-hive copy downloads.](/screenshots/55-inc006-smb-transfer.png)

*Figure 55. Kali smbclient reports completion of three registry-hive copy downloads.*

![Figure 56 — Wazuh share-access alert connects TempShare, the test account, and the Kali source IP; file-level access is corroborated by separate Windows 5145 records.](/screenshots/56-inc006-smb-share-access.png)

*Figure 56. Wazuh share-access alert connects TempShare, the test account, and the Kali source IP; file-level access is corroborated by separate Windows 5145 records.*

## Detection Assessment

| Sensor / detection | Result | Analyst assessment |
|---|---|---|
| Security `4625` / `4624` | Observed | Failed attempts followed by successful authentication |
| Wazuh `100120` | Triggered, level 10 | Password-guessing detection |
| Wazuh `92653` | Triggered | RDP type 10 evidence; distinguish from type 3 network authentication |
| Wazuh FIM `554` | Triggered | Real-time FIM validated using a benign canary file |
| Wazuh FIM `550` | Triggered | Service binary modified; FIM alone does not attribute the modifying user |
| Sysmon `1` | Observed | Direct service-to-command process correlation as SYSTEM |
| Security `4720`, `4732` | Observed | New local account and Administrators membership |
| Wazuh `60109`, `60154` | Triggered | Account creation and group-change visibility |
| Sysmon / Wazuh SAM-save alert | Triggered | Detectable credential-store acquisition action |
| Security `5145` | Observed for all three | File-level share access, corroborated by SMB client transfer log |

**Detection lessons:** ProcessGuid correlation avoids combining unrelated processes; service creation and modification are distinct signals; SMB share access is not synonymous with confirmed file transfer; and enabling FIM on the relevant executable path closed a monitoring gap for this exercise.

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Network Service Discovery | `T1046` | Nmap full TCP scan |
| Brute Force: Password Guessing | `T1110.001` | Failed RDP logons |
| Remote Services: Remote Desktop Protocol | `T1021.001` | RDP session as `inc006_employee` |
| Hijack Execution Flow: Services File Permissions Weakness | `T1574.010` | Modified service binary executed as SYSTEM |
| Create Account: Local Account | `T1136.001` | Account `hacker` created |
| Account Manipulation: Additional Local or Domain Groups | `T1098.007` | Added to local Administrators |
| OS Credential Dumping: Security Account Manager | `T1003.002` | SAM hive copy acquired, no hashes extracted |
| OS Credential Dumping: LSA Secrets | `T1003.004` | SECURITY hive copy acquired, no secrets extracted |

## Containment, Eradication, and Recovery

The responder removed the temporary share; terminated the lingering SMB session; disabled, deprivileged and ultimately removed the new account; stopped/disabled/deleted the vulnerable test service; removed the permissive NTFS ACE; and deleted the targeted test directories. The dedicated initial-access user was removed, as were the copied hive files in the verified Windows and Kali working locations. RDP was re-disabled, the lab-specific firewall exception removed, and the temporary FIM watch entry removed. Wazuh agent monitoring remained operational.

**Final seven-point Windows verification:**

```text
HackerExists       False
EmployeeExists     False
WeakServiceExists  False
TempShareExists    False
RDPDisabled        True
WazuhRunning       True
LabDirExists       False
```

These checks establish recovery within the inspected scope; they do not prove forensic-grade removal of data from unexamined directories, VM snapshots, or backups. Registry hive copies may expose lab account credentials; appropriate password rotation and snapshot handling remain important.

### Recovery Evidence

![Figure 57 — Final recovery verification: test accounts, service, share, and lab directories absent; RDP disabled; Wazuh running.](/screenshots/57-inc006-recovery-verification.png)

*Figure 57. Final recovery verification: test accounts, service, share, and lab directories absent; RDP disabled; Wazuh running.*

## Final Assessment

**Closed — successful authorized multi-stage simulation with verified core recovery.** Investigation correlated endpoint, authentication, file-integrity, process lineage, registry acquisition, and SMB audit evidence. SYSTEM-level command execution, elevated administrator access, three hive-copy acquisitions, and SMB transfers are supported; interactive SYSTEM shell access and credential-hash extraction were not demonstrated.
