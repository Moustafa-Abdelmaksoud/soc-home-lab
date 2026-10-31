# MITRE ATT&CK Mapping

This mapping summarizes the techniques documented in the lab's eight detection exercises and six incident investigations. The references point to investigation evidence; they do not claim complete ATT&CK coverage.

| Technique | Behavior represented in the lab | Supporting evidence |
|---|---|---|
| T1033 — System Owner/User Discovery | Identity discovery via `whoami` | [D001](/detections/D001-whoami-execution.md), [INC-002](/incidents/INC-002-powershell/investigation.md) |
| T1059.001 — PowerShell | Encoded PowerShell, process ancestry, network activity | [D002](/detections/D002-encoded-powershell.md), [D004](/detections/D004-scripting-host-powershell.md), [D007](/detections/D007-powershell-network-connection.md) |
| T1110.001 — Password Guessing | Repeated failed logons / controlled RDP guessing | [D003](/detections/D003-repeated-failed-logons.md), [INC-006](/incidents/INC-006-multi-stage-intrusion/investigation.md) |
| T1053.005 — Scheduled Task | Task creation involving encoded PowerShell | [D005](/detections/D005-suspicious-scheduled-task.md) |
| T1547.001 — Registry Run Keys / Startup Folder | Encoded PowerShell auto-start entry | [D006](/detections/D006-registry-persistence.md) |
| T1039 — Data from Network Shared Drive | Repeated SMB document access requests (potential collection) | [D008](/detections/D008-smb-bulk-document-access.md), [INC-004](/incidents/INC-004-smb-file-access/investigation.md) |
| T1136.001 — Create Account: Local Account | Local account creation | [INC-003](/incidents/INC-003-admin-account/investigation.md), [INC-006](/incidents/INC-006-multi-stage-intrusion/investigation.md) |
| T1098.007 — Account Manipulation: Additional Local or Domain Groups | Test account added to local Administrators | [INC-003](/incidents/INC-003-admin-account/investigation.md), [INC-006](/incidents/INC-006-multi-stage-intrusion/investigation.md) |
| T1543.003 — Create or Modify System Process: Windows Service | Windows service creation and persistence validation | [INC-005](/incidents/INC-005-service-persistence/investigation.md) |
| T1046 — Network Service Discovery | All-port TCP scan against the lab endpoint | [INC-006](/incidents/INC-006-multi-stage-intrusion/investigation.md) |
| T1021.001 — Remote Services: Remote Desktop Protocol | RDP session from controlled initial access | [INC-006](/incidents/INC-006-multi-stage-intrusion/investigation.md) |
| T1574.010 — Hijack Execution Flow: Services File Permissions Weakness | Modified service binary executed in SYSTEM context | [INC-006](/incidents/INC-006-multi-stage-intrusion/investigation.md) |
| T1003.002 — OS Credential Dumping: Security Account Manager | SAM hive copy acquired (no hashes extracted) | [INC-006](/incidents/INC-006-multi-stage-intrusion/investigation.md) |
| T1003.004 — OS Credential Dumping: LSA Secrets | SECURITY hive copy acquired (no secrets extracted) | [INC-006](/incidents/INC-006-multi-stage-intrusion/investigation.md) |

## Interpretation

ATT&CK techniques describe investigated behavior or detection intent. A rule match alone does not establish compromise. In particular, SMB Event 5145 is an access check, and registry-hive acquisition is not the same as credential-hash extraction.

The dedicated investigation and detection reports contain the event-level details, test scope, and limitations.
