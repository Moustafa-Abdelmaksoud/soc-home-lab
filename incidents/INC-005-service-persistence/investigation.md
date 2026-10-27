# INC-005 — Windows Service Persistence Investigation

| Field | Details |
|---|---|
| Incident ID | INC-005 |
| Scenario | Authorized Windows service persistence simulation |
| Endpoint | `SOC-WINDOWS` (Windows 11) |
| Monitoring | Windows Security/System Logs, Sysmon, Wazuh agent `001` |
| MITRE ATT&CK | **T1543.003 — Create or Modify System Process: Windows Service** |
| Disposition | **Authorized simulation / true-positive service installation detection** |
| Status | **Closed — persistence removed and lab artifacts cleaned up** |

## Executive Summary

A controlled Windows service was compiled and installed on `SOC-WINDOWS` to investigate service-based persistence. The service was configured for automatic startup, executed under `NT AUTHORITY\SYSTEM`, and wrote a local startup marker. Windows Security event **4697**, System event **7045**, and Sysmon process creation events documented installation and execution. Wazuh generated its built-in **rule 61138 (level 5), “New Windows Service Created,”** from event 7045.

The initial reboot produced service startup timeout events **7009/7000**: the executable was launched by `services.exe`, but the service did not reach a stable running state. Changing **only the test service** to *Automatic (Delayed Start)* resulted in successful execution and a `Running` service after reboot. The underlying cause of the original timeout was **not conclusively established**. The service was then stopped, disabled, deleted, and its executable removed; evidence copies were retained locally.

## Service Profile

| Attribute | Observed value |
|---|---|
| Internal service name | `SOC-LAB-Inc005Svc` |
| Display name | `SOC LAB INC005 Test Service` |
| Executable | `C:\ProgramData\SOC-LAB\INC005\SocLabService.exe` |
| Installation actor | `SOC-WINDOWS\socuser` (Security 4697) |
| Execution account | `LocalSystem` / `NT AUTHORITY\SYSTEM` |
| Start configuration | `Automatic`, later changed to `Automatic (Delayed Start)` |
| SHA-256 | `335A68DE48E79CF0E5B6E5877E1127D7F7725E646C9AB8AC533A0D53BBEDED5D` |
| Payload behavior | Append `SERVICE STARTED` / `SERVICE STOPPED` markers to a local lab log |

## Investigation and Evidence

### 1. Installation and execution

- **Security 4697:** `socuser` registered the service with automatic startup and `LocalSystem` as its run account.
- **System 7045:** Service Control Manager recorded installation using the **display name**, not the internal service name. This explained an initially empty text-based lookup.
- **Sysmon 1:** `powershell.exe` launched `csc.exe` to compile the service and `sc.exe` to install it. Subsequent `SocLabService.exe` execution used `NT AUTHORITY\SYSTEM`. The service process was linked to `services.exe` as its parent in the post-reboot event.
- **Wazuh:** Default rule **61138**, level **5**, alerted on System event **7045**. No additional service-creation rule was needed for basic installation visibility.

![Figure 41 — Service installation, automatic startup configuration, and initial execution](/screenshots/41-inc005-service-installation.png)

*Figure 41. Service registration, executable path, SYSTEM account, and startup log.*

![Figure 42 — Windows Security event 4697](/screenshots/42-inc005-security-4697.png)

*Figure 42. Security event 4697 identifies the installer and service configuration.*

![Figure 43 — Wazuh built-in service-installation alert](/screenshots/43-inc005-wazuh-61138.png)

*Figure 43. Wazuh rule 61138 detects System event 7045.*

### 2. Reboot persistence validation

| Test | Evidence | Outcome |
|---|---|---|
| Initial manual launch | `Running`; first `SERVICE STARTED` marker | **Passed** |
| Reboot with standard `Automatic` startup | Sysmon 1 showed `services.exe` launched the binary; System **7009** (45,000 ms timeout) and **7000** followed; service `Stopped` | **Executable launched; service startup failed** |
| Manual launch after the reboot | `Running`; second `SERVICE STARTED` marker | **Passed** |
| Reboot with `Automatic (Delayed Start)` | `Start=2`, `DelayedAutoStart=1`; service `Running`; Sysmon 1 showed `services.exe` as parent; third startup marker | **Persistence validated** |

![Figure 44 — Initial automatic startup failure](/screenshots/44-inc005-startup-timeout.png)

*Figure 44. Service Control Manager events 7009 and 7000 demonstrate the first boot-time failure.*

![Figure 45 — Delayed auto-start persistence after reboot](/screenshots/45-inc005-delayed-start-persistence.png)

*Figure 45. The delayed-start service is running after reboot and the third execution marker is present.*

**Timestamp note:** The lab showed a discrepancy between Windows-rendered local times and UTC timestamps recorded by Sysmon and the service log. Source-native timestamps were preserved rather than assuming a corrected offset.

### 3. Containment and eradication

1. Stopped the service and set its startup type to `Disabled`.
2. Verified the `SERVICE STOPPED` marker.
3. Deleted the service with `sc.exe delete`.
4. Confirmed `sc.exe query` returned **1060 (service does not exist)**, the corresponding registry key was absent, and no service process remained.
5. Preserved `service-starts.log` and the SHA-256 record under `C:\SOC-LAB\INC005\evidence\`.
6. Removed the test source, executable, log, and `C:\ProgramData\SOC-LAB\INC005` directory.

![Figure 46 — Service stopped and disabled](/screenshots/46-inc005-service-containment.png)

*Figure 46. Containment verification: `Stopped`, `Disabled`, and the stop marker.*

![Figure 47 — Service registration eradication](/screenshots/47-inc005-service-eradication.png)

*Figure 47. Service deletion confirmed by error 1060 and absence of the service registry key.*

![Figure 48 — Final artifact cleanup verification](/screenshots/48-inc005-final-cleanup.png)

*Figure 48. Lab directory, service, and executable are absent; evidence files remain in the separate evidence directory.*

## Detection Assessment

**Confirmed detection:** Wazuh **61138** alerted on Windows System **7045** (new service installation). Windows Security **4697** supplied the installing account; Sysmon **1** supplied process context and SHA-256. The existing Wazuh rule provided installation detection, so no duplicate custom rule was created.

**Limitations:** New services and `ProgramData` execution are not inherently malicious. Rule 61138 identifies installation, not guaranteed successful persistence or compromise. The initial startup timeout was observed but its root cause was not proven. This was a deliberately authorized, benign service with no malicious payload.

## Final Assessment

**Verdict:** Authorized persistence simulation; **true positive** for new-service installation. **Successful delayed-auto-start persistence** was demonstrated after reboot. **Containment and eradication completed**: the service, registration key, running process, executable, and test directory were absent at final verification. Only the specifically preserved local evidence remained.
