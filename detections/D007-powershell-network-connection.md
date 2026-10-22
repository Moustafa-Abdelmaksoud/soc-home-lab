# D007 — PowerShell Network Connection Detection

## Overview

Detect outbound TCP connections initiated by PowerShell to a monitored destination port using Sysmon Event ID 3 and a custom Wazuh rule.

This detection was developed as a controlled lab proof of concept to demonstrate process-aware network monitoring, Wazuh rule inheritance, and positive/negative detection testing.

**Important:** TCP port 8088 is used only as a test indicator. Connections to this port are not inherently malicious.

## Detection Details

| Field | Value |
|---|---|
| Detection ID | D007 |
| Detection Name | PowerShell Outbound Network Connection |
| Custom Rule ID | 100160 |
| Parent Rule | 92101 |
| Data Source | Sysmon Event ID 3 |
| Event Type | Network Connection |
| Severity | Level 6 |
| Monitored Process | powershell.exe |
| Protocol | TCP |
| Connection Initiated | true |
| Monitored Destination Port | 8088 |
| MITRE ATT&CK | T1059.001 — PowerShell |
| Detection Status | Validated for the tested positive and port-negative scenarios |
| Scope | Lab Proof of Concept |

## Lab Environment

| Component | Host | IP Address |
|---|---|---|
| Wazuh Server | SOC-WAZUH | 192.168.245.10 |
| Windows Endpoint | SOC-WINDOWS | 192.168.245.20 |
| HTTP Test Server | Kali Linux | 192.168.245.30 |

The systems communicated over an isolated VirtualBox Host-Only network.

A Python HTTP server hosted a harmless test page on Kali Linux.

## Detection Objective

Identify PowerShell processes initiating TCP connections to a selected destination port.

The detection focuses on the process responsible for the network connection rather than the destination port alone.

The rule does not attempt to determine whether the HTTP request is malicious.

## Detection Logic

The custom detection requires:

1. Sysmon Event ID 3 — Network Connection.
2. A PowerShell process communicating over TCP, identified by Wazuh Rule 92101.
3. The process initiated the connection.
4. The destination port equals 8088.

### Custom Wazuh Rule

```xml
<group name="local,sysmon,network_detection,">

  <rule id="100160" level="6">

    <if_sid>92101</if_sid>

    <field name="win.eventdata.initiated" type="pcre2">(?i)^true$</field>

    <field name="win.eventdata.destinationPort" type="pcre2">^8088$</field>

    <description>D007 - PowerShell initiated TCP connection to monitored port 8088 at $(win.eventdata.destinationIp)</description>

    <mitre>
      <id>T1059.001</id>
    </mitre>

    <group>powershell_network_activity,</group>

  </rule>

</group>
```

**Rule Location:** `/var/ossec/etc/rules/local_rules.xml`

The rule was validated using `wazuh-analysisd -t` and tested against real endpoint network activity.

## Built-in Rule Investigation

Before implementing D007, the existing Sysmon network rules were inspected.

| Rule ID | Level | Purpose |
|---|---|---|
| 61605 | 0 | Base Sysmon Event ID 3 detection |
| 92101 | 0 | PowerShell process communicating over TCP |
| 92102 | 6 | PowerShell connection to TCP port 135 |
| 92103 | 6 | PowerShell connection to TCP port 389 |
| 92107 | 4 | WScript/CScript network activity |
| 92110 | 4 | WinRM network activity on TCP port 5985 |

D007 inherits Rule 92101 through `<if_sid>92101</if_sid>`.

This avoids repeating the PowerShell executable and TCP protocol conditions in the custom rule.

Because Rule 92101 operates at Level 0, its matches do not normally generate standalone alerts in `wazuh-alerts-*` unless another rule produces an alert.

## Process and Network Correlation

Two Sysmon event types were analyzed:

| Sysmon Event | Purpose |
|---|---|
| Event ID 1 | Process Creation |
| Event ID 3 | Network Connection |

The events were correlated using the same `ProcessGuid`.

**Observed ProcessGuid:**

```text
{3f977765-ff4a-6ad9-8601-000000001a00}
```

### Observed Process Context

| Field | Value |
|---|---|
| Parent Process | explorer.exe |
| Child Process | powershell.exe |
| Process ID | 4388 |
| User | SOC-WINDOWS\socuser |
| Integrity Level | Medium |

### Observed Network Context

| Field | Value |
|---|---|
| Source IP | 192.168.245.20 |
| Destination IP | 192.168.245.30 |
| Destination Port | 8088 |
| Protocol | TCP |
| Initiated | true |

The matching ProcessGuid established that the PowerShell process observed in Event ID 1 was responsible for the connection recorded in Event ID 3.

The process creation event showed the executable and its parent but did not capture the interactive `Invoke-WebRequest` command entered later in the existing PowerShell session.

![Process and Network Correlation](/screenshots/22-d007-process-guid-correlation.png)

*Figure 1 — Sysmon ProcessGuid correlation between process creation and network activity.*

## Testing and Validation

### Positive Test — PowerShell to TCP/8088

A Python HTTP server was started on Kali Linux.

```bash
python3 -m http.server 8088 \
  --bind 192.168.245.30 \
  --directory ~/soc-network-lab
```

PowerShell initiated a harmless HTTP request:

```powershell
Invoke-WebRequest `
    -Uri "http://192.168.245.30:8088/" `
    -UseBasicParsing
```

**Expected:** Wazuh Rule 100160 generates an alert.

**Observed:** One alert was generated under Rule 100160.

**Result: PASS**

![D007 Positive Test](/screenshots/21-d007-positive-test.png)

*Figure 2 — Wazuh Rule 100160 detected the PowerShell TCP connection to port 8088.*

### Negative Test 1 — Different Process, Same Port

HTTP requests were generated using alternative executables:

- `curl.exe`
- `cscript.exe`
- A copy of curl.exe executed from the user's temporary directory

The requests successfully retrieved the HTTP test page.

However, corresponding Sysmon Event ID 3 records were not found during the investigation, and no Rule 100160 alerts were observed.

**Expected:** Network events are recorded without triggering D007.

**Observed:** Network requests succeeded, but matching Sysmon network events were not confirmed.

**Result: INCONCLUSIVE**

This test cannot be marked as passed because the expected underlying telemetry was not verified.

### Negative Test 2 — PowerShell to TCP/8080

A second HTTP server was started on TCP port 8080.

PowerShell connected to:

```text
http://192.168.245.30:8080/
```

Sysmon recorded Event ID 3 with the following attributes:

| Field | Observed |
|---|---|
| Image | powershell.exe |
| Destination IP | 192.168.245.30 |
| Destination Port | 8080 |
| Protocol | tcp |
| Initiated | true |

No Rule 100160 alerts appeared during the negative-test period.

**Expected:** No D007 alert because the destination port differs from 8088.

**Observed:** Event ID 3 was recorded locally, and no D007 alert appeared in the checked Wazuh alert window.

**Result: PASS within the tested scope**

The negative event's ingestion by Wazuh was not independently verified.

![D007 Negative Sysmon Event](/screenshots/23-d007-negative-port-sysmon.png)

*Figure 3 — Sysmon recorded a PowerShell network connection to TCP port 8080.*

![D007 Negative Wazuh Result](/screenshots/24-d007-negative-port-wazuh.png)

*Figure 4 — No Rule 100160 alerts were observed during the port-negative test.*

## Telemetry Coverage Investigation

During testing, successful HTTP connections from curl.exe and cscript.exe did not produce matching Sysmon Event ID 3 records in the inspected log output.

The active Sysmon configuration confirmed that:

- Network connection logging was enabled.
- NetworkConnect included process-based filters.
- PowerShell was explicitly included.
- curl.exe was not explicitly included by executable name.
- cscript.exe was included by executable name.
- Additional include rules covered executables launched from user directories.
- NetworkConnect also had exclusion filters.

The missing records were not fully explained, including after testing a curl.exe copy from the user's Temp directory.

No changes were made to the Sysmon configuration during this investigation.

### Key Lesson

**No Event does not mean no network connection occurred.**

**No Alert does not necessarily mean the detection correctly rejected an event.**

Endpoint collection coverage must be verified independently from SIEM alerting behavior.

## False Positives and Limitations

The current detection is a controlled lab proof of concept and has important limitations:

- Port 8088 is not inherently suspicious.
- Legitimate administrators may use PowerShell to make HTTP requests.
- The detection does not identify malicious payloads or C2 activity.
- It depends on Sysmon Event ID 3 collection and Wazuh ingestion.
- It does not inspect HTTP content.
- It does not evaluate destination reputation or whether the connection is expected for the host.
- Process-based negative testing remains inconclusive because matching network events were not confirmed.
- The static destination-port condition is unsuitable as a standalone general-purpose production detection.

Future improvements could combine process ancestry, PowerShell script logging, unusual external destinations, destination reputation, and historical network baselines.

## SOC Investigation Workflow

When Rule 100160 triggers, the analyst should review the responsible process, user, destination IP, destination port, protocol, and ProcessGuid.

The analyst should correlate the network event with Sysmon Event ID 1 to identify the process command line and parent process.

If additional PowerShell logging is available, the analyst should inspect script execution activity to understand the commands executed inside the session.

The destination should be compared against approved services and normal endpoint behavior before escalating the alert.

## Cleanup

After testing:

- Temporary curl and VBScript test files were removed from SOC-WINDOWS.
- Windows file-removal verification returned `Not found` for both files.
- The lab HTTP servers should be stopped after testing.

Previously recorded Sysmon and Wazuh events were preserved for documentation.

## Lessons Learned

- Analyzed Sysmon Event ID 3 network telemetry.
- Correlated Event ID 1 and Event ID 3 through ProcessGuid.
- Investigated Wazuh built-in network detection rules.
- Created a custom rule using rule inheritance.
- Validated PowerShell network detection on TCP port 8088.
- Verified a port-negative scenario on TCP port 8080.
- Investigated missing telemetry for alternative processes.
- Distinguished collection failures from detection failures.
- Documented the limitations of a port-based network detection.

## Final Result

**D007 successfully detected the tested PowerShell TCP connection to port 8088 and did not alert on the tested PowerShell connection to port 8080.**

Process-based negative testing remains inconclusive due to missing Sysmon telemetry.

**Detection Status: LAB VALIDATED — WITH DOCUMENTED COVERAGE LIMITATIONS**
