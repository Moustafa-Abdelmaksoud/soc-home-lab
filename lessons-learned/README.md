# Lessons Learned — SOC Home Lab

This document reflects on the **entire SOC Home Lab project**: infrastructure deployment, Windows/Sysmon telemetry, eight detection-engineering exercises (D001–D008), six incident investigations (INC-001–INC-006), two Wazuh monitoring dashboards, response verification, and portfolio documentation.

The goal is to explain **what was learned, what did not work as expected, and how the evidence changed the investigation or detection approach**. This is a retrospective on completed, authorized lab work—not a claim of production SOC coverage or a separate threat-hunting phase.

## 1. Architecture and Lab Operations

### Isolation and repeatability are part of security engineering

The environment used VirtualBox with a dedicated **Host-Only network (192.168.245.0/24)** for Wazuh, Windows 11, and Kali Linux. The Wazuh server used a separate NAT interface for updates when required.

**What I learned:**
- Stable lab IP addresses and known system roles make event correlation and test reproduction easier.
- Separating authorized attack traffic from the physical home network is a prerequisite, not an optional clean-up step.
- A working dashboard alone does not prove a working SOC: the Windows agent, event sources, and indexer must be verified end to end.

**Evidence:** [Lab Architecture](/architecture/lab-overview.md) · [Initial agent and Sysmon validation](/README.md#telemetry-and-validation)

### Test infrastructure changes can affect security results

Detection experiments involved Windows audit settings, Wazuh event collection, Sysmon configuration checks, RDP exposure, firewall rules, services, registry entries, and temporary shares. These changes were part of the test conditions and had to be accounted for during analysis and recovery.

**Lesson:** Record the configuration under test, use isolated test accounts and artifacts, and return the lab to a known state instead of assuming that deleting a payload is sufficient.

## 2. Telemetry Collection and Visibility

### Activity, an endpoint event, an indexed event, and an alert are different things

A process or network connection may occur without producing the expected Sysmon event. A Windows event may exist locally but never reach Wazuh. An ingested event may be present in archives without generating a searchable alert.

This distinction became critical in two exercises:

| Evidence | What happened | Operational lesson |
|---|---|---|
| [D007 — PowerShell Network Connection](/detections/D007-powershell-network-connection.md) | Alternative executables made successful HTTP requests, but corresponding Sysmon Event ID 3 records were not confirmed. The process-negative test was **inconclusive**, not passed. | **No alert** cannot validate a negative test until the underlying event path is confirmed. |
| [INC-004 — SMB File Access](/incidents/INC-004-smb-file-access/investigation.md) | Windows produced detailed file-share events, but Event ID **5145** was initially excluded by the Wazuh agent query. After correcting collection, events were verified in archives before a custom alert was developed. | Diagnose **collection gaps separately from detection gaps**. |

Windows Security events provided authentication and account activity; Sysmon supported process creation, ancestry, registry, file, and selected network observations; Wazuh supplied rule matching and correlation. Each source answered different questions.

**Lesson:** Troubleshoot in order: *activity → local event → collection → indexing/archive → rule match → alert*. Never assume the last stage proves all the earlier stages worked.

### Missing and suppressed events need context

Some base rules operate at Level 0 and do not normally appear as standalone alerts in `wazuh-alerts-*`. D008 intentionally suppressed individual document-read alerts while retaining the matches needed for correlation.

**Lesson:** An empty alerts search may reflect filtering, rule level, suppression, retention, or time-window choices—not necessarily an absence of activity.

## 3. Detection Engineering — D001 to D008

### A detection should target behavior, not just a tool name

The eight exercises demonstrated different design approaches:

| Exercise | Key lesson demonstrated |
|---|---|
| [D001 — Whoami Execution](/detections/D001-whoami-execution.md) | Process identity and context matter: a renamed `whoami.exe` was detected, while tested unrelated discovery commands did not trigger the custom rule. |
| [D002 — Encoded PowerShell](/detections/D002-encoded-powershell.md) | Match the suspicious command-line behavior (`-EncodedCommand` and `-enc`) rather than every PowerShell execution. A normal PowerShell command did not trigger the custom rule. |
| [D003 — Repeated Failed Logons](/detections/D003-repeated-failed-logons.md) | Correlation depends on **frequency, timeframe, and grouping key**. Five failures for one user within 120 seconds triggered the tested rule; failures split between users did not. |
| [D004 — Scripting Host → PowerShell](/detections/D004-scripting-host-powershell.md) | Parent-child process relationships can provide more specific context than either process name alone. Positive and negative process-tree tests were both needed. |
| [D005 — Suspicious Scheduled Task](/detections/D005-suspicious-scheduled-task.md) | A task configured to use encoded PowerShell warrants different treatment from an ordinary task. **Task creation does not prove execution or persistence**. |
| [D006 — Registry Run Key Persistence](/detections/D006-registry-persistence.md) | Registry changes can be narrowed by the auto-start location and command content. Sysmon can record a benign or excluded modification without the custom alert firing. |
| [D007 — PowerShell Network Connection](/detections/D007-powershell-network-connection.md) | Sysmon Event IDs **1 and 3**, joined using `ProcessGuid`, can relate a process to a connection. One negative test remained inconclusive because source telemetry was missing. |
| [D008 — SMB Bulk Document Access](/detections/D008-smb-bulk-document-access.md) | A **base rule (100170)** and a **correlation rule (100171)** can detect a burst of distinct document-read requests without alerting on every access check. |

### Positive testing is necessary but not sufficient

A positive alert shows that a rule can match **one tested scenario**. It does not establish its false-positive rate, exhaustive coverage, or behavior in every environment.

Negative tests helped define intentional exclusions:
- D002 excluded the tested ordinary PowerShell command.
- D003 did not correlate failed logons spread across different usernames.
- D004 distinguished scripting-host children from tested unrelated process chains.
- D005 and D006 excluded tested non-encoded commands.
- D008 did not produce a bulk alert during the controlled two-file test, but did during the ten-file test.

**Lesson:** Label outcomes precisely as **passed, failed, or inconclusive**. A test with missing underlying telemetry cannot be counted as a successful negative detection test.

### Rule specificity is a tradeoff

Tight conditions reduce noise but may miss alternative execution paths, slower activity, different filenames, or other process names. Broad rules increase visibility but require more analyst triage.

**Lesson:** Document detection logic, event prerequisites, grouping fields, thresholds, intended exclusions, and blind spots with the rule—not just its XML and the resulting screenshot.

## 4. Incident Investigation — INC-001 to INC-006

Investigations required moving from an alert to a defensible conclusion through evidence collection, timeline reconstruction, user/process context, and a response decision.

| Incident | Most important investigative learning |
|---|---|
| [INC-001 — Multiple Failed Logins](/incidents/INC-001-failed-logins/investigation.md) | Five failed logons produced a correlation alert, but the inspected window showed **no matching successful logon**. Repeated failures do not automatically mean account compromise. |
| [INC-002 — Suspicious PowerShell](/incidents/INC-002-powershell/investigation.md) | `ProcessGuid`/`ParentProcessGuid`, file evidence, and network context reconstructed a multi-process sequence. A timestamp discrepancy had to be documented rather than silently corrected. |
| [INC-003 — Unauthorized Admin Account](/incidents/INC-003-admin-account/investigation.md) | Creating an account and adding it to Administrators are distinct events. The account represented privilege risk even though matching account usage was not observed in the inspected authentication window. |
| [INC-004 — Suspicious SMB File Access](/incidents/INC-004-smb-file-access/investigation.md) | Local Windows logs, SMB traffic, Wazuh archives, and custom rule results exposed and helped close a **telemetry/detection visibility gap**. |
| [INC-005 — Windows Service Persistence](/incidents/INC-005-service-persistence/investigation.md) | Event **7045** established service installation, not successful persistence. Automatic startup initially timed out (System **7009/7000**); delayed automatic start was subsequently validated after reboot. |
| [INC-006 — Multi-Stage Intrusion](/incidents/INC-006-multi-stage-intrusion/investigation.md) | Linking RDP, service-binary modification, SYSTEM-context process lineage, account and group changes, registry-hive copies, and SMB activity was stronger than treating each alert in isolation. |

### Three practices made the investigations more reliable

1. **Correlate independent evidence.** Match Windows Security events, Sysmon process identifiers, Wazuh rules, and application/network artifacts before asserting causality.
2. **Preserve the time basis.** Local Windows timestamps and UTC-based records may be displayed differently. Keep original timestamps and explain inconsistencies instead of forcing a timeline to fit.
3. **Separate suspicious behavior from confirmed impact.** These were controlled lab simulations. A matched detection is not automatically evidence of malicious intent, unauthorized access, or completed exfiltration.

### State exactly what the evidence proves

For [INC-006](/incidents/INC-006-multi-stage-intrusion/investigation.md), the evidence supported **SYSTEM-context command execution**, an elevated administrator session, acquisition of SAM/SECURITY/SYSTEM hive copies, and observed SMB downloads in the lab.

It did **not** demonstrate an interactive SYSTEM shell, extracted password hashes, or cracked credentials. Likewise, Windows Event **5145** records a file-share access check; it is not standalone proof of complete file transfer.

**Lesson:** Accurate limitations make a report more credible, not less.

## 5. Incident Response, Recovery, and Evidence Handling

### Containment and eradication are different stages

Disabling access reduces immediate exposure; deleting test services, accounts, shares, scheduled tasks, registry values, and temporary files addresses the specific simulated changes. The response should also restore temporary changes to firewall, RDP, and monitoring settings as appropriate.

In [INC-005](/incidents/INC-005-service-persistence/investigation.md), service removal was checked through stopped/disabled state, deletion results, registry-key absence, and process checks. In [INC-006](/incidents/INC-006-multi-stage-intrusion/investigation.md), **seven final recovery checks** verified the inspected accounts, service, share, RDP state, Wazuh state, and lab directory.

**Lesson:** A command returning success is weaker than a separate post-action verification. Recovery checks demonstrate the state of **what was inspected**, not absolute forensic eradication from every snapshot or backup.

### Keep investigation evidence separate from sensitive artifacts

Screenshots, alert records, timelines, and relevant hashes or metadata support a reproducible investigation. Registry-hive exports, passwords, and sensitive payload content should not be published as portfolio evidence.

**Lesson:** Documentation quality includes knowing **what not to commit** to GitHub.

## 6. SOC Monitoring and Dashboard Design

Two saved dashboards were created from the `wazuh-alerts-*` data view:

- [SOC Security Overview](/dashboards/README.md#1-soc-security-overview): alert totals, high-severity counts, alert volume over time, rule frequency, severity distribution, and ATT&CK tactics.
- [Authentication & Endpoint Activity](/dashboards/README.md#2-authentication--endpoint-activity): failed logons, RDP rule alerts, account/group changes, suspicious PowerShell detections, new services, and SMB bulk-access alerts.

![SOC Security Overview](/screenshots/58-soc-security-overview.png)

*Figure 58. Saved SOC Security Overview dashboard, combining high-level KPIs and alert-distribution panels.*

![Authentication and Endpoint Activity](/screenshots/59-soc-authentication-endpoint-activity.png)

*Figure 59. Saved Authentication & Endpoint Activity dashboard with six focused KPIs and a PowerShell alert timeline.*

### A useful KPI requires a precise definition

- `rule.level >= 12` counts high-severity **alerts**, not confirmed incidents.
- Event **4625** counts indexed Windows failed logons, not exclusively RDP attempts.
- Rule **100120** counts correlation alerts, not the number of password guesses.
- Events **4720** and **4732** count account-creation and local-group-addition events; they do not by themselves establish malicious account usage or Administrators-only membership.
- Event **7045** counts service-installation events, not successful boot persistence.
- Rule **100171** counts bulk-access detections, not the number of SMB files transferred.
- MITRE tactics can be assigned to more than one alert category and do not prove that every underlying event was an attack.

The [dashboard documentation](/dashboards/README.md) records the DQL filters and captured numbers. Those numbers were **time-dependent snapshots**, not fixed project results.

**Lesson:** Save the correct filters with each visualization, use meaningful titles, group related KPIs, and state the time range and source index. A dashboard is useful only when the displayed number means what its label says.

## 7. The End-to-End Workflow I Can Now Demonstrate

```text
Design an isolated environment
             |
             v
Configure Windows auditing, Sysmon, and the Wazuh agent
             |
             v
Verify telemetry from the endpoint to Wazuh
             |
             v
Design a behavioral rule and test positive/negative cases
             |
             v
Investigate alerts with timeline and process/user context
             |
             v
Assess impact and evidence limitations
             |
             v
Contain, clean up, and verify recovery
             |
             v
Monitor patterns using saved SOC dashboards
             |
             v
Document findings, ATT&CK mappings, and lessons
```

This end-to-end workflow is the project's central outcome: progressing from **building the SIEM environment** to **explaining and validating security findings**.

## 8. Opportunities for Future Improvement

These are **future possibilities, not completed features**:

- Re-test ambiguous visibility conditions, especially D007's missing Sysmon Event ID 3 records for alternative executables.
- Make telemetry and visualization configuration exports easier to reproduce after redeployment.
- Define a repeatable schedule for regression testing when Sysmon filters, Wazuh rules, or Windows audit policies change.
- Evaluate multi-endpoint monitoring, alert retention, and dashboard behavior with larger datasets.
- Introduce measurement of alert triage effort or false-positive rates if the lab is expanded.

---

## Final Reflection

The biggest lesson was that **generating an alert is only the beginning of SOC work**. An analyst needs to understand the source event, test the detection boundary, correlate independent artifacts, recognize missing visibility, qualify conclusions, and verify remediation.

The completed SOC Home Lab demonstrates those practices across infrastructure, detection engineering, investigation, response, dashboards, and documentation.