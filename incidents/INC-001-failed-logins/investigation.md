# INC-001 — Multiple Failed Logins Investigation

## Incident Overview

| Field | Details |
|---|---|
| Case ID | INC-001 |
| Date | October 24, 2026 |
| Affected Host | SOC-WINDOWS (192.168.245.20) |
| Source Host | Kali Linux (192.168.245.30) |
| Target Account | inc001_test |
| Data Source | Windows Security Event ID 4625 |
| Wazuh Detection | Custom Rule 100120 |
| MITRE ATT&CK | T1110.001 — Password Guessing |
| Severity | Low — Authorized Lab |
| Verdict | Benign True Positive |

## 1. Scenario

Five controlled SMB authentication attempts were performed from Kali Linux against a temporary local Windows account using an incorrect password.

The objective was to investigate repeated authentication failures, identify their source, validate Wazuh correlation, and determine whether any successful authentication occurred.

## 2. Evidence Collection

Windows Security Logs recorded five failed authentication events.

| Field | Observed Value |
|---|---|
| Event ID | 4625 |
| TargetUserName | inc001_test |
| TargetDomainName | SOC-WINDOWS |
| IpAddress | 192.168.245.30 |
| WorkstationName | KALI |
| LogonType | 3 — Network |
| Authentication Package | NTLM |
| Status | 0xC000006D |
| SubStatus | 0xC000006A — Wrong Password |

## 3. Investigation Timeline

Times below are displayed in the Wazuh Dashboard timezone.

| Time | Event |
|---|---|
| 16:36:48 | First failed authentication |
| 16:36:53 | Second failed authentication |
| 16:36:57 | Third failed authentication |
| 16:37:02 | Fourth failed authentication |
| 16:37:55 | Fifth failed authentication and correlation alert |

**Observed duration:** Approximately 67 seconds.

## 4. Detection Analysis

Custom Wazuh Rule `100120` detected multiple authentication failures against the same account.

Detection configuration:

- Frequency: 5 matching events
- Timeframe: 120 seconds
- Parent rule: 60122
- Correlation field: `win.eventdata.targetUserName`
- Alert level: 10

**Result: PASS**

The rule successfully identified the repeated failed-logon pattern.

The rule correlates by target username, not by source IP. Source attribution was therefore validated separately using the individual events.

## 5. Successful Logon Investigation

Windows Security events `4624` and `4625` were reviewed for the test account and Kali source IP.

| Event Type | Count |
|---|---|
| Failed logons — 4625 | 5 |
| Successful logons — 4624 | 0 |

No successful authentication was observed for this account and source IP within the examined three-hour window.

This does not establish that no successful logon occurred outside the investigated scope.

## 6. Incident Assessment

The observed behavior matched a potential password-guessing pattern.

However, the authentication attempts were intentionally generated in an authorized, isolated SOC lab.

**Classification:** Benign True Positive

**Severity:** Low

**Containment:** Not required

**Compromise:** No evidence of successful unauthorized access identified within the investigated scope.

## 7. Response and Cleanup

After preserving the investigation evidence:

- Removed the temporary `inc001_test` account.
- Removed the temporary inbound SMB firewall rule `SOC-LAB-INC001-SMB-KALI`.
- Verified that both objects were no longer returned by the corresponding Windows queries.
- Preserved Windows Security and Wazuh alert records.

## 8. Evidence Screenshots

![Five failed authentication events](/screenshots/25-inc001-five-failed-logons.png)

*Figure 1 — Five Windows Security Event ID 4625 records targeting the same account.*

![Wazuh correlation detection](/screenshots/26-inc001-wazuh-correlation.png)

*Figure 2 — Custom Wazuh Rule 100120 detected the repeated authentication failures.*

![Authentication investigation result](/screenshots/27-inc001-logon-investigation.png)

*Figure 3 — Windows investigation confirmed five failed and zero matching successful logons within the selected window.*

## 9. Lessons Learned

- A single failed logon does not establish an authentication attack.
- Repeated failures should be investigated by user, source IP, timing, and authentication type.
- SIEM correlation rules can identify patterns that individual events cannot.
- A detection alert does not prove successful compromise.
- Incident severity and response decisions must account for context and evidence.

## Conclusion

INC-001 demonstrated a complete SOC investigation workflow: controlled simulation, telemetry analysis, alert validation, event correlation, successful-logon checking, incident assessment, and cleanup.

The activity was classified as an authorized lab test rather than a confirmed security compromise.
