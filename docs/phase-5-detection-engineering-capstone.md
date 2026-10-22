# Detection Engineering Capstone

## Objective

Validate detection logic, investigate correlated security events, and determine whether observed activity represents a security incident.

## Lab Environment

| Host | Role | IP |
|---|---|---|
| SOC-WAZUH | Wazuh Manager | 192.168.245.10 |
| SOC-WINDOWS | Windows Endpoint | 192.168.245.20 |
| Kali Linux | Controlled HTTP Server | 192.168.245.30 |

## 1. Positive and Negative Testing

We validated custom rule `100110` (D002), which detects PowerShell execution using `-EncodedCommand`.

| Test | Behavior | Result |
|---|---|---|
| Positive | Encoded PowerShell launched from Explorer | PASS — Rule 100110 |
| Negative | PowerShell launched with ordinary `-Command` | PASS — Rule 100110 did not trigger |

We also observed detection overlap: built-in Wazuh rule `92057` detected an encoded PowerShell process spawned by another PowerShell process.

**Lesson learned:** A custom rule must be evaluated against both matching and non-matching activity. Different rules can cover overlapping but non-identical behaviors.

## 2. Event Correlation

A controlled encoded PowerShell script requested a webpage from Kali on TCP port 8088 and received HTTP 200.

The events shared the following Sysmon ProcessGuid:

`{3f977765-44f7-6ada-7d02-000000001a00}`

| Time (UTC) | Sysmon Event ID | Wazuh Rule | Finding |
|---|---|---|---|
| 17:16:42.933 | 1 | 92057 | Encoded PowerShell execution |
| 17:16:42.934 | 11 | 92213 | Temporary file creation |
| 17:16:44.560 | 3 | 100160 | TCP connection to 192.168.245.30:8088 |

The matching ProcessGuid established that the process creation, file creation, and network connection events belonged to the same PowerShell process.

**Lesson learned:** Event correlation requires a reliable shared identifier, not just similar timestamps or process names.

## 3. Alert Triage

The file creation alert referenced a temporary script:

`C:\Users\socuser\AppData\Local\Temp\__PSScriptPolicyTest_*.ps1`

This filename is consistent with PowerShell execution-policy testing.

The event did not establish that malware was downloaded or executed.

**Lesson learned:** An alert can accurately detect an event without establishing malicious intent.

## 4. Encoded Command Analysis

The PowerShell command was extracted from a Wazuh alert and decoded from Base64 as UTF-16LE text.

The decoded script:

- Printed the process ID.
- Sent an HTTP request to the controlled Kali server.
- Printed the HTTP response status.
- Slept for 60 seconds.

No payload execution, persistence operation, or file download command was identified in the decoded script.

**Lesson learned:** Inspect encoded command content safely before drawing conclusions about its behavior.

## 5. Final Verdict

**Disposition:** Benign True Positive — Authorized Lab Activity.

The detection signals matched real activity, but the observed behavior was intentionally generated during an authorized test.

The investigation established the event sequence and destination without identifying evidence of malicious compromise.

## Limitations

- Rule `100110` was validated independently, but rule `92057` was the final execution alert in the correlated Capstone scenario.
- Correlation was performed manually using `ProcessGuid`; no automated multi-event correlation rule was implemented.
- Rule `100160` monitors a lab-specific TCP port. Port 8088 is not inherently malicious.
- The findings apply to the observed test activity, not the overall security state of the endpoint.

## Conclusion

This exercise demonstrated the complete detection engineering workflow:

**Detection → Validation → Correlation → Investigation → Triage → Verdict**

The main outcome was learning to distinguish detection accuracy from malicious intent and to reconstruct activity using evidence rather than assumptions.
