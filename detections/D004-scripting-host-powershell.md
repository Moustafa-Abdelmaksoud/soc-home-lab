# D004 — Suspicious Parent-Child Process Relationship

## Overview

Detect suspicious process execution where Windows Script Host (`wscript.exe` or `cscript.exe`) launches PowerShell.

This detection extends an existing Wazuh rule to identify a specific parent-child process relationship using Sysmon Event ID 1.

## Detection Details

| Field | Value |
|---|---|
| Detection ID | D004 |
| Custom Rule ID | 100130 |
| Parent Rule | 92000 |
| Data Source | Sysmon Event ID 1 |
| Detection Type | Parent-Child Process Relationship |
| Severity | Level 9 |
| MITRE ATT&CK | T1059.001 — PowerShell |
| Status | Validated |

## Detection Logic

The built-in Wazuh rule `92000` identifies process creation events originating from Windows Script Host.

The custom rule extends this detection by verifying that the child process has the original filename `PowerShell.EXE`.

### Custom Wazuh Rule

```xml
<group name="local,sysmon,parent_child_detection,">

  <rule id="100130" level="9">

    <if_sid>92000</if_sid>

    <field name="win.eventdata.originalFileName" type="pcre2">(?i)^powershell\.exe$</field>

    <description>D004 - Suspicious Parent-Child Relationship: Scripting Host spawning PowerShell</description>

    <mitre>
      <id>T1059.001</id>
    </mitre>

    <group>suspicious_process_creation,</group>

  </rule>

</group>
```

**Rule Location:** `/var/ossec/etc/rules/local_rules.xml`

### Why Use Rule Inheritance?

Instead of duplicating the existing parent process conditions, D004 uses:

```xml
<if_sid>92000</if_sid>
```

This allows the detection to cover both `wscript.exe` and `cscript.exe` while adding only the required child-process condition.

## Testing and Validation

### Positive Tests — Passed

A harmless VBScript was executed using both Windows Script Host interpreters.

| Parent Process | Child Process | Result |
|---|---|---|
| wscript.exe | powershell.exe | PASS |
| cscript.exe | powershell.exe | PASS |

**Observed:** Wazuh generated two alerts under Rule `100130`, confirming that both parent processes are covered.

![D004 Positive Tests](screenshots/10-d004-positive-tests.png)

*Figure 1 — D004 successfully detected PowerShell launched by WScript and CScript.*

### Negative Test 1 — WScript Spawning Notepad

A VBScript launched Notepad instead of PowerShell.

**Expected:** Built-in Rule `92000` may trigger, but D004 must not trigger.

**Observed:** Rule `92000` generated a Level 4 alert. No Rule `100130` alert was generated in the test window.

**Result: PASS**

![D004 Built-in Rule Negative Test](screenshots/11-d004-wscript-notepad.png)

*Figure 2 — WScript launching Notepad triggered only the general scripting interpreter detection.*

### Negative Test 2 — CMD Spawning PowerShell

PowerShell was launched directly from Command Prompt using a harmless test command.

**Expected:** No Rule `100130` alert.

**Observed:** Sysmon recorded the `cmd.exe → powershell.exe` relationship, and no Rule `100130` alert appeared in the tested Wazuh time window.

**Result: PASS**

![D004 CMD Negative Test](screenshots/12-d004-cmd-powershell.png)

*Figure 3 — Sysmon confirmed that CMD launched PowerShell.*

![D004 No Custom Alerts](screenshots/13-d004-negative-no-alerts.png)

*Figure 4 — No D004 alerts during negative testing.*

## False Positives and Limitations

Legitimate administrative scripts may use Windows Script Host to launch PowerShell, potentially generating false positives.

The detection only covers parent processes matched by Wazuh Rule `92000`. It does not identify every possible method of launching PowerShell.

The rule also depends on the child's `OriginalFileName` metadata and the continued behavior of its parent rule.

A matching alert indicates suspicious behavior requiring investigation, not confirmed malicious activity.

## Lessons Learned

- Analyzed parent-child relationships using Sysmon Event ID 1.
- Investigated an existing Wazuh rule before creating a custom detection.
- Implemented rule inheritance using `if_sid`.
- Improved detection coverage by removing a redundant parent process condition.
- Validated the detection with two positive and two negative test cases.
- Distinguished suspicious execution patterns from confirmed attacks.

## Final Result

**D004 successfully detects PowerShell launched by WScript or CScript without alerting on the tested unrelated parent-child process relationships.**

**Detection Status: VALIDATED**
