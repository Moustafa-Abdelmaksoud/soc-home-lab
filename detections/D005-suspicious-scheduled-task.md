# D005 — Suspicious Scheduled Task Creation

## Overview

Detect the creation of Windows Scheduled Tasks configured to execute PowerShell with encoded commands.

This detection identifies potentially suspicious persistence configurations at task creation time, before the scheduled action is executed.

## Detection Details

| Field | Value |
|---|---|
| Detection ID | D005 |
| Detection Name | Suspicious Scheduled Task Creation |
| Custom Rule ID | 100140 |
| Parent Rule | 60228 |
| Data Source | Windows Security Event Logs |
| Event ID | 4698 |
| Severity | Level 10 |
| Detection Type | Persistence / Behavioral Detection |
| MITRE ATT&CK | T1053.005 — Scheduled Task |
| Related Technique | T1059.001 — PowerShell |
| Status | Validated |

## Detection Logic

The detection triggers when a newly created Scheduled Task contains both a PowerShell executable reference and an encoded command argument.

**Detection conditions:**

- Windows Security Event ID 4698
- Built-in Wazuh Rule 60228
- Task content contains `powershell.exe`
- Task content contains `-EncodedCommand` or `-enc`

### Custom Wazuh Rule

```xml
<group name="local,windows,persistence,">

  <rule id="100140" level="10">

    <if_sid>60228</if_sid>

    <field name="win.eventdata.taskContent" type="pcre2">(?is)powershell\.exe.*-(?:EncodedCommand|enc)\b</field>

    <description>D005 - Scheduled Task Created with Encoded PowerShell</description>

    <mitre>
      <id>T1053.005</id>
      <id>T1059.001</id>
    </mitre>

    <group>suspicious_scheduled_task,</group>

  </rule>

</group>
```

**Rule Location:** `/var/ossec/etc/rules/local_rules.xml`

## Built-in Rule Investigation

Wazuh Rule `60228` detects the creation of Windows Scheduled Tasks using Security Event ID `4698`.

The existing rule provides general task creation visibility at Level 4.

D005 extends this detection through `<if_sid>60228</if_sid>` and applies additional conditions to identify tasks configured to execute encoded PowerShell commands.

This reduces alerts from ordinary task creation while highlighting a specific execution pattern that warrants investigation.

## Testing and Validation

### Positive Test — Encoded PowerShell Task

**Task Name:** `SOC-LAB-D005-Encoded-Positive`

A Scheduled Task was registered with an action configured to execute PowerShell using `-EncodedCommand`.

The encoded payload performed a harmless `Write-Output` operation. The task was scheduled for a future date and was not executed during testing.

**Expected:** Rule `100140` generates a Level 10 alert.

**Observed:** Wazuh generated one alert under Rule `100140`.

**Result: PASS**

![D005 Positive Test](/screenshots/14-d005-positive-test.png)

*Figure 1 — Wazuh detected a newly created Scheduled Task containing encoded PowerShell.*

### Negative Test 1 — Normal CMD Task

**Task Name:** `SOC-LAB-D005-Negative-CMD`

A task was registered with the following action:

```cmd
cmd.exe /c exit 0
```

**Expected:** General task creation alert only.

**Observed:** Rule `60228` triggered, while Rule `100140` did not.

**Result: PASS**

### Negative Test 2 — PowerShell Without Encoding

**Task Name:** `SOC-LAB-D005-Negative-PS`

A task was configured to execute:

```powershell
powershell.exe -NoProfile -Command "Get-Date"
```

**Expected:** General task creation alert only.

**Observed:** Rule `60228` triggered, while Rule `100140` did not.

**Result: PASS**

![D005 Negative Events](/screenshots/15-d005-negative-events.png)

*Figure 2 — Both negative-test tasks generated standard Windows Scheduled Task creation alerts.*

![D005 Negative Result](/screenshots/16-d005-negative-result.png)

*Figure 3 — No Rule 100140 alerts during the negative-test window.*

## Event Analysis

| Field | Description |
|---|---|
| `win.system.eventID` | Windows Security Event ID 4698 |
| `win.eventdata.taskName` | Name of the registered Scheduled Task |
| `win.eventdata.taskContent` | Task definition, including execution actions and arguments |
| `win.eventdata.subjectUserName` | Account that created the task, when available |
| `rule.id` | Wazuh detection rule |

The `taskContent` field contained an escaped XML representation of the Scheduled Task definition, including its executable path and arguments.

## False Positives and Limitations

Encoded PowerShell is not inherently malicious. Legitimate administrative tools and automation systems may use it.

The current detection has several limitations:

- It detects task creation through Event ID 4698, but does not directly cover task modification through Event ID 4702.
- It searches for text patterns rather than parsing the Scheduled Task XML structure.
- The executable and encoded-command indicators are matched within the same field, but are not guaranteed to belong to the same task action.
- It may miss alternative PowerShell executable names, command-line variations, or tasks that use other execution methods.
- A matching alert does not prove that the task ran or that malicious persistence was established.

Additional investigation is required to determine whether a detected task is authorized.

## SOC Investigation Workflow

When Rule `100140` triggers, the analyst should review the task name, creator account, executable path, command-line arguments, scheduled triggers, and privilege context.

The analyst should also look for subsequent task execution, PowerShell process creation, related network connections, and other suspicious activity on the endpoint.

## Cleanup

After testing, all five lab tasks were removed:

- `SOC-LAB-D005-Baseline`
- `SOC-LAB-D005-Encoded`
- `SOC-LAB-D005-Encoded-Positive`
- `SOC-LAB-D005-Negative-CMD`
- `SOC-LAB-D005-Negative-PS`

The scheduled tasks were deleted to prevent unintended future execution. Previously generated Wazuh alerts remained available for investigation.

## Lessons Learned

- Configured and verified Windows Scheduled Task auditing.
- Investigated Security Event ID 4698 and Wazuh Rule 60228.
- Built a custom detection using rule inheritance.
- Distinguished persistence configuration from process execution.
- Validated the detection through positive and negative testing.
- Identified false-positive scenarios and detection limitations.
- Removed all temporary Scheduled Tasks after testing.

## Final Result

**D005 successfully detected the creation of a Scheduled Task configured to execute encoded PowerShell while avoiding alerts for the tested normal CMD and non-encoded PowerShell tasks.**

**Detection Status: VALIDATED**
