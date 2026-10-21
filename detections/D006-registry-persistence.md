# D006 — Suspicious Registry Run Key Persistence

## Overview

Detect potentially suspicious Windows Registry auto-start entries configured to execute PowerShell with encoded commands.

This detection monitors Sysmon Event ID 13 and extends an existing Wazuh registry detection rule to identify possible persistence mechanisms.

## Detection Details

| Field | Value |
|---|---|
| Detection ID | D006 |
| Detection Name | Registry Auto-Start Entry with Encoded PowerShell |
| Custom Rule ID | 100150 |
| Parent Rule | 92300 |
| Data Source | Sysmon Event ID 13 |
| Detection Type | Registry Persistence |
| Severity | Level 10 |
| MITRE ATT&CK | T1547.001 — Registry Run Keys / Startup Folder |
| Related Technique | T1059.001 — PowerShell |
| Status | Validated |

## Detection Logic

The detection identifies Registry auto-start entries containing PowerShell execution with an encoded command argument.

The rule requires:

- A Sysmon Event ID 13 registry value modification.
- A registry location matched by Wazuh Rule `92300`.
- Registry value data containing `powershell.exe` followed by `-EncodedCommand` or `-enc`.

### Custom Wazuh Rule

```xml
<group name="local,sysmon,registry_persistence,">

  <rule id="100150" level="10">

    <if_sid>92300</if_sid>

    <field name="win.eventdata.details" type="pcre2">(?i)powershell\.exe.*-(?:EncodedCommand|enc)\b</field>

    <description>D006 - Registry Auto-Start Entry with Encoded PowerShell</description>

    <mitre>
      <id>T1547.001</id>
      <id>T1059.001</id>
    </mitre>

    <group>suspicious_registry_persistence,</group>

  </rule>

</group>
```

**Rule Location:** `/var/ossec/etc/rules/local_rules.xml`

## Built-in Rule Investigation

Before developing D006, existing Wazuh rules were investigated.

| Rule ID | Description | Level |
|---|---|---|
| 61615 | Sysmon Registry Value Set — Event ID 13 | 0 |
| 92300 | Registry auto-start location detection | 0 |
| 92301 | Suspicious file extension in registry auto-start entry | 12 |

Rule `92300` provides the parent detection logic for the custom rule.

Because the base rules operate at Level 0, not every matching registry event generates a standalone alert in the Wazuh alerts index.

D006 specializes the detection by inspecting the Registry value data for encoded PowerShell execution.

## Event Analysis

The baseline test created a value under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Sysmon represented the same user registry hive using `HKU` and the user's SID.

Relevant fields included:

| Field | Description |
|---|---|
| Event ID | 13 |
| EventType | SetValue |
| Image | Process that modified the Registry |
| TargetObject | Registry value path |
| Details | Data written to the Registry |
| User | Account associated with the modification |

During investigation, an additional event involving `RunNotification` was observed.

This reinforced the importance of examining the full `TargetObject` rather than searching for the word `Run` alone.

## Testing and Validation

### Positive Test — Encoded PowerShell Run Key

**Registry Value:** `SOC-LAB-D006-Encoded-Positive`

A test value was added to the current user's Run key, referencing PowerShell with an encoded command.

The encoded payload contained a harmless `Write-Output` statement.

**Expected Result:** Rule `100150` generates a Level 10 alert.

**Observed Result:** Wazuh generated one alert under Rule `100150`.

**Result: PASS**

![D006 Positive Test](/screenshots/17-d006-positive-test.png)

*Figure 1 — Wazuh detected an auto-start Registry entry containing encoded PowerShell.*

### Negative Test 1 — Normal CMD Run Key

**Registry Value:** `SOC-LAB-D006-Negative-CMD`

**Value Data:**

```text
C:\Windows\System32\cmd.exe /c exit 0
```

**Expected Result:** No Rule `100150` alert.

**Observed Result:** Sysmon recorded the registry modification, but D006 did not trigger.

**Result: PASS**

### Negative Test 2 — PowerShell Without Encoding

**Registry Value:** `SOC-LAB-D006-Negative-PS`

The test entry referenced PowerShell with a standard `-Command` argument and no encoded command.

**Expected Result:** No Rule `100150` alert.

**Observed Result:** Sysmon recorded the registry modification, but D006 did not trigger.

**Result: PASS**

![D006 Negative Sysmon Events](/screenshots/18-d006-negative-sysmon.png)

*Figure 2 — Sysmon recorded both negative-test registry modifications.*

![D006 Negative Wazuh Result](/screenshots/19-d006-negative-wazuh.png)

*Figure 3 — No D006 alerts appeared during the negative-test window.*

## False Positives and Limitations

Encoded PowerShell is not inherently malicious. Legitimate administration tools may configure auto-start entries using encoded commands.

The detection also has limitations:

- It depends on the registry paths covered by Wazuh Rule `92300`.
- It relies on text matching within the Registry value data.
- It may miss PowerShell aliases, alternative executable names, or argument variations.
- It does not cover every Windows persistence technique.
- It does not prove that an auto-start entry was actually executed.

Additional context is necessary before confirming malicious persistence.

## SOC Investigation Workflow

When Rule `100150` triggers, the analyst should review the modified Registry path, value data, modifying process, associated user, and process execution history.

The analyst should also examine the encoded command, determine whether the entry is authorized, and investigate related process creation or network events.

## Cleanup

All four lab Registry values were removed after testing:

- `SOC-LAB-D006-Baseline`
- `SOC-LAB-D006-Encoded-Positive`
- `SOC-LAB-D006-Negative-CMD`
- `SOC-LAB-D006-Negative-PS`

The test entries were removed to prevent unintended execution during future user logons.

![D006 Registry Cleanup](/screenshots/20-d006-registry-cleanup.png)

*Figure 4 — PowerShell confirmed removal of the four test values.*

## Lessons Learned

- Analyzed Windows Registry persistence using Sysmon Event ID 13.
- Distinguished actual Run Key modifications from RunNotification events.
- Investigated Wazuh Rules 61615, 92300, and 92301.
- Extended an existing detection through rule inheritance.
- Implemented detection logic using Registry value data.
- Validated the detection with positive and negative tests.
- Identified false positives and detection limitations.
- Removed temporary registry entries after testing.

## Final Result

**D006 successfully detected a Windows Registry auto-start entry configured to execute encoded PowerShell, while avoiding alerts on the tested normal CMD and non-encoded PowerShell entries.**

**Detection Status: VALIDATED**
