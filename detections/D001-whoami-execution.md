# D001 — Whoami Execution Detection

## Objective

Detect execution of the Windows `whoami.exe` utility, which can be used for System Owner/User Discovery.

## Data Source

- Sysmon
- Event ID 1 — Process Creation

## MITRE ATT&CK

- T1033 — System Owner/User Discovery

## Detection Logic

The detection identifies Sysmon Process Creation events where the executable's original filename is `whoami.exe`.

```text
Sysmon Event ID 1
AND
OriginalFileName = whoami.exe
```

`OriginalFileName` was selected instead of relying only on the current executable path because it can still identify the original binary after simple file renaming.

## Wazuh Rule

```xml
<rule id="100100" level="5">
  <if_group>sysmon_event1</if_group>

  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^whoami\.exe$</field>

  <description>Whoami execution detected - possible System Owner/User Discovery</description>

  <mitre>
    <id>T1033</id>
  </mitre>
</rule>
```

## Positive Test

Command executed:

```powershell
whoami
```

Expected result:

```text
Rule 100100 triggers.
```

Observed result:

```text
Rule 100100 triggered successfully.
```

## Negative Tests

The following commands were executed:

```powershell
hostname
ipconfig
```

Expected result:

```text
Rule 100100 should not trigger.
```

Observed result:

```text
No additional Rule 100100 alerts were generated.
```

## Renamed Binary Validation

A copy of `whoami.exe` was created with a different filename:

```powershell
Copy-Item "C:\Windows\System32\whoami.exe" "C:\Tools\identity-check.exe"
```

The renamed executable was then executed:

```powershell
C:\Tools\identity-check.exe
```

Sysmon recorded:

```text
Image:
C:\Tools\identity-check.exe

OriginalFileName:
whoami.exe
```

Rule `100100` still triggered successfully because the detection uses `OriginalFileName` rather than relying only on the executable path.

![Whoami Renamed Binary Detection](/screenshots/05-d001-whoami-renamed-detection.png)

## Investigation Context

Useful fields for investigation include:

```text
Image
CommandLine
ParentImage
User
IntegrityLevel
ProcessId
ParentProcessId
ProcessGuid
Hashes
```

## False Positives

`whoami.exe` is a legitimate Windows utility and may be executed by:

- System administrators
- IT support personnel
- Troubleshooting scripts
- Security tools
- Authorized penetration testers

Therefore, execution of `whoami.exe` alone should not be treated as proof of malicious activity.

## Analyst Interpretation

The detection confirms that System Owner/User Discovery behavior occurred.

Additional context such as the parent process, user, surrounding commands, endpoint role, and related alerts should be reviewed before determining whether the activity is malicious.

## Validation Summary

| Test | Expected | Result |
|---|---|---|
| `whoami` | Trigger | Passed |
| `hostname` | No trigger | Passed |
| `ipconfig` | No trigger | Passed |
| Renamed `whoami.exe` | Trigger | Passed |

## Lessons Learned

- An event and an alert are not the same thing.
- Sysmon Event ID 1 provides rich process execution telemetry.
- Detection conditions should be selected separately from investigation context.
- `OriginalFileName` can provide better resilience against simple binary renaming than relying only on `Image`.
- Positive and negative tests are both required to validate detection logic.
- A successful detection does not automatically mean malicious activity occurred.