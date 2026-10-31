# D008 — SMB Bulk Document Access Detection

| Field | Details |
|---|---|
| Detection ID | D008 |
| Wazuh rules | **100170** (base), **100171** (behavioral correlation) |
| Data source | Windows Security Event ID **5145** — Detailed File Share |
| Platform | Windows 11 / Wazuh 4.14.8; agent `001` (`SOC-WINDOWS`) |
| Severity | **Level 8** for correlated activity (`100171`) |
| MITRE ATT&CK | **T1039 — Data from Network Shared Drive** (potential collection) |
| Validation | Positive and negative tests completed in **INC-004**, October 26, 2026 |
| Status | **Validated in isolated SOC lab** |

## Detection Objective

Detect **unusual bursts of SMB document-read requests** associated with one Windows network logon, rather than alerting on every individual file access. The rule is behavioral: it does **not** rely on a specific share, username, source IP address, or test filename.

A Windows **5145** event records an SMB share access check. It can support a file-access investigation, but **does not independently prove that a complete file was downloaded**. The original INC-004 investigation separately used `smbclient` receipts and SMB2 network evidence to validate transfer.

## Rule Logic

| Rule | Role | Logic |
|---|---|---|
| **100170** | Base match; level **1** | Security audit-success parent `60103`; Event ID `5145`; `accessList` includes `%%4416` (ReadData / ListDirectory); target name ends in `.csv`, `.tsv`, `.txt`, `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.zip`, or `.7z`. Uses `no_log` so individual matches do not flood alerts. |
| **100171** | Correlated alert; level **8** | Requires prior `100170` matches; `frequency="8"` within `timeframe="120"` seconds; same `subjectLogonId`; different `relativeTargetName`; suppresses repeated alerts for `120` seconds after firing. |

**Intended detection pattern:** one SMB logon generating many matching read-access checks against differing document filenames in a short period. The source IP and username are useful investigation context in the final alert, **but the rule does not explicitly require the same source IP or username** beyond the same Logon ID and agent-level correlation.

### Installed Wazuh Rule Configuration

The following is the combined rule block recorded in the existing `/var/ossec/etc/rules/local_rules.xml`; these are **not** separate rules files.

```xml
<!-- INC-004: SMB Multiple File Read Detection -->
<group name="local,windows_security,smb_monitoring,">

  <!-- Base: SMB document-read access check -->
  <rule id="100170" level="1">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID" type="pcre2">^5145$</field>
    <field name="win.eventdata.accessList" type="pcre2">(?:^|\s)%%4416(?:\s|$)</field>
    <field name="win.eventdata.relativeTargetName" type="pcre2">(?i)\.(?:csv|tsv|txt|pdf|docx?|xlsx?|pptx?|zip|7z)$</field>
    <description>SMB document read request by $(win.eventdata.subjectUserName)</description>
    <options>no_log</options>
  </rule>

  <!-- Correlation: multiple differing document-read requests -->
  <rule id="100171" level="8" frequency="8" timeframe="120" ignore="120">
    <if_matched_sid>100170</if_matched_sid>
    <same_field>win.eventdata.subjectLogonId</same_field>
    <different_field>win.eventdata.relativeTargetName</different_field>
    <description>Possible SMB bulk document access by $(win.eventdata.subjectUserName) from $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1039</id>
    </mitre>
    <group>smb_bulk_file_access,</group>
  </rule>

</group>
```

**Why level 1 with `no_log`?** Wazuh frequency correlation can reference base-rule matches with `if_matched_sid`, but a level-0 rule cannot serve this purpose. Keeping `100170` at level 1 and suppressing its individual output allows `100171` to raise the meaningful behavioral alert.

## Validation Results

The exercise used a temporary read-only Finance SMB share, test account `inc004_reader`, and **synthetic** files. No production data was involved.

| Test | Procedure / observation | Result |
|---|---|---|
| Telemetry check | Before correction, Windows logged `5145` locally but Wazuh agent's Security-channel XPath excluded it. After removing only that exclusion, a fresh `5145` event for `README.txt` appeared in `archives.json`. | **Collection restored** |
| Negative | A small, two-file SMB read test did not meet the behavioral threshold. | **No `100171` alert observed** |
| Positive | Ten distinct synthetic text files were requested through SMB under the same logon. Windows recorded ten matching `5145` events, Record IDs **40327–40336**. | **`100171` triggered** |

### Collection and Ingestion Evidence

![Figure 38 — Wazuh agent Security event filter](/screenshots/38-inc004-agent-5145-filter.png)

*Figure 38. The Windows agent Security-channel filter was updated to include Event ID 5145, restoring detailed SMB file-share telemetry collection.*

![Figure 39 — Event ID 5145 ingestion verification](/screenshots/39-inc004-5145-ingestion.png)

*Figure 39. A fresh Event ID 5145 for the test SMB share was received by the Wazuh manager, confirming event ingestion before behavioral detection was tested.*

### Behavioral Alert Evidence

**Observed Wazuh alert:**

```text
Timestamp:   2026-10-26T16:24:04.637+0000
Rule ID:     100171
Level:       8
Description: Possible SMB bulk document access by inc004_reader from 192.168.245.30
Logon ID:    0xb232ba
```

![Figure 40 — SMB bulk document access alert](/screenshots/40-inc004-bulk-access-alert.png)

*Figure 40. Wazuh rule 100171 generated a Level 8 alert after the controlled SMB test accessed ten distinct synthetic documents in a short interval.*

The positive test establishes that a burst of **ten different filenames** produced a level-8 detection, while the two-file test did not. It does **not** prove that Wazuh always counts exactly eight globally unique filenames, or that every alert represents exfiltration.

### Analyst Verification

Wazuh Discover (index `wazuh-alerts-*`):

```text
agent.id: "001" AND rule.id: "100171"
```

Or on the Wazuh manager:

```bash
sudo jq -r '
  select(.agent.id == "001" and .rule.id == "100171") |
  [.timestamp, .rule.id, .rule.level, .rule.description,
   (.data.win.eventdata.subjectLogonId // "-")] | @tsv
' /var/ossec/logs/alerts/alerts.json
```

For investigation, pivot on `subjectLogonId`, `ipAddress`, `subjectUserName`, `shareName`, and `relativeTargetName`; correlate with Windows `4624` / `5140` / `5145`, SMB client logs, and network captures where available.

## False Positives, Gaps, and Tuning

- **Potential false positives:** legitimate backups, file indexing, bulk reporting, document migrations, and user-driven batch downloads.
- **Potential blind spots:** Event ID `5145` auditing disabled or filtered before ingestion; unsupported file extensions; access patterns below the threshold or spread over more than 120 seconds; multiple read operations and filename variations that do not correspond to distinct completed downloads.
- **Correlation limitation:** `subjectLogonId` is scoped to a Windows logon on the monitored endpoint. The rule does not additionally enforce an identical source IP, account, or share across all contributing events.
- **Tuning approach:** establish normal SMB activity by host, share, user role, and time; investigate repeated alerts; introduce narrow documented exclusions only for validated benign workflows rather than broadly suppressing SMB events.

## Detection Assessment

**Verdict:** **True positive for the authorized bulk SMB read-access activity** simulated in INC-004. The test confirmed end-to-end ingestion and a behavioral rule match. This is **not** proof of malicious intent, production-data theft, or full-file transfer on its own.

**Implementation note:** Both rule IDs belong together in the existing `local_rules.xml` file. Their production relevance depends on keeping detailed file-share auditing enabled and preserving Event ID `5145` in the Wazuh agent's Security event filter.

## Related Evidence

- [INC-004 — SMB File Access Investigation](/incidents/INC-004-smb-file-access/investigation.md)
- [Wazuh rule syntax reference](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
