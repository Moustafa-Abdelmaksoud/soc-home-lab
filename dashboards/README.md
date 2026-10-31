# SOC Monitoring Dashboards

Two custom Wazuh dashboards developed to monitor alert volume, detection severity, Windows authentication activity, endpoint changes, and selected lab detection rules.

**Platform:** Wazuh Dashboard (OpenSearch)  
**Data view:** `wazuh-alerts-*`  
**Time range used for validation:** Last 30 days, screenshot captured October 31, 2026  
**Lab endpoint:** `SOC-WINDOWS` (Windows agent `001`)  
**Scope:** Alerts indexed by Wazuh; not an exhaustive view of raw Windows event logs.

## 1. SOC Security Overview

Provides a high-level summary of security alert activity and ATT&CK categorization.

![Figure 58 — SOC Security Overview dashboard](/screenshots/58-soc-security-overview.png)

*Figure 58. Saved SOC Security Overview dashboard displaying overall alert counts, severity, alert trends, most frequently triggered rules, and MITRE ATT&CK tactics.*

| Panel | Visualization | Configuration / filter |
|---|---|---|
| SOC-01 — Alert Volume Over Time | Vertical bar | Count by `timestamp` (date histogram, auto interval) |
| SOC-02 — High-Severity Alerts | Metric | `rule.level >= 12` |
| SOC-03 — Top Triggered Rules | Horizontal bar | Terms on `rule.id`, descending by Count, top 10 |
| SOC-04 — Alerts by Severity | Donut | Terms on `rule.level`, descending by Count |
| SOC-05 — MITRE ATT&CK Tactics | Horizontal bar | `rule.mitre.tactic:*`; Terms on `rule.mitre.tactic`, descending by Count |
| SOC-06 — Total Alerts | Metric | Count across the selected time range; no query filter |

**Observed at capture:** 12,219 total alerts and 1,419 high-severity alerts. Rule `60602` contributed the highest alert volume. The most frequent MITRE tactic classifications were Privilege Escalation, Defense Evasion, and Persistence.

These figures are a point-in-time snapshot, not permanent KPI targets. Alert volume is not the number of distinct incidents, and one alert may have more than one ATT&CK tactic.

## 2. Authentication & Endpoint Activity

Focuses on Windows authentication failures, suspicious account and service changes, and selected behavioral detection alerts.

![Figure 59 — Authentication & Endpoint Activity dashboard](/screenshots/59-soc-authentication-endpoint-activity.png)

*Figure 59. Saved Authentication & Endpoint Activity dashboard showing six security KPIs and a timeline of selected suspicious PowerShell detections.*

| Panel | Visualization | DQL filter | Observed count |
|---|---|---|---:|
| SOC-07 — Failed Windows Logons | Metric | `data.win.system.eventID: "4625"` | 41 |
| SOC-08 — RDP Brute-Force Alerts | Metric | `rule.id: "100120"` | 3 |
| SOC-09A — New User Accounts | Metric | `data.win.system.eventID: "4720"` | 8 |
| SOC-09B — Local Group Membership Changes | Metric | `data.win.system.eventID: "4732"` | 4 |
| SOC-10 — Suspicious PowerShell Activity | Vertical bar, daily date histogram | `rule.id: ("100110" OR "100150" OR "100160")` | 11* |
| SOC-11 — New Windows Services | Metric | `data.win.system.eventID: "7045"` | 4 |
| SOC-12 — SMB Bulk Access Alerts | Metric | `rule.id: "100171"` | 1 |

\*PowerShell alert count was estimated by summing the three visible daily histogram bars in the captured view (2 + 7 + 2); it is not an independently queried aggregate.

### Selected detection semantics

- **Failed logons (4625):** all indexed Windows failed-logon events, not exclusively RDP failures.
- **RDP brute-force (100120):** number of correlation-rule alerts, not individual password guesses.
- **Account creation (4720):** event count, not necessarily unique usernames.
- **Local group additions (4732):** membership changes across local security groups, not necessarily Administrators-only additions.
- **PowerShell rules (100110/100150/100160):** selected detections covering encoded commands, an encoded PowerShell auto-start entry, and PowerShell network activity. Excludes generic rule `92066`.
- **New services (7045):** service-installation events; not proof of malicious persistence.
- **SMB bulk access (100171):** high-level correlation alert (Level 8), not the underlying document-read request rule `100170`, and not proof that files were fully downloaded.

## Validation and interpretation

All panels were created in Wazuh Visualize, then added as saved visualizations to their respective dashboards. The captured screenshots show both dashboards in view mode and the 30-day period was used while testing the panels.

Every KPI depends on the selected time range, indexed alert retention, the availability of the source event in `wazuh-alerts-*`, and correct persistence of the visualization's query filter. An empty panel alone does not establish that the activity never occurred. Bulk file requests and Windows object-access events must not be represented as completed file exfiltration without corroborating evidence.

## Related investigations and detections

- [INC-006 — Multi-Stage Intrusion Investigation](/incidents/INC-006-multi-stage-intrusion/investigation.md)
- [D008 — SMB Bulk Document Access Detection](/detections/D008-smb-bulk-document-access.md)
