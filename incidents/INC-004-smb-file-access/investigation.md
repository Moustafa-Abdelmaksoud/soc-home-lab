# INC-004 — Suspicious SMB File Access and Detection Coverage Gap

**Status:** Closed — authorized lab simulation  
**Disposition:** True positive for simulated bulk SMB file access; no real-world compromise  
**Investigation dates:** October 25–26, 2026  
**Affected host:** `SOC-WINDOWS` (`192.168.245.20`)  
**Source:** Kali (`192.168.245.30`)  
**SIEM:** Wazuh 4.14.8 (`SOC-WAZUH`, `192.168.245.10`)

## Summary

Investigated authenticated SMB access to a temporary Finance share and the collection of **synthetic** files. Network evidence confirmed SMB2 file transfers, while Windows Security logs recorded successful logons and share/file access. The investigation exposed two monitoring gaps: Windows Event ID **5145** was explicitly excluded by the Wazuh agent's Security-channel filter, and newly ingested 5145 events did not initially generate useful alerts. Collection was repaired, and a behavioral detection prototype was developed and validated.

## Key evidence

| Source                    | Finding                                                                                                                                 |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Windows Security          | Two `4624` successful logons, three `5140` share-access events, and seven `5145` detailed file-share events during the initial activity |
| Wazuh alerts (initial)    | Rules `92657` (`4624`) and `67017` (`5140`) fired; no `5145` alert                                                                      |
| Network capture           | SMB2 `CREATE`/`READ` requests and responses showed transfers of `Payroll-FAKE.csv` (140 bytes) and `README.txt` (51 bytes)              |
| Wazuh agent configuration | Security-channel XPath query excluded `EventID != 5145`                                                                                 |
| Wazuh archives (post-fix) | New `5145` event received for `README.txt`, `inc004_reader`, `192.168.245.30`; `SubjectLogonId: 0x33a439`                               |
| Behavioral validation     | Ten 5145 read-request events for ten distinct synthetic files in one SMB session; rule `100171` generated a level-8 alert               |

## Investigation and remediation

1. **Confirmed access and transfer.** The temporary account `inc004_reader` authenticated to `INC004_FINANCE`. Windows events identified the account and source address; `smbclient` output and the packet capture independently confirmed the transfer of synthetic files.
2. **Identified a collection gap.** The Wazuh agent's Windows Security query filtered out Event ID `5145`. Removed only that exclusion, retaining the other noise-reduction filters. After restarting the agent, enabled manager JSON archives temporarily and verified ingestion of a new `5145` event.
3. **Identified an alerting gap.** The post-fix `5145` event appeared in `archives.json` but not in `alerts.json`.
4. **Improved detection.** Added rules to the existing `local_rules.xml`. Base rule `100170` matches selected SMB document-read requests through Windows Security audit-success parent rule `60103`. Correlation rule `100171` looks for repeated document-read requests within 120 seconds, using the logon ID and differing target filenames. Final configuration: `100170` level 1 with `no_log`; `100171` level 8, `frequency=8`, `timeframe=120`, `ignore=120`.
5. **Validated behavior.** A two-file negative test produced no observed `100171` alert. A ten-file positive test produced a level-8 alert at `2026-10-26T16:24:04Z`, with logon ID `0xb232ba`. Windows logged ten corresponding `5145` events (Record IDs `40327`–`40336`) for ten distinct filenames.
6. **Contained and cleaned up.** Disabled and deleted `inc004_reader`; removed its explicit NTFS grant; removed the `INC004_FINANCE` share, the scoped Kali-to-Windows TCP/445 firewall rule, and the synthetic Finance directory. Verified the account, share, firewall exception, and Finance directory were absent. Restored manager `<logall_json>no</logall_json>` and verified the manager was active.

## Assessment

**Verdict:** Confirmed, authorized SMB access and synthetic file collection in an isolated lab. The behavioral alert is a **true positive for the activity tested**, not evidence of an unauthorized breach or production-data exfiltration.

**Limitations:** Event `5145` records an access check and does not alone establish completed file transfer; the network capture and `smbclient` receipts provide that evidence. The positive test demonstrates alerting during ten distinct file requests, but does not independently prove that the rule always counts eight unique files. The threshold is experimental; backup jobs, legitimate bulk access, and other normal workflows could produce false positives. Windows-local timestamps differed from the Wazuh/packet timestamps and should not be merged into a precise cross-host timeline without clock validation.

## Evidence screenshots

**Figure 36 — SMB2 file transfer.** Wireshark shows SMB2 `CREATE` and `READ` requests/responses for synthetic files.

![Figure 36 - Wireshark SMB2 file transfer](screenshots/36-inc004-smb2-transfer.png)

**Figure 37 — Initial SIEM visibility.** Wazuh alerts for events `4624` and `5140`, with no initial `5145` alerts.

![Figure 37 - Initial Wazuh SMB alerts](screenshots/37-inc004-initial-wazuh-alerts.png)

**Figure 38 — Collection filtering root cause.** The Windows Wazuh agent Security-channel XPath query excluded Event ID `5145`.

![Figure 38 - Agent exclusion of Event 5145](screenshots/38-inc004-agent-5145-filter.png)

**Figure 39 — Collection fix validation.** The new Event `5145` appeared in Wazuh `archives.json` for `README.txt` after the filter was corrected.

![Figure 39 - Event 5145 in Wazuh archives](screenshots/39-inc004-5145-ingestion.png)

**Figure 40 — Behavioral alert.** Rule `100171` generated a level-8 alert for multiple document-read requests from one SMB session.

![Figure 40 - Wazuh rule 100171 alert](screenshots/40-inc004-bulk-access-alert.png)

The raw SMB packet capture and detailed local forensic artifacts are deliberately excluded from this public report, as SMB captures may contain sensitive authentication/session information. Screenshots should be checked for secrets before publication.

## Lessons learned

- Distinguish **missing telemetry** from **missing alerts** before changing detection logic.
- Validate collection fixes with new endpoint-generated events.
- Test detections against benign and suspicious activity, and document the limits of the rule.
- Use correlated host and network evidence for file-transfer conclusions.
