# INC-003 — Unauthorized Admin Account Investigation

## Incident Overview

| Field | Details |
|---|---|
| Case ID | INC-003 |
| Date | October 25, 2026 |
| Affected Host | SOC-WINDOWS — 192.168.245.20 |
| Account Created | inc003_support |
| Actor Account | SOC-WINDOWS\socuser |
| Privileged Group | BUILTIN\Administrators |
| Data Sources | Windows Security Logs, Wazuh SIEM |
| Classification | Benign True Positive |
| Severity | Low — Authorized Lab |
| Status | Investigation Completed / Cleanup Verified |

## 1. Scenario

This investigation simulated the creation of an unexpected local Windows account followed by its addition to the local Administrators group.

The simulation began from an already elevated, authorized Windows session.

The objective was to detect privileged account changes, correlate related Windows Security events using account SIDs, investigate account usage, and validate access removal.

No privilege-escalation exploit or unauthorized initial access was performed.

## 2. Evidence Collection

Four Windows Security events established the account lifecycle.

| Event ID | Wazuh Rule | Observed Activity |
|---|---|---|
| 4720 | 60109 | Local account created |
| 4732 | 60154 | Account added to Administrators |
| 4733 | 60154 | Account removed from Administrators |
| 4726 | 60111 | Local account deleted |

All four events were observed in Wazuh Discover for agent `001`.

### Account Identity

The investigation identified the following account SID:

`S-1-5-21-262593852-1112691316-1522484287-1006`

The local Administrators group was identified using its well-known SID:

`S-1-5-32-544`

### Identity Correlation

- Event 4720: `TargetSid` identified the newly created account.
- Event 4732: `MemberSid` matched the account SID, confirming its addition to Administrators.
- Event 4733: `MemberSid` matched the same account SID, confirming membership removal.
- Event 4726: `TargetSid` matched the account SID, confirming account deletion.

The `SubjectUserName` field identified `socuser` as the actor performing these changes.

**Finding:** A single local account was created, granted privileged group membership, removed from that group, and deleted.

## 3. Investigation Timeline

Times below are shown as displayed in the Wazuh Dashboard on October 25, 2026.

| Time | Event ID | Activity |
|---|---|---|
| 16:30:39 | 4720 | inc003_support created |
| 16:42:51 | 4732 | Account added to Administrators |
| 17:22:42 | 4733 | Administrator membership removed |
| 17:22:44 | 4726 | Account deleted |

The account held Administrators group membership for approximately 40 minutes during the authorized exercise.

Windows-local time displays were not independently reconciled with Dashboard time settings; the timeline consistently uses Dashboard timestamps.

## 4. Account Usage Investigation

Windows Security events 4624 and 4625 were searched for the account name and SID from the beginning of the investigation day.

| Event | Observed Count |
|---|---|
| Successful Logon — 4624 | 0 |
| Failed Logon — 4625 | 0 |

No matching authentication events were observed in the selected local Security Log query.

This result is limited to the examined log source and time window. It does not prove that the account was never used under any circumstances.

No test login was deliberately performed with the privileged account.

## 5. Security Assessment

The investigated sequence demonstrates a potentially serious administrative access change.

In an enterprise environment, an unapproved account added to local Administrators could provide an additional means of privileged access or persistence.

However, in this lab:

- The changes were explicitly authorized.
- The actor account was known.
- Account creation and membership changes were directly observed.
- No successful login by the test account was found in the examined events.
- The administrative membership and test account were subsequently removed.

**Final Classification:** Benign True Positive

**Case Severity:** Low — Authorized Lab

**Compromise Assessment:** No unauthorized compromise established.

**Escalation Decision:** No incident escalation required for the authorized simulation.

An equivalent unapproved change on a production endpoint would warrant prompt validation of authorization, account activity, and the need for containment.

## 6. MITRE ATT&CK Mapping

| Technique | Simulated Behavior |
|---|---|
| T1136.001 — Create Account: Local Account | Creation of inc003_support |
| T1098.007 — Account Manipulation: Additional Local or Domain Groups | Addition to local Administrators |

The mapping describes the simulated behaviors, not malicious intent.

This exercise did not demonstrate escalation from an unprivileged account because the initiating session was already elevated.

## 7. Response and Remediation

The following response actions were performed:

1. Removed inc003_support from the local Administrators group.
2. Verified the corresponding Windows Security Event 4733 in Wazuh.
3. Deleted the temporary local account.
4. Verified the corresponding Windows Security Event 4726 in Wazuh.
5. Checked current local account and group membership state.

### Post-Remediation Verification

```text
AccountExists         : False
AdminMembershipExists : False
```

**Result:** PASS — Temporary account and privileged membership removed.

Security logs were retained for investigation evidence.

## 8. Evidence Screenshots

### Figure 1 — Account Creation and Administrative Membership

![Account creation and group modification](/screenshots/32-inc003-account-privilege-wazuh.png)

*Wazuh events 4720 and 4732 showing account creation, administrative membership, and matching SID evidence.*

### Figure 2 — Account Usage Investigation

![Account authentication check](/screenshots/33-inc003-account-usage-check.png)

*Windows Security Log investigation showing zero matching successful and failed logons in the selected window.*

### Figure 3 — Remediation Events

![Administrator membership removed and account deleted](/screenshots/34-inc003-response-events.png)

*Wazuh events 4733 and 4726 documenting privileged group removal and account deletion.*

### Figure 4 — Final Cleanup Verification

![Account and membership verification](/screenshots/35-inc003-cleanup-verification.png)

*PowerShell confirms that neither the test account nor its Administrators membership remains.*

## 9. Limitations

- This was an authorized simulation, not a real unauthorized account takeover.
- No privilege-escalation technique was executed.
- Authentication searches covered a defined local log source and time window.
- No automated multi-event detection rule correlating account creation with privileged group addition was created.
- Response actions demonstrated controlled access removal, not a production incident response operation.
- Exact Windows-local and Dashboard timestamp differences were not investigated.

## 10. Lessons Learned

- Account creation and administrative group modification are separate security events.
- Account SIDs provide stronger identity correlation than usernames alone.
- The actor responsible for a change must be distinguished from the account being modified.
- Privileged account risk exists even when successful authentication has not been observed.
- Incident severity depends on authorization and operational context.
- Effective response verification requires checking both event logs and the current system state.

## Conclusion

INC-003 demonstrated an end-to-end investigation of privileged local account changes, including creation, group membership modification, account usage analysis, access removal, and post-remediation verification.

The exercise strengthened identity-based correlation, Windows Security Log investigation, and evidence-driven incident response skills.
