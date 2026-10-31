# Lessons Learned

The following takeaways are based on the project's completed [detection exercises](/detections/) and [incident investigations](/incidents/), not a separate threat-hunting phase.

## Telemetry quality precedes detection quality

Windows event auditing and Wazuh collection configuration influence what can be investigated. [INC-004](/incidents/INC-004-smb-file-access/investigation.md) exposed a visibility gap involving detailed file-share access events. Adding and validating Event 5145 ingestion improved detection coverage, but a file-access check alone cannot confirm a completed transfer.

## Correlation matters more than isolated alerts

Event sequences and process context are stronger than single detections. [INC-006](/incidents/INC-006-multi-stage-intrusion/investigation.md) linked RDP activity, changes to a lab service executable, SYSTEM-context child processes, local account creation, group membership changes, hive acquisition, and SMB evidence. Independent events needed interpretation as a timeline.

## Positive and negative tests define a detection's scope

The [detection reports](/detections/) document what triggered selected rules and what did not. For [D008](/detections/D008-smb-bulk-document-access.md), the controlled ten-file access test produced a bulk-access alert while the two-file test did not. This establishes behavior in the tested conditions, not a universal guarantee or an exact count of transferred files.

## Privilege and persistence findings need careful wording

Service installation and administrative group membership changes can be legitimate. Their suspiciousness depends on timing, executing user, file location, permissions, and surrounding activity. [INC-005](/incidents/INC-005-service-persistence/investigation.md) and [INC-006](/incidents/INC-006-multi-stage-intrusion/investigation.md) demonstrate why service execution and persistence must be verified through evidence.

## Recovery needs observable verification

The investigations recorded containment, test-artifact removal, and verification steps. [INC-006](/incidents/INC-006-multi-stage-intrusion/investigation.md) concluded with seven checks confirming the inspected lab accounts, service, share, RDP state, monitoring state, and lab directories. Such checks establish recovery in their inspected scope, not forensic proof that no copy exists elsewhere.

## Monitoring panels must state their semantics

The [SOC dashboards](/dashboards/README.md) visualize indexed Wazuh alerts in a selected time range. An alert count is not an incident count; multiple detections can correspond to one activity, and the absence of indexed alerts does not prove no underlying event occurred. Accurate panel labels and saved filters are essential.

## Portfolio reporting should distinguish observation from inference

Evidence screenshots, queries, rule IDs, timelines, limitations, and clean-up checks improve reproducibility. Avoid implying credential-hash extraction, completed data exfiltration, or interactive SYSTEM access unless those outcomes are independently demonstrated.

---

**Project outcome:** A controlled SOC workflow spanning telemetry collection, rule validation, alert triage, investigation, detection-gap analysis, monitoring dashboards, and documented recovery.
