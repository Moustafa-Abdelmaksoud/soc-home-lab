# SOC Home Lab Architecture

## Objective

The objective of this project is to build a practical
Security Operations Center home lab for learning:

- Security monitoring
- Windows log analysis
- Detection engineering
- Alert investigation
- Incident response
- MITRE ATT&CK mapping

## Lab Components

### Wazuh Server
Acts as the central SIEM/XDR platform responsible for
collecting, analyzing, and alerting on security events.

### Windows Endpoint
Represents a corporate workstation monitored using
Windows Event Logs, Sysmon, and the Wazuh Agent.

### Kali Linux
Represents an attacker machine used to generate controlled
security events inside the isolated lab environment.
