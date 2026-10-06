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

## Network Design

The lab uses a dedicated VirtualBox Host-Only network to isolate security testing traffic from the physical home network.

| System | Role | IP Address |
|---|---|---|
| Windows Host | Management | 192.168.245.1 |
| Wazuh Server | SIEM / XDR | 192.168.245.10 |
| Windows 11 Endpoint | Monitored Workstation | 192.168.245.20 |
| Kali Linux | Attacker / Adversary Simulation | 192.168.245.30 |

### Network

192.168.245.0/24

### Interface Design

The Wazuh server uses two network interfaces:

- NAT interface for Internet access and package updates.
- Host-Only interface for internal SOC lab communication.

The attacker and victim systems communicate only inside the isolated lab network during attack simulations.
