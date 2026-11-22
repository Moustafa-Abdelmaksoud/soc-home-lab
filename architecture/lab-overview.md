# SOC Home Lab Architecture

## Objective

This project is a practical Security Operations Center home lab for:

- Security monitoring
- Windows log analysis
- Detection engineering
- Firewall policy validation
- Network segmentation
- Alert investigation
- Incident response
- MITRE ATT&CK mapping

The current design separates the adversary-simulation host from the monitored SOC subnet so traffic from the attack zone to protected internal systems must traverse the FortiGate.

## Lab Components

### Wazuh Server

Acts as the central SIEM/XDR platform responsible for collecting, analyzing, and alerting on security events.

- Internal IP: `192.168.245.10/24`
- Receives Windows endpoint telemetry through the Wazuh agent
- Receives FortiGate traffic logs through a local rsyslog collector
- Monitors `/var/log/fortigate/traffic.log` with Wazuh logcollector

### SOC-WINDOWS

Represents a corporate Windows 11 workstation monitored using Windows Event Logs, Sysmon, and the Wazuh Agent.

- Internal IP: `192.168.245.20/24`
- Persistent return route to `192.168.246.0/24` through FortiGate `192.168.245.40`

### Kali Linux

Represents an authorized adversary-simulation host.

- Attack-zone IP: `192.168.246.30/24`
- Route to `192.168.245.0/24` through FortiGate `192.168.246.40`
- Separate VirtualBox NAT interface remains the default route for Internet access

The Kali configuration was verified after reboot to confirm the attack-zone address and internal-SOC route persisted.

### FortiGate

FortiGate provides the routed security boundary between the attack zone and the internal SOC subnet.

| Interface | Role | IP |
|---|---|---|
| `port1` | WAN / VMware NAT | `192.168.248.129/24` |
| `port2` | ATTACK-ZONE | `192.168.246.40/24` |
| `port3` | INTERNAL / SOC | `192.168.245.40/24` |

The verified routing table contains:

```text
S* 0.0.0.0/0         via 192.168.248.2, port1
C  192.168.245.0/24  directly connected, port3
C  192.168.246.0/24  directly connected, port2
C  192.168.248.0/24  directly connected, port1
```

No additional static routes are configured on FortiGate.

## Hypervisor Design

The lab intentionally uses both VMware and VirtualBox.

### VMware

FortiGate runs in VMware.

- `VMnet8` -> VMware NAT -> FortiGate WAN (`port1`)
- `VMnet1` -> bridged to VirtualBox Host-Only Ethernet Adapter #3 -> ATTACK-ZONE
- `VMnet0` -> bridged to VirtualBox Host-Only Ethernet Adapter #2 -> INTERNAL / SOC

### VirtualBox

Wazuh, SOC-WINDOWS, and Kali run in VirtualBox.

Relevant host-only networks:

| VirtualBox network | Subnet | Purpose |
|---|---|---|
| Host-Only Ethernet Adapter #2 | `192.168.245.0/24` | INTERNAL / SOC |
| Host-Only Ethernet Adapter #3 | `192.168.246.0/24` | ATTACK-ZONE |

This mixed-hypervisor bridge design allows the VMware FortiGate VM to sit inline between VirtualBox network segments.

## Current Network Topology

```text
                         Internet
                            |
                     VMware NAT
                    192.168.248.0/24
                            |
                 FortiGate port1
                 192.168.248.129
                            |
              +-------------+-------------+
              |                           |
      FortiGate port2             FortiGate port3
       ATTACK-ZONE                 INTERNAL / SOC
       192.168.246.40              192.168.245.40
              |                           |
              |                     +-----+------+
              |                     |            |
            Kali                SOC-WINDOWS     Wazuh
      192.168.246.30           192.168.245.20 192.168.245.10
```

The key security property is that Kali and SOC-WINDOWS are no longer on the same Layer-2 subnet. Traffic from the attack zone to `192.168.245.0/24` must be routed through FortiGate.

## Firewall Baseline

The active custom firewall baseline was reduced to the policies required for the current architecture.

### ATTACK_TO_WAZUH_DENY

```text
Source interface:      port2
Destination interface: port3
Source:                KALI_ATTACK (192.168.246.30/32)
Destination:           WAZUH_SERVER (192.168.245.10/32)
Action:                deny
Service:               ALL
Logging:               all
```

This explicit deny policy is intentionally logged to provide visibility into attempts from the attack zone to reach the SIEM infrastructure.

### ATTACK_TO_WINDOWS_ICMP

```text
Source interface:      port2
Destination interface: port3
Source:                KALI_ATTACK (192.168.246.30/32)
Destination:           SOC_WINDOWS (192.168.245.20/32)
Action:                accept
Service:               PING
Logging:               all
```

This is a narrow validation policy used to prove routed enforcement through FortiGate. Future attack scenarios should open only the services required for that scenario.

### Removed Legacy Configuration

The following stale lab configuration was removed after the architecture change:

- `LAB_ALLOW_HTTPS` firewall policy
- `LAB_DESTINATION` address object (`1.1.1.1/32`)
- `LAB_DNS_UDP` custom service
- `LAB_HTTP_8080` custom service

Reference counts were checked before deletion.

## Interface Hardening

The attack-zone FortiGate interface was hardened from:

```text
allowaccess ping https ssh
```

to:

```text
allowaccess ping
```

Validation from Kali confirmed:

- ICMP to `192.168.246.40`: **allowed**
- TCP/22 to `192.168.246.40`: **timed out**
- TCP/443 to `192.168.246.40`: **timed out**

FortiGate administration remains available from the internal side through `port3`.

## FortiGate to Wazuh Logging

FortiGate traffic logs are forwarded to the Wazuh server:

```text
FortiGate
   |
   | Syslog TCP/514
   v
rsyslog on 192.168.245.10
   |
   v
/var/log/fortigate/traffic.log
   |
   v
Wazuh logcollector
   |
   v
fortigate-firewall-v5 decoder
   |
   v
Wazuh rules and alerts
```

Live validation showed raw FortiGate deny events with:

```text
srcip=192.168.246.30
srcintf=port2
dstip=192.168.245.10
dstintf=port3
action=deny
policyid=2
policyname=ATTACK_TO_WAZUH_DENY
service=PING
```

Wazuh logcollector was also confirmed to be monitoring `/var/log/fortigate/traffic.log`.

## Security Validation

The segmentation migration was validated with both positive and negative tests:

| Test | Result |
|---|---|
| Kali -> FortiGate port2 ping | **Allowed** |
| Kali -> SOC-WINDOWS ping through FortiGate | **Allowed and logged by ATTACK_TO_WINDOWS_ICMP** |
| Kali -> Wazuh | **Denied** |
| Kali -> Wazuh deny traffic visible in FortiGate Forward Traffic | **Confirmed** |
| FortiGate deny log written to `/var/log/fortigate/traffic.log` | **Confirmed** |
| Wazuh decoder `fortigate-firewall-v5` | **Confirmed** |
| D009 repeated untrusted access alert | **Live validated** |

See [D009 — Untrusted Access to Wazuh Server](/detections/D009-untrusted-access-to-wazuh.md) for the detection logic and validation boundaries.

## Security Considerations and Limitations

- The lab is isolated and used only for authorized testing.
- Kali retains a separate NAT interface for Internet access. Therefore FortiGate currently enforces **attack-zone-to-internal-SOC traffic**, not all Kali Internet traffic.
- Wazuh and SOC-WINDOWS remain on the same internal subnet, so their local Layer-2 communication does not traverse FortiGate.
- The Wazuh protection detection is based on FortiGate-visible traffic. A path that bypasses FortiGate must be detected with host telemetry or another control.
- The current trusted SOC subnet is lab-specific. Production deployments should model all approved management, monitoring, VPN, and jump-host ranges explicitly.
