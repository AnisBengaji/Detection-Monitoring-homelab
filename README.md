# Cybersecurity Homelab — Detection & Monitoring

A virtualized SOC environment built on Pop OS using VMware Workstation, simulating a corporate Active Directory environment with full network segmentation, intrusion detection, and SIEM integration. This lab covers the full SOC workflow: attack simulation → log ingestion → detection → investigation.

---

## Architecture

![Architecture](newArchitecture.png)

---

## Stack

| Layer | Tool |
|-------|------|
| Hypervisor | VMware Workstation (Pop OS Host) |
| Firewall & Routing | pfSense 2.6.0 |
| Network Intrusion Detection | Suricata 8.0.4 |
| Endpoint Telemetry | Sysmon (SwiftOnSecurity config) |
| SIEM | Splunk Enterprise |
| Identity & Access | Active Directory (Windows Server 2019) |
| Attack Simulation | Kali Linux + Atomic Red Team |

---

## Network Architecture

| Network | Subnet | Interface | Purpose |
|---------|--------|-----------|---------|
| KALI | 192.168.1.0/24 | em1 | Attack machine isolation |
| VICTIMNET | 192.168.2.0/24 | em2 | Domain Controller + endpoints |
| SEC | 192.168.3.0/24 | em3 | Security monitoring (Suricata) |
| SPANPORT | — | em4 | Traffic mirroring |
| SPLUNK | 192.168.4.0/24 | em5 | SIEM isolation |

---

## Data Sources Ingested

| Source | Data | Splunk Index |
|--------|------|--------------|
| Suricata IDS | Network alerts, flow data, DNS, SMB, HTTP | suricata |
| Sysmon (EID 1,3,7,10,11) | Process creation, network connections, file events | wineventlog |
| Windows Security Logs | Authentication, privilege use, account management | wineventlog |
| Windows System/Application | Service events, application errors | wineventlog |
| pfSense Syslog | Firewall allow/deny, DNS queries, DHCP leases | pfsense |

---

## Log Ingestion Setup

### pfSense Syslog → Splunk
- pfSense configured to forward syslog to Splunk UDP port 514
- Covers firewall allow/deny rules, interface traffic, DNS and DHCP activity

### Sysmon → Splunk
- Sysmon installed on Windows DC using SwiftOnSecurity config
- Splunk Universal Forwarder monitors `Microsoft-Windows-Sysmon/Operational`
- Forwards to Splunk indexer at `192.168.4.10:9997`

### Windows Event Logs → Splunk
- Security, System, and Application logs forwarded via Universal Forwarder
- Covers EventIDs: 4624, 4625, 4634, 4672, 4688, 4720, 4732

---

## Attack Scenarios & Detection

### 🔴 Kali Linux Attack Chain

#### Phase 1 — Reconnaissance

**Tools:** Nmap
```bash
sudo nmap -sn 192.168.2.0/24
sudo nmap -sS -sV -A -T4 192.168.2.10
sudo nmap -O 192.168.2.10
```

**OS Detection:**

![OS Detection](osDetection.png)

**Port & Services Scan:**

![Ports and Services](ports&services.png)

**Detected in Splunk:**

![Splunk Phase 1](splunkphase1.png)

**Splunk Query:**
```
index=suricata event_type=alert | table timestamp src_ip dest_ip alert.signature
```

**MITRE:** T1595 - Active Scanning, T1046 - Network Service Scanning

---

#### Phase 2 — Enumeration

**Tools:** Nmap SMB scripts, CrackMapExec
```bash
sudo nmap --script=smb-enum-shares,smb-enum-users -p 445 192.168.2.10
crackmapexec smb 192.168.2.10 --users --shares
```

**CrackMapExec AD Enumeration:**

![CrackMapExec](CrackMapExec_AD_ENUM.png)

**Detected in Splunk (SMB alerts):**

![Splunk SMB](splunk_smb.png)

**Splunk Query:**
```
index=suricata event_type=alert app_proto=smb | table timestamp src_ip dest_ip alert.signature
```

**MITRE:** T1135 - Network Share Discovery, T1087 - Account Discovery

---

#### Phase 3 — Credential Attack (NTLM Brute Force)

**Tools:** Hydra, Metasploit smb_login, CrackMapExec password spray

**Hydra Brute Force:**

![Hydra](hydra.png)

**Password Spray:**

![Password Spray](password_sprays.png)

**Metasploit SMB Login:**

![Metasploit](metaspPWD.png)

**Detected in Splunk:**

![Splunk Brute Force](splunk_crack.png)

**Splunk Queries:**
```
index=suricata event_type=alert app_proto=smb | table timestamp src_ip dest_ip alert.signature direction
index=wineventlog EventCode=4625 | stats count by src_ip user | sort -count
```

**MITRE:** T1110 - Brute Force, T1557 - Adversary in the Middle

---

### 🔵 Atomic Red Team — MITRE ATT&CK Simulation

Atomic Red Team installed on Windows DC via `Invoke-AtomicRedTeam`. Each test simulates a real adversary technique mapped to MITRE ATT&CK and validates detection in Splunk via Sysmon telemetry.

#### T1057 — Process Discovery
```powershell
Invoke-AtomicTest T1057
```
**Processes Detected:** `whoami`, `hostname`, `tasklist`, `wmic process get`, `Get-Process`, `Taskmgr.exe`

![T1057 Splunk](AtommicT1057_SPLUNK.png)

---

#### T1087.001 — Account Discovery + T1059.001 PowerShell + T1003.001 Credential Dumping
```powershell
Invoke-AtomicTest T1087.001
Invoke-AtomicTest T1059.001
Invoke-AtomicTest T1003.001
```

![Atomic T1059 T1003](Atomic_T1059_T1003_Splunk.png)

---

#### Additional Atomic Red Team Results

![Atomic R1](AtomicR1.png)

![Atomic R2](AtomicR2.png)

![Atomic R3](AtomicR3.png)

**Splunk Query used for all Atomic tests:**
```
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Image>(?<Image>[^<]+)</Image>"
| rex field=_raw "<CommandLine>(?<CommandLine>[^<]+)</CommandLine>"
| rex field=_raw "<User>(?<User>[^<]+)</User>"
| where NOT match(Image, "splunk")
| table _time Image CommandLine User
| sort -_time
```

---

## MITRE ATT&CK Coverage

| Phase | Technique ID | Technique | Tool | Detected |
|-------|-------------|-----------|------|----------|
| Reconnaissance | T1595 | Active Scanning | Nmap | ✅ Suricata |
| Reconnaissance | T1046 | Network Service Scanning | Nmap | ✅ Suricata |
| Enumeration | T1135 | Network Share Discovery | CrackMapExec | ✅ Suricata |
| Enumeration | T1087 | Account Discovery | Nmap SMB scripts | ✅ Suricata |
| Credential Access | T1110 | Brute Force | Hydra + Metasploit | ✅ Suricata + EID 4625 |
| Credential Access | T1557 | Adversary in the Middle | NTLM Capture | ✅ Suricata |
| Discovery | T1057 | Process Discovery | Atomic Red Team | ✅ Sysmon EID 1 |
| Discovery | T1087.001 | Local Account Discovery | Atomic Red Team | ✅ Sysmon EID 1 |
| Execution | T1059.001 | PowerShell | Atomic Red Team | ✅ Sysmon EID 1 |
| Credential Access | T1003.001 | LSASS Dump | Atomic Red Team | ✅ Sysmon EID 10 |

---

## Key Splunk Queries

**All Suricata Alerts:**
```
index=suricata event_type=alert | table timestamp src_ip dest_ip alert.signature alert.severity | sort -timestamp
```

**SMB Attack Detection:**
```
index=suricata event_type=alert app_proto=smb | table timestamp src_ip dest_ip alert.signature direction | sort -timestamp
```

**Brute Force Detection:**
```
index=wineventlog EventCode=4625 | stats count by src_ip user | sort -count
```

**Sysmon Process Creation:**
```
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Image>(?<Image>[^<]+)</Image>"
| rex field=_raw "<CommandLine>(?<CommandLine>[^<]+)</CommandLine>"
| where NOT match(Image, "splunk")
| table _time Image CommandLine User
| sort -_time
```

**Full Attack Timeline:**
```
index=suricata OR index=wineventlog (EventCode=4625 OR EventCode=4624 OR event_type=alert)
| table _time src_ip dest_ip alert.signature EventCode user
| sort -_time
```

---

## Detection Coverage

| Tactic | Detection Method | Source |
|--------|-----------------|--------|
| Reconnaissance | ET SCAN signatures, ICMP detection | Suricata |
| Network Scanning | SMB malformed request detection | Suricata |
| Brute Force | NTLM auth attempt signatures | Suricata |
| Failed Logins | EventID 4625 threshold alerting | Windows/Splunk |
| Process Creation | Sysmon EID 1 | Sysmon/Splunk |
| Credential Dumping | Sysmon EID 10 (LSASS access) | Sysmon/Splunk |
| PowerShell Abuse | Sysmon EID 1 + script block logging | Sysmon/Splunk |
| Firewall Activity | pfSense syslog allow/deny | pfSense/Splunk |

---

## Skills Demonstrated

- Network segmentation and VLAN design using pfSense on a Linux host
- VMware Workstation homelab design and configuration
- Suricata IDS deployment, rule management and alert tuning
- Splunk log ingestion, indexing and correlation across multiple sources
- Sysmon deployment and configuration for endpoint visibility
- pfSense syslog forwarding to Splunk for network-layer detection
- Active Directory administration and attack surface awareness
- Offensive security using Kali Linux, Hydra, and Metasploit
- MITRE ATT&CK technique simulation using Atomic Red Team
- End-to-end SOC workflow: attack simulation → detection → investigation

---

## Upcoming Additions

- [ ] Phase 4 — Exploitation (EternalBlue MS17-010)
- [ ] Phase 5 — Post Exploitation (Mimikatz credential dumping)
- [ ] Splunk custom dashboards with attack timeline visualization
- [ ] BloodHound Active Directory attack path mapping
- [ ] Windows 10 endpoint added to domain with Sysmon

---

## References

- [Suricata Documentation](https://docs.suricata.io)
- [Splunk Documentation](https://docs.splunk.com)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam)
