# Advanced Security Monitoring Suite - New Tools

## 🚀 What's New

Three critical new tools that complete your defensive security arsenal:

1. **Network Traffic Monitor** (`network_traffic_monitor.py`) - Real-time traffic analysis
2. **Ransomware Behavior Detector** (`ransomware_detector.py`) - Behavioral ransomware detection
3. **Active Directory Monitor** (`ad_monitor.py`) - Enterprise AD security

---

## 🌐 Network Traffic Monitor (NTM)

### What It Does
Real-time network traffic analysis and anomaly detection without external dependencies.

### Key Features
- **Data Exfiltration Detection** - Tracks unusual outbound data volumes
- **C2 Beaconing Detection** - Identifies command & control communication patterns
- **Port Scan Detection** - Detects when YOUR system is being scanned
- **DNS Anomaly Detection** - Catches DNS tunneling and suspicious queries
- **Suspicious Port Detection** - Flags connections to hacker ports (4444, 1337, etc.)
- **Connection Rate Monitoring** - Detects rapid connection attempts

### Usage

```bash
# Create baseline of normal traffic
python network_traffic_monitor.py --baseline

# Monitor for 5 minutes with 10-second intervals
python network_traffic_monitor.py --monitor --duration 300 --interval 10

# One-time scan
python network_traffic_monitor.py --scan

# Export results to SIEM
python network_traffic_monitor.py --scan --export ntm_results.json
```

### Detection Capabilities

| Detection Type | Severity | Description |
|---------------|----------|-------------|
| Port Scan | HIGH | Detects scanning attempts targeting your system |
| C2 Pattern | CRITICAL | Identifies potential command & control traffic |
| Suspicious TLD | HIGH | Flags connections to .ru, .cn, .onion, etc. |
| Data Exfiltration | MEDIUM | Excessive outbound connections to single host |
| DNS Tunneling | HIGH | Detects DNS-based data exfiltration |
| Suspicious Ports | CRITICAL | Connections to Metasploit, IRC, Tor ports |

### How It Works
- Parses `/proc/net/tcp` and `/proc/net/udp` on Linux (no root required for basic features)
- Falls back to `netstat` for cross-platform compatibility
- Tracks connection patterns over time to detect anomalies
- Baseline comparison for deviation detection

### SIEM Integration
Export JSON format includes:
- Timestamp and severity for each alert
- Source/destination IPs and ports
- Alert type and detailed message
- Traffic statistics

---

## 🛡️ Ransomware Behavior Detector (RBD)

### What It Does
**Behavioral detection** of ransomware activity - catches zero-day ransomware that signature-based tools miss.

### Key Features
- **Mass Encryption Detection** - Identifies rapid file modification patterns
- **File Entropy Analysis** - Detects encrypted files by entropy measurement
- **Shadow Copy Monitoring** - Alerts on deletion attempts (Windows)
- **Backup Tampering Detection** - Monitors backup services and directories
- **Ransom Note Detection** - Identifies ransom note files
- **Extension Change Tracking** - Flags suspicious file extension changes

### Usage

```bash
# One-time scan (30-second file activity check)
python ransomware_detector.py --scan

# Continuous monitoring (5 minutes, 1-minute intervals)
python ransomware_detector.py --monitor --duration 300 --interval 60

# Monitor specific paths
python ransomware_detector.py --monitor --paths "C:\Users" "D:\Data"

# Export results
python ransomware_detector.py --scan --export rbd_results.json
```

### Detection Capabilities

| Detection Type | Threshold | Severity | Description |
|---------------|-----------|----------|-------------|
| Mass File Modification | 50 files/min | CRITICAL | Ransomware encryption in progress |
| High Entropy Files | >7.5 entropy | HIGH | Files showing encryption patterns |
| Extension Changes | Suspicious ext | CRITICAL | Files renamed to .encrypted, .locked, etc. |
| Shadow Copy Deletion | Any deletion | CRITICAL | Backup recovery prevention |
| Backup Service Stopped | Service down | HIGH | Ransomware disabling backups |
| Ransom Note Detected | File found | CRITICAL | Active ransomware confirmed |

### Monitored Paths (Default)
**Windows:**
- `C:\Users\[User]\Documents`
- `C:\Users\[User]\Desktop`
- `C:\Users\[User]\Pictures`
- `C:\Users\Public\Documents`

**Linux:**
- `~/Documents`, `~/Desktop`, `~/Pictures`
- `/home` (all user directories)

### How It Works
1. **Baseline Snapshot** - Takes initial snapshot of monitored files
2. **Periodic Checks** - Scans for modifications at specified intervals
3. **Entropy Analysis** - Measures file randomness (encrypted = high entropy)
4. **Pattern Detection** - Identifies ransomware behavior patterns
5. **Service Monitoring** - Tracks backup service status (Windows)

### Critical Indicators
If you see these alerts, **IMMEDIATELY**:
1. Disconnect from network
2. DO NOT restart the system
3. Contact incident response team
4. Preserve evidence (disk image if possible)

---

## 🏢 Active Directory Monitor (ADSM)

### What It Does
Enterprise-grade Active Directory security monitoring for detecting domain-level attacks.

### Key Features
- **Golden/Silver Ticket Detection** - Identifies forged Kerberos tickets
- **GPO Change Monitoring** - Tracks Group Policy Object modifications
- **Privilege Escalation Detection** - Monitors Domain Admin additions
- **Critical Group Tracking** - Watches Domain/Enterprise Admin groups
- **Kerberos Anomaly Detection** - Identifies suspicious ticket activity
- **Security Event Analysis** - Parses Windows Security logs for AD attacks

### Usage

```bash
# Create baseline (run on domain-joined Windows system)
python ad_monitor.py --baseline

# Run security scan
python ad_monitor.py --scan

# Export results for SIEM
python ad_monitor.py --scan --export adsm_results.json
```

### Requirements
- **Windows-only** (Active Directory environment)
- **Administrator privileges** required
- **Domain membership** required
- **PowerShell** execution policy allowing scripts

### Monitored Groups
- Domain Admins
- Enterprise Admins
- Schema Admins
- Backup Operators
- Account Operators
- DNSAdmins
- Group Policy Creator Owners

### Detection Capabilities

| Detection Type | Severity | Description |
|---------------|----------|-------------|
| Domain Admin Addition | CRITICAL | New member added to Domain Admins |
| GPO Modified | HIGH | Group Policy Object changed |
| GPO Deleted | HIGH | Group Policy Object removed |
| Weak Kerberos Encryption | HIGH | RC4/DES encryption detected (downgrade attack) |
| Excessive Failed Logons | HIGH | Brute force attempt detected |
| Admin Rights Assigned | MEDIUM | New admin privileges granted |

### How It Works
1. **Baseline Creation** - Captures current AD state (groups, GPOs, tickets)
2. **Group Enumeration** - Uses `net group /domain` to check memberships
3. **GPO Tracking** - PowerShell `Get-GPO` cmdlet for policy monitoring
4. **Kerberos Analysis** - Uses `klist` to examine active tickets
5. **Event Log Parsing** - Analyzes Security event log for suspicious IDs

### Security Event IDs Monitored
- `4624` - Account Logon
- `4625` - Failed Logon (brute force indicator)
- `4672` - Admin Rights Assigned
- `4768/4769/4770` - Kerberos Ticket Activity
- `4728/4732/4756` - Group Membership Changes
- `5136/5137/5141` - Directory Object Changes

---

## 📊 Comparison Matrix

| Feature | NTM | RBD | ADSM |
|---------|-----|-----|------|
| **Platform** | Linux/Windows | Linux/Windows | Windows Only |
| **Requires Root/Admin** | No (basic) | No (basic) | Yes |
| **Real-time Monitoring** | ✅ | ✅ | ✅ |
| **SIEM Export** | ✅ | ✅ | ✅ |
| **Zero Dependencies** | ✅ | ✅ | ✅ (uses built-in tools) |
| **Baseline Required** | Optional | No | Yes |
| **Best For** | Network attacks | Ransomware | AD environments |

---

## 🔧 Integration with Existing Suite

These tools complement your existing security suite:

| Your Existing Tools | New Tools | Coverage Gap Filled |
|--------------------|-----------|---------------------|
| PNCM (Process/Network) | NTM | **Live traffic analysis** vs. connection snapshots |
| FIM (File Integrity) | RBD | **Behavioral patterns** vs. individual file changes |
| PED (Privilege Escalation) | ADSM | **Domain-level** vs. local privilege tracking |
| SSH Monitor | NTM | **Network-wide** vs. SSH-specific |
| Port Scanner | NTM | **Inbound detection** vs. outbound scanning |

---

## 🚨 Alert Priority Guide

### CRITICAL (Immediate Action Required)
- **RBD**: Mass file encryption detected, shadow copies deleted, ransom note found
- **NTM**: C2 beaconing pattern, connection to Metasploit ports
- **ADSM**: Domain Admin group modified, GPO deleted

### HIGH (Investigate Within 1 Hour)
- **RBD**: High entropy files, backup service stopped
- **NTM**: Port scan detected, suspicious TLD connections
- **ADSM**: GPO modified, weak Kerberos encryption

### MEDIUM (Review Within 24 Hours)
- **RBD**: Backup directory missing
- **NTM**: Rapid connection rate, excessive connections to single host
- **ADSM**: Admin rights assigned, group member removed

---

## 📈 Recommended Deployment

### Healthcare / Critical Infrastructure
```bash
# Run all three on domain controller or security server
python network_traffic_monitor.py --monitor --duration 86400 &  # 24h monitoring
python ransomware_detector.py --monitor --duration 86400 --interval 300 &  # Check every 5min
python ad_monitor.py --scan  # Run hourly via scheduler
```

### SIEM Integration
```bash
# Automated export every hour
0 * * * * python network_traffic_monitor.py --scan --export /var/log/security/ntm_$(date +\%Y\%m\%d_\%H\%M).json
0 * * * * python ransomware_detector.py --scan --export /var/log/security/rbd_$(date +\%Y\%m\%d_\%H\%M).json
0 * * * * python ad_monitor.py --scan --export /var/log/security/adsm_$(date +\%Y\%m\%d_\%H\%M).json
```

---

## 🎯 Zero-Day Protection

These tools provide **behavioral detection**:

| Traditional Tools | These Tools |
|------------------|-------------|
| Signature-based (needs known threats) | **Behavior-based (catches unknowns)** |
| Reactive (after attack) | **Proactive (during attack)** |
| High false negatives | **Pattern matching reduces misses** |

**Example**: A brand new ransomware variant will:
- ❌ Bypass signature-based antivirus
- ✅ **Trigger RBD** (mass file changes, high entropy)
- ✅ **Trigger NTM** (C2 communication)
- ✅ **Trigger ADSM** (if domain-wide attack)

---

## 📝 Quick Start

### 1. Network Traffic Monitor
```bash
# First-time setup
python network_traffic_monitor.py --baseline
# Start monitoring
python network_traffic_monitor.py --monitor --duration 3600
```

### 2. Ransomware Detector
```bash
# No baseline needed - immediate detection
python ransomware_detector.py --monitor --duration 3600 --interval 60
```

### 3. Active Directory Monitor (Windows)
```powershell
# Run as Administrator
python ad_monitor.py --baseline
# Schedule hourly scans
python ad_monitor.py --scan
```

---

## 🔐 Security Best Practices

1. **Run NTM continuously** on critical servers
2. **Run RBD on file servers** and user workstations
3. **Run ADSM on domain controllers** (hourly scans)
4. **Export to centralized SIEM** for correlation
5. **Set up alerting** for CRITICAL severity events
6. **Review baselines** monthly for AD and network
7. **Test ransomware detection** with simulation tools

---

## 📚 Additional Resources

- **MITRE ATT&CK Coverage**: These tools detect techniques across multiple tactics (Initial Access, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement, Exfiltration, Impact)
- **Compliance**: Supports HIPAA, PCI-DSS, GDPR, SOC 2 requirements for monitoring and alerting
- **Incident Response**: JSON exports provide evidence for forensic analysis

---

## 🤝 Contributing

These tools are designed to be extensible:
- Add new detection patterns to `suspicious_patterns` lists
- Extend baseline tracking for additional AD objects
- Add custom thresholds for your environment

---

## ⚠️ Disclaimer

These tools are for **defensive security monitoring only**. Use responsibly and ensure you have authorization to monitor systems. Some features require administrative privileges - use the principle of least privilege.

---

**Total Suite**: 15 tools (12 original + 3 new)  
**Lines of Code**: ~8,500  
**External Dependencies**: Zero  
**Platform Support**: Windows & Linux  
**License**: MIT
