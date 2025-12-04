# Network Port Scanner & Service Detector

A professional multi-threaded network port scanner with service detection and vulnerability identification. Critical for infrastructure protection and network security auditing.

## 🎯 Perfect For

- **Critical Infrastructure Protection** - Discover exposed services
- **Healthcare Security (HIPAA)** - Audit network attack surface
- **Network Security Auditing** - Regular security assessments
- **Compliance Verification** - PCI-DSS, SOC 2 requirements
- **Incident Response** - Identify compromised systems
- **Asset Discovery** - Map network infrastructure

## ✨ Features

- ✅ **Multi-threaded Scanning** - Fast concurrent port checks
- ✅ **Service Detection** - Identify services via banner grabbing
- ✅ **Vulnerability Detection** - Flag known security issues
- ✅ **Common Ports Database** - Pre-configured service mappings
- ✅ **Custom Port Ranges** - Flexible scanning options
- ✅ **JSON Reporting** - Export for SIEM integration
- ✅ **Security Recommendations** - Actionable remediation advice
- ✅ **Zero Dependencies** - Pure Python 3 standard library

## 🚀 Quick Start

### Basic Scan
```bash
# Scan common ports on target
python3 port_scanner.py 192.168.1.1

# Scan specific domain
python3 port_scanner.py example.com
```

### Custom Port Ranges
```bash
# Scan specific port range
python3 port_scanner.py 192.168.1.1 -p 1-1000

# Scan specific ports
python3 port_scanner.py example.com -p 22,80,443,3306,5432

# Full port scan (all 65535 ports - SLOW!)
python3 port_scanner.py 10.0.0.1 --full
```

### Performance Tuning
```bash
# Fast scan with 100 threads
python3 port_scanner.py 192.168.1.1 -t 100

# Custom timeout for slow networks
python3 port_scanner.py 192.168.1.1 --timeout 3.0
```

### Export Results
```bash
# Export to JSON for analysis
python3 port_scanner.py 192.168.1.1 --export scan_report.json
```

## 📊 Sample Output

```
======================================================================
Network Port Scanner - Starting Scan
======================================================================
Target: example.com (93.184.216.34)
Ports: 29 ports
Threads: 50
Timeout: 1.0s
Started: 2025-10-30 14:23:45
======================================================================

[+] Port 22/tcp OPEN - SSH
    Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
[+] Port 80/tcp OPEN - HTTP
    Banner: HTTP/1.1 200 OK Server: nginx/1.18.0
[+] Port 443/tcp OPEN - HTTPS
[+] Port 3306/tcp OPEN - MySQL
    ⚠️  HIGH: Database ports exposed - restrict to localhost/VPN

======================================================================
Scan Report - example.com (93.184.216.34)
======================================================================

📊 SUMMARY
──────────────────────────────────────────────────────────────────────
Total open ports: 4
Unique services: 4
Vulnerabilities: 1

🔍 SERVICES DETECTED
──────────────────────────────────────────────────────────────────────
  SSH: 1 port(s)
  HTTP: 1 port(s)
  HTTPS: 1 port(s)
  MySQL: 1 port(s)

🔓 OPEN PORTS
──────────────────────────────────────────────────────────────────────
Port     State      Service              Detected       
──────────────────────────────────────────────────────────────────────
22       open       SSH                  SSH            
         Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
80       open       HTTP                 HTTP           
         Banner: HTTP/1.1 200 OK Server: nginx/1.18.0
443      open       HTTPS                Unknown        
3306     open       MySQL                MySQL          

⚠️  VULNERABILITIES DETECTED
──────────────────────────────────────────────────────────────────────
Port 3306/tcp (MySQL)
  HIGH: Database ports exposed - restrict to localhost/VPN

🔒 SECURITY RECOMMENDATIONS
──────────────────────────────────────────────────────────────────────
• HIGH: Database ports exposed - restrict to localhost/VPN
• MEDIUM: Implement HTTPS for all web services
```

## 🔍 What Gets Detected

### Service Identification
- SSH (port 22)
- FTP (ports 20, 21)
- Telnet (port 23)
- SMTP (ports 25, 587, 465)
- DNS (port 53)
- HTTP/HTTPS (ports 80, 443, 8080, 8443)
- Databases (MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis)
- Remote Access (RDP, VNC)
- SMB/Windows shares (port 445)
- Elasticsearch (port 9200)

### Known Vulnerabilities Flagged
```
CRITICAL: Telnet (port 23) - unencrypted communication
HIGH: FTP (port 21) - plaintext credentials
HIGH: SMB (port 445) - potential EternalBlue vulnerability
HIGH: Redis (port 6379) - often misconfigured without auth
HIGH: MongoDB (port 27017) - often exposed without auth
HIGH: Database ports - should not be publicly accessible
MEDIUM: HTTP (port 80) - unencrypted web traffic
MEDIUM: RDP (port 3389) - common brute force target
```

## 💡 Usage Examples

### Healthcare Environment
```bash
# Audit medical device network segment
python3 port_scanner.py 10.10.20.0/24 -p 22,80,443,3389,5900

# Check specific medical device
python3 port_scanner.py medical-device.hospital.local

# Export for compliance documentation
python3 port_scanner.py 192.168.100.50 --export hipaa_audit_$(date +%Y%m%d).json
```

### Critical Infrastructure
```bash
# Scan SCADA/ICS network
python3 port_scanner.py plc.factory.local -p 102,502,47808,20000,44818

# Check industrial control system
python3 port_scanner.py 10.0.50.10 -p 1-10000

# Quick security assessment
python3 port_scanner.py control-system.grid.local
```

### Web Application Security
```bash
# Check web server ports
python3 port_scanner.py webserver.example.com -p 80,443,8080,8443

# Scan common web services
python3 port_scanner.py api.example.com -p 80,443,3000,5000,8000,9000
```

### Regular Security Audits
```bash
# Weekly infrastructure scan
for server in $(cat production_servers.txt); do
    python3 port_scanner.py $server --export reports/${server}_$(date +%Y%m%d).json
done

# Compare against baseline
python3 port_scanner.py 192.168.1.1 --export current_scan.json
diff baseline_scan.json current_scan.json
```

## 🚨 Common Findings & Implications

### 1. Telnet (Port 23) Open
**Risk**: CRITICAL  
**Issue**: All traffic including passwords sent in plaintext  
**Fix**: Disable Telnet, use SSH instead  
```bash
sudo systemctl stop telnet
sudo systemctl disable telnet
```

### 2. FTP (Port 21) Open
**Risk**: HIGH  
**Issue**: Credentials transmitted in cleartext  
**Fix**: Use SFTP or FTPS  
```bash
# Disable FTP
sudo systemctl stop vsftpd
# Use SFTP (already available with SSH)
```

### 3. Database Ports Exposed
**Risk**: HIGH  
**Issue**: Direct database access from internet  
**Fix**: Restrict to localhost or VPN  
```bash
# MySQL - bind to localhost only
# Edit /etc/mysql/mysql.conf.d/mysqld.cnf
bind-address = 127.0.0.1

# Or use firewall
sudo ufw deny 3306
```

### 4. RDP (Port 3389) Exposed
**Risk**: MEDIUM  
**Issue**: Common brute force target  
**Fix**: VPN access only, enable Network Level Authentication  
```bash
# Restrict to specific IPs
sudo ufw allow from 192.168.1.0/24 to any port 3389
```

### 5. SMB (Port 445) Open
**Risk**: HIGH  
**Issue**: Vulnerable to EternalBlue and other exploits  
**Fix**: Disable if not needed, patch systems  
```bash
sudo systemctl stop smbd
sudo systemctl disable smbd
```

## 📁 File Structure

```
port_scanner.py         - Main scanner script
scan_report.json        - Example scan results (created with --export)
```

## 🔧 Command-Line Options

```
usage: port_scanner.py [-h] [-p PORTS] [-t THREADS] [--timeout TIMEOUT]
                       [--full] [--export EXPORT]
                       target

positional arguments:
  target               Target IP address or hostname

options:
  -h, --help           Show help message
  -p, --ports PORTS    Ports to scan: "common", "1-1000", or "22,80,443"
  -t, --threads INT    Number of threads (default: 50)
  --timeout FLOAT      Socket timeout in seconds (default: 1.0)
  --full               Scan all 65535 ports (SLOW!)
  --export FILE        Export results to JSON file
```

## 🎓 Advanced Usage

### Automated Security Scanning
```bash
#!/bin/bash
# Daily security scan script

TARGETS_FILE="critical_systems.txt"
OUTPUT_DIR="/var/security/scans"
DATE=$(date +%Y%m%d)

while read target; do
    echo "Scanning $target..."
    python3 port_scanner.py "$target" \
        --export "${OUTPUT_DIR}/${target}_${DATE}.json"
    
    # Alert on new open ports
    if [ -f "${OUTPUT_DIR}/${target}_previous.json" ]; then
        if ! diff -q "${OUTPUT_DIR}/${target}_${DATE}.json" \
                    "${OUTPUT_DIR}/${target}_previous.json" > /dev/null; then
            echo "ALERT: Port changes detected on $target" | \
                mail -s "Security Alert" security@company.com
        fi
    fi
    
    cp "${OUTPUT_DIR}/${target}_${DATE}.json" \
       "${OUTPUT_DIR}/${target}_previous.json"
done < "$TARGETS_FILE"
```

### Integration with SIEM
```python
#!/usr/bin/env python3
import subprocess
import json
import requests

# Run scan
result = subprocess.run(
    ['python3', 'port_scanner.py', '192.168.1.1', '--export', '/tmp/scan.json'],
    capture_output=True
)

# Load results
with open('/tmp/scan.json', 'r') as f:
    scan_data = json.load(f)

# Send to SIEM
requests.post(
    'https://siem.company.com/api/scans',
    json=scan_data,
    headers={'Authorization': 'Bearer YOUR_TOKEN'}
)
```

### Subnet Scanning
```bash
# Scan entire subnet (requires nmap for host discovery)
nmap -sn 192.168.1.0/24 | grep "Nmap scan report" | awk '{print $5}' | \
while read ip; do
    python3 port_scanner.py "$ip" --export "scans/${ip}.json"
done
```

## ⚠️ Important Notes

### Performance
- Default 50 threads balances speed and accuracy
- Increase threads (-t 100) for faster scanning of large port ranges
- Decrease timeout (--timeout 0.5) for local network scans
- Full scans (--full) can take 10+ minutes per host

### Legal & Ethical Considerations
- **Only scan systems you own or have permission to test**
- Unauthorized port scanning may violate laws and policies
- Some networks/firewalls may flag scanning as attack behavior
- Use responsibly for legitimate security purposes only

### Accuracy
- Firewalls may silently drop packets (timeout vs. closed)
- Some services may not respond to banner requests
- Service detection is best-effort based on common signatures
- IDS/IPS may detect and block scanning attempts

## 🤝 Integration Examples

### With Vulnerability Scanner
```bash
# First discover open ports
python3 port_scanner.py target.com --export open_ports.json

# Then run vulnerability scan on open ports only
python3 vuln_scanner.py --input open_ports.json
```

### With Configuration Management
```bash
# Ansible playbook to scan all inventory hosts
- name: Security port scan
  shell: python3 /usr/local/bin/port_scanner.py {{ inventory_hostname }}
  register: scan_result
  
- name: Alert on unexpected ports
  mail:
    subject: "Unexpected open ports on {{ inventory_hostname }}"
    body: "{{ scan_result.stdout }}"
  when: scan_result.rc != 0
```

### With Monitoring Systems
```bash
# Nagios check
python3 port_scanner.py $HOSTADDRESS$ -p 22,80,443
if [ $? -eq 0 ]; then
    echo "OK - Expected ports open"
    exit 0
else
    echo "CRITICAL - Unexpected port configuration"
    exit 2
fi
```

## 📚 References

- NIST SP 800-115 (Technical Guide to Information Security Testing)
- OWASP Testing Guide (Infrastructure Configuration Management Testing)
- CIS Controls v8 (Secure Configuration for Network Devices)
- PCI-DSS Requirement 2.2 (Unnecessary services should be disabled)

## 📄 License

MIT License - Use freely for security assessments

## 👨‍💻 Author

Created for cybersecurity professionals, system administrators, and infrastructure teams.

---

**Remember**: Always obtain proper authorization before scanning any network or system. Port scanning without permission may be illegal in your jurisdiction.
