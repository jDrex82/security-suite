# INTEGRATION GUIDE
## Adding New Advanced Tools to Your Security Suite

---

## 📦 Package Contents

**New Tools (3):**
1. `network_traffic_monitor.py` - 28KB - Real-time network traffic analysis
2. `ransomware_detector.py` - 28KB - Behavioral ransomware detection  
3. `ad_monitor.py` - 25KB - Active Directory security monitoring

**Documentation:**
- `NEW_TOOLS_README.md` - Comprehensive documentation
- `INTEGRATION_GUIDE.md` - This file

---

## 🚀 Quick Integration Steps

### Step 1: Add to Existing Suite

```bash
# If you have the complete_security_suite_v2 structure:
cd complete_security_suite_v2/

# Create new directory for advanced tools
mkdir -p advanced/

# Copy new tools
cp network_traffic_monitor.py advanced/
cp ransomware_detector.py advanced/
cp ad_monitor.py advanced/

# Copy for cross-platform (both in linux/ and windows/)
cp network_traffic_monitor.py linux/
cp ransomware_detector.py linux/
cp ransomware_detector.py windows/
cp network_traffic_monitor.py windows/
cp ad_monitor.py windows/  # Windows-only
```

### Step 2: Create Unified Launcher (Optional)

Create `advanced_security_launcher.sh` (Linux) or `advanced_security_launcher.bat` (Windows):

**Linux (`advanced_security_launcher.sh`):**
```bash
#!/bin/bash

echo "================================"
echo "Advanced Security Suite Launcher"
echo "================================"
echo ""
echo "1. Network Traffic Monitor"
echo "2. Ransomware Detector"
echo "3. Active Directory Monitor (Windows)"
echo "4. Run All (Background)"
echo "5. Exit"
echo ""
read -p "Select option: " choice

case $choice in
    1)
        python3 network_traffic_monitor.py --monitor --duration 3600
        ;;
    2)
        python3 ransomware_detector.py --monitor --duration 3600 --interval 60
        ;;
    3)
        echo "Active Directory Monitor is Windows-only"
        ;;
    4)
        echo "Starting all tools in background..."
        python3 network_traffic_monitor.py --monitor --duration 86400 --export ntm_results.json &
        python3 ransomware_detector.py --monitor --duration 86400 --interval 300 --export rbd_results.json &
        echo "Tools running in background. Check *_results.json for output."
        ;;
    5)
        exit 0
        ;;
esac
```

**Windows (`advanced_security_launcher.bat`):**
```batch
@echo off
echo ================================
echo Advanced Security Suite Launcher
echo ================================
echo.
echo 1. Network Traffic Monitor
echo 2. Ransomware Detector
echo 3. Active Directory Monitor
echo 4. Run All (Background)
echo 5. Exit
echo.
set /p choice="Select option: "

if "%choice%"=="1" (
    python network_traffic_monitor.py --monitor --duration 3600
)
if "%choice%"=="2" (
    python ransomware_detector.py --monitor --duration 3600 --interval 60
)
if "%choice%"=="3" (
    python ad_monitor.py --scan
)
if "%choice%"=="4" (
    echo Starting all tools in background...
    start /B python network_traffic_monitor.py --monitor --duration 86400 --export ntm_results.json
    start /B python ransomware_detector.py --monitor --duration 86400 --interval 300 --export rbd_results.json
    start /B python ad_monitor.py --scan --export adsm_results.json
    echo Tools running in background. Check *_results.json for output.
)
if "%choice%"=="5" (
    exit
)
```

---

## 📋 Deployment Scenarios

### Scenario 1: Complete Monitoring (24/7)

**For a single server with all tools:**

```bash
# Create systemd service (Linux) or Windows Task Scheduler job

# network-traffic-monitor.service
[Unit]
Description=Network Traffic Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/security-suite/network_traffic_monitor.py --monitor --duration 86400 --export /var/log/security/ntm.json
Restart=always

[Install]
WantedBy=multi-user.target

# ransomware-detector.service
[Unit]
Description=Ransomware Behavior Detector
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/security-suite/ransomware_detector.py --monitor --duration 86400 --interval 300 --export /var/log/security/rbd.json
Restart=always

[Install]
WantedBy=multi-user.target
```

**Windows Task Scheduler:**
```powershell
# Create scheduled tasks
schtasks /create /tn "NetworkTrafficMonitor" /tr "python C:\SecuritySuite\network_traffic_monitor.py --monitor --duration 86400" /sc daily /st 00:00 /ru SYSTEM

schtasks /create /tn "RansomwareDetector" /tr "python C:\SecuritySuite\ransomware_detector.py --monitor --duration 86400 --interval 300" /sc daily /st 00:00 /ru SYSTEM

schtasks /create /tn "ADMonitor" /tr "python C:\SecuritySuite\ad_monitor.py --scan --export C:\Logs\adsm.json" /sc hourly /ru SYSTEM
```

### Scenario 2: SIEM Integration

**Centralized logging via cron (Linux):**

```bash
# Add to /etc/cron.d/security-monitoring

# Network Traffic Monitor - every 30 minutes
*/30 * * * * root python3 /opt/security-suite/network_traffic_monitor.py --scan --export /var/log/security/ntm_$(date +\%Y\%m\%d_\%H\%M).json

# Ransomware Detector - every 15 minutes
*/15 * * * * root python3 /opt/security-suite/ransomware_detector.py --scan --export /var/log/security/rbd_$(date +\%Y\%m\%d_\%H\%M).json

# AD Monitor - every hour (Windows DC only)
0 * * * * Administrator python C:\SecuritySuite\ad_monitor.py --scan --export C:\Logs\Security\adsm_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%.json
```

**Then configure log shipper (Splunk, ELK, etc.):**
```bash
# Example: Filebeat configuration for ELK
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/security/ntm_*.json
    - /var/log/security/rbd_*.json
    - /var/log/security/adsm_*.json
  json.keys_under_root: true
  json.add_error_key: true
  tags: ["security", "advanced-suite"]
```

### Scenario 3: Healthcare / Critical Infrastructure

**Recommended configuration for high-security environments:**

```yaml
# Configuration file: security_config.yaml

network_traffic_monitor:
  mode: continuous
  duration: 86400  # 24 hours
  interval: 10  # Check every 10 seconds
  export: /var/log/security/ntm/ntm_$(date).json
  alert_on:
    - CRITICAL
    - HIGH
  
ransomware_detector:
  mode: continuous
  duration: 86400
  interval: 60  # Check every minute for file changes
  monitored_paths:
    - /home
    - /var/www
    - /opt/medical-records  # Custom path
    - /mnt/patient-data     # Custom path
  export: /var/log/security/rbd/rbd_$(date).json
  
ad_monitor:
  mode: scheduled
  frequency: hourly
  baseline_update: weekly  # Update baseline every week
  export: /var/log/security/adsm/adsm_$(date).json
  monitored_groups:
    - Domain Admins
    - Healthcare Admins  # Custom group
    - HIPAA Compliance  # Custom group
```

---

## 🔗 Tool Interaction Matrix

How these tools complement your existing suite:

| Existing Tool | New Tool | Integration Point |
|--------------|----------|-------------------|
| **ssh_monitor** | network_traffic_monitor | Share network connection data |
| **fim** | ransomware_detector | File integrity + behavioral patterns |
| **ped** | ad_monitor | Local + domain privilege escalation |
| **pncm** | network_traffic_monitor | Process-level + network-level correlation |
| **port_scanner** | network_traffic_monitor | Outbound scanning + inbound detection |

### Example Correlation

```python
# Pseudo-code for alert correlation
if (fim.detect_mass_changes() AND 
    ransomware_detector.detect_high_entropy() AND
    network_traffic_monitor.detect_c2_traffic()):
    
    alert_severity = "CRITICAL"
    alert_type = "RANSOMWARE_WITH_C2"
    action = "IMMEDIATE_ISOLATION_REQUIRED"
```

---

## 📊 Monitoring Dashboard Setup

### Grafana Dashboard JSON

Create a unified dashboard that displays:

1. **Network Traffic Panel**
   - Active connections
   - Data transfer rates
   - Suspicious destinations

2. **Ransomware Indicators Panel**
   - File modification rate
   - High entropy file count
   - Shadow copy status

3. **AD Security Panel**
   - Group membership changes
   - GPO modifications
   - Failed authentication attempts

**Sample Prometheus metrics:**
```yaml
# Add to prometheus.yml
scrape_configs:
  - job_name: 'security_suite'
    static_configs:
      - targets: ['localhost:9090']
    file_sd_configs:
      - files:
        - '/var/log/security/ntm_*.json'
        - '/var/log/security/rbd_*.json'
        - '/var/log/security/adsm_*.json'
```

---

## 🎯 Testing & Validation

### Test Network Traffic Monitor

```bash
# Simulate suspicious traffic
# Test 1: Port scan detection (from another host)
nmap -sS -p 1-1000 [your-server-ip]

# Test 2: Suspicious port connection
nc -l 4444  # Metasploit port

# Test 3: Rapid connections
for i in {1..100}; do curl http://example.com & done
```

### Test Ransomware Detector

```bash
# Simulate mass file changes (SAFE TEST)
mkdir /tmp/ransomware-test
cd /tmp/ransomware-test
for i in {1..100}; do
    echo "test data" > file_$i.txt
    sleep 0.1
done

# Encrypt files (simulate ransomware behavior)
for f in *.txt; do
    openssl enc -aes-256-cbc -salt -in "$f" -out "$f.encrypted" -k testpassword
    rm "$f"
done

# RBD should detect:
# - Mass file modifications
# - Extension changes to .encrypted
# - High entropy in new files
```

### Test Active Directory Monitor

```powershell
# Create test baseline
python ad_monitor.py --baseline

# Simulate changes (as Domain Admin)
net group "Test Security Group" /add /domain
net group "Test Security Group" testuser /add /domain

# Run scan (should detect new group and member)
python ad_monitor.py --scan
```

---

## 🔧 Troubleshooting

### Network Traffic Monitor

**Issue**: "Permission denied" reading /proc/net
```bash
# Solution: Run with sudo or as root
sudo python3 network_traffic_monitor.py --scan
```

**Issue**: No alerts generated
```bash
# Check if traffic is being captured
python3 network_traffic_monitor.py --scan --interval 5
# Look for "Active connections" count
```

### Ransomware Detector

**Issue**: High false positive rate
```bash
# Adjust thresholds in script:
'rapid_file_changes': 100,  # Increase from 50
'entropy_threshold': 8.0,    # Increase from 7.5
```

**Issue**: Shadow copy check failing (Windows)
```powershell
# Ensure VSS service is running
Get-Service -Name VSS
Start-Service VSS
```

### Active Directory Monitor

**Issue**: "Not running as Administrator"
```powershell
# Run PowerShell as Administrator
# Or use runas:
runas /user:Administrator python ad_monitor.py --scan
```

**Issue**: PowerShell execution policy
```powershell
# Check policy
Get-ExecutionPolicy

# Set to RemoteSigned (if needed)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 📈 Performance Impact

| Tool | CPU Usage | Memory | Disk I/O | Network Impact |
|------|-----------|--------|----------|----------------|
| NTM | <5% | ~50MB | Low | Minimal (reads /proc) |
| RBD | <10% | ~100MB | Medium (file scanning) | None |
| ADSM | <5% | ~50MB | Low | Low (AD queries) |

**Optimization tips:**
- Run NTM with longer intervals on busy servers (30s instead of 10s)
- Exclude known-good directories in RBD (e.g., `/tmp`, build directories)
- Schedule ADSM during low-activity hours

---

## 🔐 Security Hardening

1. **Restrict log file access:**
```bash
chmod 600 /var/log/security/*.json
chown security:security /var/log/security/*.json
```

2. **Run with dedicated service account:**
```bash
useradd -r -s /bin/false security-monitor
# Run tools as security-monitor user
```

3. **Enable log rotation:**
```bash
# /etc/logrotate.d/security-suite
/var/log/security/*.json {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
}
```

---

## 📚 Maintenance Schedule

| Task | Frequency | Tool |
|------|-----------|------|
| Update baselines | Weekly | NTM, ADSM |
| Review thresholds | Monthly | All |
| Test alerts | Monthly | All |
| Update documentation | Quarterly | - |
| Audit log retention | Quarterly | - |

---

## 🚨 Incident Response Playbook

### CRITICAL Alert: Ransomware Detected (RBD)

1. **Immediate Actions (< 5 minutes)**
   - Disconnect affected system from network
   - Do NOT shutdown or restart
   - Alert security team

2. **Investigation (< 30 minutes)**
   - Review RBD JSON export for affected files
   - Check NTM for C2 connections
   - Identify patient zero

3. **Containment (< 1 hour)**
   - Isolate affected network segment
   - Disable compromised accounts (ADSM findings)
   - Verify backup integrity

### CRITICAL Alert: C2 Traffic Detected (NTM)

1. **Immediate Actions**
   - Block destination IP at firewall
   - Isolate source system
   - Capture memory dump

2. **Investigation**
   - Review PNCM for suspicious processes
   - Check FIM for modified binaries
   - Analyze NTM export for full connection history

### CRITICAL Alert: Domain Admin Added (ADSM)

1. **Immediate Actions**
   - Verify legitimacy with change control
   - If unauthorized, disable account immediately
   - Review Kerberos tickets (ADSM)

2. **Investigation**
   - Check who made the change (Event ID 4728)
   - Review recent GPO changes
   - Scan for Golden Ticket indicators

---

## 📞 Support & Escalation

**For issues:**
1. Check troubleshooting section above
2. Review tool-specific README
3. Check log files for detailed errors

**For feature requests:**
- Submit issues via your internal ticketing system
- Include use case and expected behavior

---

## ✅ Deployment Checklist

- [ ] Tools copied to correct directories
- [ ] Execution permissions set (`chmod +x`)
- [ ] Initial baselines created (NTM, ADSM)
- [ ] Tested on non-production system
- [ ] Log rotation configured
- [ ] SIEM integration tested
- [ ] Alert thresholds tuned
- [ ] Incident response procedures documented
- [ ] Team trained on alert response
- [ ] Scheduled maintenance calendar created

---

**Integration Complete!** You now have a comprehensive security suite with:
- 12 original tools (SSH, FIM, PED, PNCM, Port Scanner, SSL, Web Log Analyzer)
- 3 new advanced tools (NTM, RBD, ADSM)
- **Total: 15 defensive security tools**

🛡️ **Full spectrum coverage**: Network → Host → Domain → Application
