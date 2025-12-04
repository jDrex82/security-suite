# Windows/Linux Mixed Environment Deployment Guide
## Complete Security Monitoring Toolkit

**Version 2.0** - Cross-Platform Edition  
**Last Updated:** November 2025

---

## Table of Contents

1. [Overview](#overview)
2. [Platform Compatibility Matrix](#platform-compatibility-matrix)
3. [Prerequisites](#prerequisites)
4. [Windows Installation](#windows-installation)
5. [Linux Installation](#linux-installation)
6. [Quick Start Guide](#quick-start-guide)
7. [Tool-Specific Deployment](#tool-specific-deployment)
8. [Cross-Platform Considerations](#cross-platform-considerations)
9. [Centralized Monitoring Setup](#centralized-monitoring-setup)
10. [Automation & Scheduling](#automation--scheduling)
11. [SIEM Integration](#siem-integration)
12. [Troubleshooting](#troubleshooting)
13. [Best Practices](#best-practices)
14. [Security Hardening](#security-hardening)

---

## Overview

This toolkit provides comprehensive security monitoring capabilities for both Windows and Linux environments. The suite includes:

### Cross-Platform Tools (Work on Both Windows & Linux)
- **Port Scanner** - Network port scanning and service detection
- **SSL Monitor** - SSL/TLS certificate monitoring and expiration tracking
- **Web Log Analyzer** - Web server log analysis for attack detection

### Platform-Specific Tools

**Windows**
- **Event Log Monitor** (ssh_monitor_windows.py) - Security event log analysis
- **File Integrity Monitor** (fim_windows.py) - Windows file system monitoring
- **Privilege Escalation Detector** (ped_windows.py) - Windows privilege monitoring
- **Process & Network Monitor** (pncm_windows.py) - Windows process/network analysis

**Linux**
- **SSH Monitor** (ssh_monitor.py) - SSH authentication monitoring
- **File Integrity Monitor** (fim.py) - Linux file system monitoring
- **Privilege Escalation Detector** (ped.py) - Linux privilege monitoring
- **Process & Network Monitor** (pncm.py) - Linux process/network analysis

---

## Platform Compatibility Matrix

| Tool | Windows | Linux | macOS | Requires Admin | External Dependencies |
|------|---------|-------|-------|----------------|----------------------|
| port_scanner.py | ✅ | ✅ | ✅ | No | None |
| ssl_monitor.py | ✅ | ✅ | ✅ | No | None |
| web_log_analyzer.py | ✅ | ✅ | ✅ | No | None |
| ssh_monitor_windows.py | ✅ | ❌ | ❌ | Yes | pywin32 (optional) |
| fim_windows.py | ✅ | ❌ | ❌ | Yes | pywin32 (optional) |
| ped_windows.py | ✅ | ❌ | ❌ | Yes | None |
| pncm_windows.py | ✅ | ❌ | ❌ | Yes | None |
| ssh_monitor.py | ❌ | ✅ | ✅ | Yes | None |
| fim.py | ❌ | ✅ | ✅ | Yes | None |
| ped.py | ❌ | ✅ | ✅ | Yes | None |
| pncm.py | ❌ | ✅ | ✅ | Yes | None |

---

## Prerequisites

### Common Requirements (Both Platforms)
- Python 3.6 or higher
- Administrator/root privileges for system monitoring tools
- Sufficient disk space for logs and baselines (minimum 100MB recommended)

### Windows-Specific
- Windows 10/11 or Windows Server 2016/2019/2022
- PowerShell 5.1 or higher
- Optional: pywin32 for enhanced Windows Event Log access
  ```powershell
  pip install pywin32
  ```

### Linux-Specific
- Modern Linux distribution (Ubuntu 20.04+, RHEL 8+, Debian 11+, etc.)
- Access to system logs in `/var/log/`
- Optional: systemd for service management

---

## Windows Installation

### Method 1: Manual Installation

1. **Download and Extract**
   ```powershell
   # Extract the toolkit
   Expand-Archive -Path complete_security_suite.zip -DestinationPath C:\SecurityTools
   cd C:\SecurityTools\complete_security_suite
   ```

2. **Verify Python Installation**
   ```powershell
   python --version
   # Should show Python 3.6 or higher
   ```

3. **Install Optional Dependencies**
   ```powershell
   # For enhanced Windows Event Log monitoring
   pip install pywin32
   
   # For WMI alternative method
   pip install wmi
   ```

4. **Test Installation**
   ```powershell
   # Test cross-platform tool
   python port_scanner.py 127.0.0.1 -p 80,443
   
   # Test Windows tool (requires Administrator)
   python fim_windows.py --create-baseline
   ```

### Method 2: Using the Launcher

1. **Extract and Launch**
   ```powershell
   cd C:\SecurityTools\complete_security_suite
   
   # Right-click security_suite_launcher.bat
   # Select "Run as Administrator"
   ```

2. **Use Interactive Menu**
   - The launcher provides an easy-to-use menu system
   - Automatically checks for Python and dependencies
   - Guides you through tool selection

### Windows Deployment Script

Create `deploy_windows.ps1`:

```powershell
# Windows Deployment Script for Security Monitoring Toolkit

# Set execution policy (run once as admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Create directories
$InstallPath = "C:\SecurityTools"
$LogPath = "C:\SecurityTools\Logs"
New-Item -ItemType Directory -Force -Path $InstallPath
New-Item -ItemType Directory -Force -Path $LogPath

# Extract toolkit
Expand-Archive -Path ".\complete_security_suite.zip" -DestinationPath $InstallPath -Force

# Install Python dependencies
pip install pywin32
pip install wmi

# Create scheduled task for monitoring
$Action = New-ScheduledTaskAction -Execute "python" -Argument "$InstallPath\fim_windows.py --check" -WorkingDirectory $InstallPath
$Trigger = New-ScheduledTaskTrigger -Daily -At 2am
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "SecurityMonitoring-FIM" -Action $Action -Trigger $Trigger -Principal $Principal

Write-Host "Installation complete!" -ForegroundColor Green
Write-Host "Toolkit installed to: $InstallPath" -ForegroundColor Yellow
```

---

## Linux Installation

### Method 1: Manual Installation

1. **Download and Extract**
   ```bash
   unzip complete_security_suite.zip
   cd complete_security_suite
   chmod +x *.py *.sh
   ```

2. **Verify Python Installation**
   ```bash
   python3 --version
   # Should show Python 3.6 or higher
   ```

3. **Test Installation**
   ```bash
   # Test cross-platform tool
   python3 port_scanner.py 127.0.0.1 -p 80,443
   
   # Test Linux tool (requires sudo)
   sudo python3 fim.py --create-baseline
   ```

### Method 2: Using Quick Start Script

```bash
chmod +x QUICKSTART.sh
sudo ./QUICKSTART.sh
```

### Linux Deployment Script

Create `deploy_linux.sh`:

```bash
#!/bin/bash
# Linux Deployment Script for Security Monitoring Toolkit

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root or with sudo"
    exit 1
fi

# Set installation paths
INSTALL_DIR="/opt/security-monitoring"
LOG_DIR="/var/log/security-monitoring"
CONFIG_DIR="/etc/security-monitoring"

# Create directories
mkdir -p $INSTALL_DIR
mkdir -p $LOG_DIR
mkdir -p $CONFIG_DIR

# Extract and set permissions
unzip -o complete_security_suite.zip -d $INSTALL_DIR
chmod +x $INSTALL_DIR/*.py
chmod +x $INSTALL_DIR/*.sh

# Create systemd service for FIM
cat > /etc/systemd/system/fim-monitor.service << 'EOF'
[Unit]
Description=File Integrity Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/security-monitoring
ExecStart=/usr/bin/python3 /opt/security-monitoring/fim.py --monitor --interval 300
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable fim-monitor.service

# Create cron jobs
cat > /etc/cron.d/security-monitoring << 'EOF'
# SSH Monitor - Every 6 hours
0 */6 * * * root /usr/bin/python3 /opt/security-monitoring/ssh_monitor.py > /var/log/security-monitoring/ssh-monitor.log 2>&1

# Privilege Escalation Detection - Daily at 2 AM
0 2 * * * root /usr/bin/python3 /opt/security-monitoring/ped.py --check > /var/log/security-monitoring/ped.log 2>&1

# Process Monitor - Every 4 hours
0 */4 * * * root /usr/bin/python3 /opt/security-monitoring/pncm.py --check > /var/log/security-monitoring/pncm.log 2>&1
EOF

echo "Installation complete!"
echo "Toolkit installed to: $INSTALL_DIR"
echo "Logs will be written to: $LOG_DIR"
```

---

## Quick Start Guide

### Windows Quick Start

1. **Open Command Prompt as Administrator**
2. **Navigate to toolkit directory**
3. **Run the launcher:**
   ```cmd
   security_suite_launcher.bat
   ```

### Linux Quick Start

1. **Open Terminal**
2. **Navigate to toolkit directory**
3. **Run with sudo:**
   ```bash
   sudo ./QUICKSTART.sh
   ```

### First-Time Setup (Both Platforms)

1. **Create Baselines** (Required before monitoring)
   
   **Windows:**
   ```cmd
   python fim_windows.py --create-baseline
   python ped_windows.py --create-baseline
   python pncm_windows.py --create-baseline
   ```
   
   **Linux:**
   ```bash
   sudo python3 fim.py --create-baseline
   sudo python3 ped.py --create-baseline
   sudo python3 pncm.py --create-baseline
   ```

2. **Run Initial Checks**
   
   **Windows:**
   ```cmd
   python ssh_monitor_windows.py --last-hours 24
   python fim_windows.py --check
   ```
   
   **Linux:**
   ```bash
   sudo python3 ssh_monitor.py
   sudo python3 fim.py --check
   ```

---

## Tool-Specific Deployment

### Cross-Platform Tools

#### Port Scanner
**Use Case:** Network reconnaissance, vulnerability assessment

**Windows:**
```powershell
python port_scanner.py 192.168.1.1 -p 1-1000
python port_scanner.py internal-server.local --common-ports
```

**Linux:**
```bash
python3 port_scanner.py 192.168.1.1 -p 1-1000
python3 port_scanner.py internal-server.local --common-ports
```

#### SSL Monitor
**Use Case:** Certificate expiration tracking, TLS configuration audit

**Windows:**
```powershell
python ssl_monitor.py example.com
python ssl_monitor.py example.com --export ssl-report.json
```

**Linux:**
```bash
python3 ssl_monitor.py example.com
python3 ssl_monitor.py example.com --export ssl-report.json
```

#### Web Log Analyzer
**Use Case:** Attack pattern detection, traffic analysis

**Windows:**
```powershell
python web_log_analyzer.py C:\inetpub\logs\LogFiles\access.log
```

**Linux:**
```bash
python3 web_log_analyzer.py /var/log/nginx/access.log
python3 web_log_analyzer.py /var/log/apache2/access.log
```

### Windows-Specific Tools

#### Event Log Monitor
**Deployment:**
```powershell
# One-time analysis
python ssh_monitor_windows.py --last-hours 24

# Export for SIEM integration
python ssh_monitor_windows.py --last-hours 48 --export security-events.json

# Scheduled task
schtasks /create /tn "SecurityEventMonitor" /tr "python C:\SecurityTools\ssh_monitor_windows.py --last-hours 24 --export C:\Logs\events.json" /sc daily /st 02:00 /ru SYSTEM
```

#### File Integrity Monitor (Windows)
**Deployment:**
```powershell
# Initial baseline
python fim_windows.py --create-baseline

# Regular checks via Task Scheduler
python fim_windows.py --check --export C:\Logs\fim-changes.json

# Continuous monitoring
python fim_windows.py --monitor --interval 60
```

#### Privilege Escalation Detector (Windows)
**Deployment:**
```powershell
# Create baseline
python ped_windows.py --create-baseline

# Daily checks via Task Scheduler
schtasks /create /tn "PrivilegeMonitor" /tr "python C:\SecurityTools\ped_windows.py --check --export C:\Logs\priv-changes.json" /sc daily /st 03:00 /ru SYSTEM
```

### Linux-Specific Tools

#### SSH Monitor
**Deployment:**
```bash
# One-time analysis
sudo python3 ssh_monitor.py

# Follow mode (real-time)
sudo python3 ssh_monitor.py --follow

# Cron job for regular monitoring
echo "0 */6 * * * root /usr/bin/python3 /opt/security-monitoring/ssh_monitor.py > /var/log/ssh-monitor.log 2>&1" >> /etc/cron.d/security-monitoring
```

#### File Integrity Monitor (Linux)
**Deployment:**
```bash
# Initial baseline
sudo python3 fim.py --create-baseline

# Regular checks via cron
echo "0 2 * * * root /usr/bin/python3 /opt/security-monitoring/fim.py --check --export /var/log/fim-changes.json" >> /etc/cron.d/security-monitoring

# Continuous monitoring with systemd
systemctl start fim-monitor.service
systemctl enable fim-monitor.service
```

---

## Cross-Platform Considerations

### File Path Differences

**Windows:**
- Use backslashes: `C:\SecurityTools\logs\output.json`
- Or forward slashes: `C:/SecurityTools/logs/output.json`
- Environment variables: `%USERPROFILE%`, `%SystemRoot%`

**Linux:**
- Use forward slashes: `/opt/security-monitoring/logs/output.json`
- Environment variables: `$HOME`, `$USER`

### Privilege Requirements

**Windows:**
- Run Command Prompt or PowerShell as Administrator
- Right-click → "Run as Administrator"
- UAC prompt will appear

**Linux:**
- Use `sudo` command
- Or switch to root: `su -`
- Configure passwordless sudo for automation (with caution)

### Log File Locations

**Windows:**
- Event Logs: Accessed via API (not files)
- IIS Logs: `C:\inetpub\logs\LogFiles\`
- Application Logs: `C:\ProgramData\[Application]\Logs\`

**Linux:**
- System Logs: `/var/log/`
- SSH Logs: `/var/log/auth.log` or `/var/log/secure`
- Web Server: `/var/log/nginx/` or `/var/log/apache2/`

---

## Centralized Monitoring Setup

### Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│           Centralized SIEM/Log Server              │
│  (Splunk, ELK Stack, Graylog, Windows Event       │
│   Collector, syslog-ng)                            │
└─────────────────────────────────────────────────────┘
                        ▲
                        │ JSON Exports
                        │ Syslog Forwarding
         ┌──────────────┴──────────────┐
         │                             │
┌────────▼───────────┐        ┌───────▼────────────┐
│  Windows Servers   │        │   Linux Servers    │
│                    │        │                    │
│  - Event Monitor   │        │  - SSH Monitor     │
│  - FIM Windows     │        │  - FIM Linux       │
│  - PED Windows     │        │  - PED Linux       │
│  - PNCM Windows    │        │  - PNCM Linux      │
└────────────────────┘        └────────────────────┘
```

### JSON Export Strategy

All tools support `--export` for JSON output, enabling easy integration:

**Windows Example:**
```powershell
# Schedule hourly exports
python fim_windows.py --check --export C:\Logs\fim\fim-$(Get-Date -Format 'yyyyMMdd-HHmmss').json
```

**Linux Example:**
```bash
# Schedule hourly exports
python3 fim.py --check --export /var/log/security/fim-$(date +%Y%m%d-%H%M%S).json
```

### Syslog Integration (Linux)

Configure rsyslog to forward security monitoring results:

```bash
# /etc/rsyslog.d/security-monitoring.conf
# Forward all security monitoring logs to central server
if $programname contains 'security-monitoring' then @@siem-server.example.com:514
```

### Windows Event Forwarding

Configure Windows Event Forwarding to send Event Logs to a central collector:

```powershell
# On source computers
winrm quickconfig
wecutil qc

# On collector server
# Create subscription via Event Viewer → Subscriptions
```

---

## Automation & Scheduling

### Windows Task Scheduler

**Create automated monitoring tasks:**

```powershell
# FIM - Daily at 2 AM
$Action = New-ScheduledTaskAction -Execute "python.exe" `
    -Argument "C:\SecurityTools\fim_windows.py --check --export C:\Logs\fim.json" `
    -WorkingDirectory "C:\SecurityTools"
$Trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "Security-FIM-Check" -Action $Action -Trigger $Trigger -Principal $Principal -Description "File Integrity Monitor Daily Check"

# PED - Daily at 3 AM
$Action = New-ScheduledTaskAction -Execute "python.exe" `
    -Argument "C:\SecurityTools\ped_windows.py --check --export C:\Logs\ped.json" `
    -WorkingDirectory "C:\SecurityTools"
$Trigger = New-ScheduledTaskTrigger -Daily -At "03:00"
Register-ScheduledTask -TaskName "Security-PED-Check" -Action $Action -Trigger $Trigger -Principal $Principal -Description "Privilege Escalation Detection Daily Check"

# PNCM - Every 4 hours
$Action = New-ScheduledTaskAction -Execute "python.exe" `
    -Argument "C:\SecurityTools\pncm_windows.py --check --export C:\Logs\pncm.json" `
    -WorkingDirectory "C:\SecurityTools"
$Trigger = New-ScheduledTaskTrigger -Once -At "00:00" -RepetitionInterval (New-TimeSpan -Hours 4) -RepetitionDuration ([TimeSpan]::MaxValue)
Register-ScheduledTask -TaskName "Security-PNCM-Check" -Action $Action -Trigger $Trigger -Principal $Principal -Description "Process Network Monitor Every 4 Hours"

# Event Log Monitor - Every 6 hours
$Action = New-ScheduledTaskAction -Execute "python.exe" `
    -Argument "C:\SecurityTools\ssh_monitor_windows.py --last-hours 6 --export C:\Logs\events.json" `
    -WorkingDirectory "C:\SecurityTools"
$Trigger = New-ScheduledTaskTrigger -Once -At "00:00" -RepetitionInterval (New-TimeSpan -Hours 6) -RepetitionDuration ([TimeSpan]::MaxValue)
Register-ScheduledTask -TaskName "Security-EventLog-Monitor" -Action $Action -Trigger $Trigger -Principal $Principal -Description "Windows Event Log Monitor Every 6 Hours"
```

### Linux Cron Jobs

**Create cron schedule:**

```bash
# Edit root crontab
sudo crontab -e

# Add these lines:

# SSH Monitor - Every 6 hours
0 */6 * * * /usr/bin/python3 /opt/security-monitoring/ssh_monitor.py --export /var/log/security/ssh-$(date +\%Y\%m\%d-\%H\%M\%S).json

# FIM - Daily at 2 AM
0 2 * * * /usr/bin/python3 /opt/security-monitoring/fim.py --check --export /var/log/security/fim-$(date +\%Y\%m\%d-\%H\%M\%S).json

# PED - Daily at 3 AM
0 3 * * * /usr/bin/python3 /opt/security-monitoring/ped.py --check --export /var/log/security/ped-$(date +\%Y\%m\%d-\%H\%M\%S).json

# PNCM - Every 4 hours
0 */4 * * * /usr/bin/python3 /opt/security-monitoring/pncm.py --check --export /var/log/security/pncm-$(date +\%Y\%m\%d-\%H\%M\%S).json
```

### Linux Systemd Services

**Create systemd service for continuous monitoring:**

```bash
# /etc/systemd/system/security-fim.service
[Unit]
Description=File Integrity Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/security-monitoring
ExecStart=/usr/bin/python3 fim.py --monitor --interval 300
Restart=always
RestartSec=10
StandardOutput=append:/var/log/security/fim-service.log
StandardError=append:/var/log/security/fim-service-error.log

[Install]
WantedBy=multi-user.target
```

**Enable and start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable security-fim.service
sudo systemctl start security-fim.service
sudo systemctl status security-fim.service
```

---

## SIEM Integration

### Splunk Integration

**Windows Universal Forwarder:**
```powershell
# Install Splunk Universal Forwarder
# Configure inputs.conf

[monitor://C:\SecurityTools\Logs\*.json]
sourcetype = security:monitoring:json
index = security

[monitor://C:\SecurityTools\Logs\fim-*.json]
sourcetype = security:fim
index = security

[monitor://C:\SecurityTools\Logs\ped-*.json]
sourcetype = security:ped
index = security
```

**Linux Forwarder:**
```bash
# /opt/splunkforwarder/etc/system/local/inputs.conf

[monitor:///var/log/security/*.json]
sourcetype = security:monitoring:json
index = security
```

### ELK Stack Integration

**Filebeat Configuration:**

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/security/*.json
  json.keys_under_root: true
  json.add_error_key: true
  fields:
    source: security-monitoring
    environment: production

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "security-monitoring-%{+yyyy.MM.dd}"

output.logstash:
  hosts: ["logstash:5044"]
```

### Graylog Integration

**Configure Syslog Input:**

1. Create JSON UDP input on port 12201
2. Configure tools to send JSON via syslog
3. Create extractors for JSON fields

### Custom SIEM Script

```python
#!/usr/bin/env python3
"""
Simple SIEM aggregator for security monitoring toolkit
"""

import json
import glob
import datetime
from pathlib import Path

def aggregate_logs(log_dir):
    """Aggregate all JSON logs"""
    findings = {
        'timestamp': datetime.datetime.now().isoformat(),
        'fim': [],
        'ped': [],
        'pncm': [],
        'events': []
    }
    
    # Read all JSON files
    for json_file in Path(log_dir).glob('*.json'):
        try:
            with open(json_file) as f:
                data = json.load(f)
                
            if 'fim-' in json_file.name:
                findings['fim'].append(data)
            elif 'ped-' in json_file.name:
                findings['ped'].append(data)
            elif 'pncm-' in json_file.name:
                findings['pncm'].append(data)
            elif 'event' in json_file.name:
                findings['events'].append(data)
                
        except Exception as e:
            print(f"Error reading {json_file}: {e}")
    
    return findings

# Usage
logs = aggregate_logs('/var/log/security')
# Send to SIEM, generate report, etc.
```

---

## Troubleshooting

### Common Issues

#### Windows: "Python not recognized"

**Solution:**
```powershell
# Add Python to PATH
$env:Path += ";C:\Python39;C:\Python39\Scripts"

# Or reinstall Python with "Add to PATH" checked
```

#### Windows: "Access Denied" errors

**Solution:**
- Run Command Prompt as Administrator
- Check User Account Control (UAC) settings
- Verify script has proper permissions

#### Windows: pywin32 import errors

**Solution:**
```powershell
# Reinstall pywin32
pip uninstall pywin32
pip install --upgrade pywin32

# Run post-install script
python Scripts/pywin32_postinstall.py -install
```

#### Linux: "Permission denied" accessing logs

**Solution:**
```bash
# Run with sudo
sudo python3 ssh_monitor.py

# Or add user to necessary groups
sudo usermod -a -G adm $USER
# Log out and back in for group changes to take effect
```

#### Linux: "Log file not found"

**Solution:**
```bash
# Check log locations
ls -la /var/log/auth.log
ls -la /var/log/secure

# The script will try to find the correct location automatically
```

#### Both: Baseline file corrupted

**Solution:**
```bash
# Delete and recreate baseline
rm fim_baseline*.json
python3 fim.py --create-baseline  # Linux
python fim_windows.py --create-baseline  # Windows
```

### Performance Issues

**Large baseline files:**
- Use `--no-recursive` flag to limit directory scanning
- Exclude large directories from monitoring
- Split monitoring into multiple baseline files

**High CPU usage:**
- Increase check intervals
- Reduce number of monitored paths
- Run checks during off-peak hours

### Getting Help

1. Check tool-specific README files
2. Run tool with `--help` flag
3. Check log files for detailed error messages
4. Review the COMPLETE_TOOLKIT_README.md

---

## Best Practices

### Baseline Management

1. **Create baselines during stable periods**
   - After fresh installation
   - After approved changes
   - During maintenance windows

2. **Update baselines regularly**
   - After system updates
   - After configuration changes
   - Monthly or after major changes

3. **Version control baselines**
   ```bash
   # Save baseline with timestamp
   cp fim_baseline.json fim_baseline_$(date +%Y%m%d).json
   ```

### Monitoring Schedule

**Recommended frequencies:**

| Tool | Frequency | Rationale |
|------|-----------|-----------|
| Event Log Monitor | Every 6 hours | Balance between real-time and performance |
| SSH Monitor | Every 6 hours | Catch authentication issues promptly |
| FIM | Daily | File changes are typically infrequent |
| PED | Daily | Privilege changes are rare events |
| PNCM | Every 4 hours | Network/process anomalies need quicker detection |
| Port Scanner | Weekly | Infrastructure changes are infrequent |
| SSL Monitor | Daily | Certificate expiration monitoring |
| Web Log Analyzer | Hourly | Attack detection requires timely analysis |

### Log Retention

```powershell
# Windows: Create log rotation script
$LogPath = "C:\SecurityTools\Logs"
$DaysToKeep = 30
Get-ChildItem $LogPath -Recurse -File | 
    Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-$DaysToKeep)} | 
    Remove-Item -Force
```

```bash
# Linux: Use logrotate
# /etc/logrotate.d/security-monitoring
/var/log/security/*.json {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 root root
}
```

### Alert Configuration

**Priority Levels:**

**Critical (Immediate action required):**
- New administrator accounts
- Privilege escalation detected
- Critical file modifications
- Suspicious process execution

**High (Action within 4 hours):**
- Failed login attempts (>10)
- New scheduled tasks
- New listening ports
- Service changes

**Medium (Action within 24 hours):**
- File modifications in monitored paths
- New user accounts
- Password policy changes

**Low (Review weekly):**
- Informational events
- Baseline updates needed
- Performance metrics

### Security Hardening

**Protect tool files:**

**Windows:**
```powershell
# Set restrictive permissions
icacls "C:\SecurityTools" /grant Administrators:F /inheritance:r
icacls "C:\SecurityTools" /grant SYSTEM:F
```

**Linux:**
```bash
# Set restrictive permissions
sudo chown -R root:root /opt/security-monitoring
sudo chmod 700 /opt/security-monitoring
sudo chmod 600 /opt/security-monitoring/*.json
```

**Protect baseline files:**
- Store in secure location
- Use file permissions to prevent tampering
- Consider using digital signatures
- Back up to separate system

**Network security:**
- Use encrypted channels for log transmission
- Implement firewall rules for log collection
- Use VPN for remote monitoring
- Authenticate all connections

---

## Compliance Considerations

### HIPAA Compliance

The toolkit supports HIPAA requirements for:
- Access monitoring (Event Log/SSH Monitor)
- Integrity checking (FIM)
- Audit trails (All tools with JSON export)
- Regular monitoring (Scheduled checks)

**Configuration for HIPAA:**
```bash
# Monitor healthcare-specific paths
sudo python3 fim.py --create-baseline --path /var/www/ehr
sudo python3 fim.py --create-baseline --path /opt/medical-records
```

### PCI-DSS Compliance

Requirements covered:
- File integrity monitoring (Requirement 11.5)
- Log monitoring (Requirement 10)
- Access control monitoring (Requirement 8)
- Network security monitoring (Requirement 1)

### GDPR/Data Privacy

**Important:** Logs may contain personal information:
- Configure appropriate retention periods
- Implement access controls
- Use encryption for storage and transmission
- Document processing activities

---

## Summary

This deployment guide provides comprehensive instructions for implementing the security monitoring toolkit across Windows and Linux environments. Key takeaways:

✅ **Platform Flexibility** - Use appropriate tools for each platform  
✅ **Centralized Monitoring** - Aggregate logs from all systems  
✅ **Automation** - Schedule regular checks and monitoring  
✅ **Integration** - Export JSON for SIEM/log management  
✅ **Compliance** - Support regulatory requirements  
✅ **Security** - Protect monitoring infrastructure  

For additional support, consult the individual tool README files and documentation.

---

## Quick Reference

### Essential Commands

**Windows:**
```powershell
# Launch interactive menu
security_suite_launcher.bat

# Manual tool execution
python fim_windows.py --create-baseline
python fim_windows.py --check
python ped_windows.py --create-baseline
python ped_windows.py --check
python pncm_windows.py --create-baseline
python pncm_windows.py --check
python ssh_monitor_windows.py --last-hours 24
```

**Linux:**
```bash
# Quick start
sudo ./QUICKSTART.sh

# Manual tool execution
sudo python3 fim.py --create-baseline
sudo python3 fim.py --check
sudo python3 ped.py --create-baseline
sudo python3 ped.py --check
sudo python3 pncm.py --create-baseline
sudo python3 pncm.py --check
sudo python3 ssh_monitor.py
```

**Cross-Platform:**
```bash
python port_scanner.py <target> -p 1-1000
python ssl_monitor.py <domain>
python web_log_analyzer.py <logfile>
```

---

**Document Version:** 2.0  
**Last Updated:** November 2025  
**Compatibility:** Windows 10/11, Windows Server 2016+, Linux (All modern distributions)
