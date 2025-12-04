# Windows Security Tools Package
## Complete Security Monitoring Suite - Windows Edition

This package contains Windows-compatible versions and deployment tools for the complete security monitoring suite.

## 📦 Package Contents

### 1. Windows Launcher Script
**File:** `security_suite_launcher.bat`
- Interactive menu-driven interface for all tools
- Automatic requirement checking
- Easy-to-use navigation
- Administrator privilege detection
- Built-in documentation access

### 2. Windows-Compatible Security Tools

#### Event Log Monitor (`ssh_monitor_windows.py`)
**Equivalent to:** Linux SSH Monitor
**Purpose:** Monitors Windows Security Event Logs for authentication attempts and security events
**Features:**
- Tracks login attempts (successful and failed)
- Monitors privileged operations
- Detects account changes
- Analyzes security events (Event IDs 4624, 4625, 4672, etc.)
- Supports both pywin32 and WMI methods
- JSON export for SIEM integration

**Usage:**
```powershell
# Analyze last 24 hours
python ssh_monitor_windows.py --last-hours 24

# Export to JSON
python ssh_monitor_windows.py --export security-events.json

# Analyze last 48 hours with export
python ssh_monitor_windows.py --last-hours 48 --export events.json
```

**Requirements:**
- Administrator privileges
- Optional: `pip install pywin32` for enhanced functionality

---

#### File Integrity Monitor (`fim_windows.py`)
**Equivalent to:** Linux FIM
**Purpose:** Detects unauthorized changes to critical Windows system files
**Features:**
- Monitors critical Windows paths (System32, registry hives, startup folders)
- Hash-based change detection (SHA-256)
- Tracks file metadata (size, timestamps, attributes)
- Windows-specific attributes (hidden, system, encrypted flags)
- Recursive directory scanning
- Continuous monitoring mode
- JSON export

**Usage:**
```powershell
# Create baseline
python fim_windows.py --create-baseline

# Check for changes
python fim_windows.py --check

# Monitor specific directory
python fim_windows.py --create-baseline --path "C:\Important Files"
python fim_windows.py --check --path "C:\Important Files"

# Continuous monitoring (check every 60 seconds)
python fim_windows.py --monitor --interval 60

# Export changes
python fim_windows.py --check --export changes.json
```

**Monitored Paths by Default:**
- `C:\Windows\System32\config\` (SAM, SYSTEM, SECURITY, SOFTWARE)
- `C:\Windows\System32\drivers\etc\hosts`
- `C:\Windows\System32\drivers\`
- `C:\Windows\System32\WindowsPowerShell\`
- `C:\Windows\Tasks\` (Scheduled tasks)
- Startup folders (System and User)

---

#### Privilege Escalation Detector (`ped_windows.py`)
**Equivalent to:** Linux PED
**Purpose:** Monitors Windows systems for privilege escalation attempts
**Features:**
- Tracks user account changes
- Monitors group membership changes (especially Administrators group)
- Detects new scheduled tasks
- Monitors startup programs (registry and folders)
- Tracks Windows services
- Monitors network shares
- Checks firewall status
- Baseline comparison

**Usage:**
```powershell
# Create security baseline
python ped_windows.py --create-baseline

# Check for privilege escalation
python ped_windows.py --check

# Continuous monitoring (check every 5 minutes)
python ped_windows.py --monitor --interval 300

# Export findings
python ped_windows.py --check --export priv-changes.json
```

**Detects:**
- New user accounts
- New group memberships (especially Administrators)
- New scheduled tasks
- New startup programs
- New or modified services
- New network shares
- Firewall configuration changes

---

#### Process & Network Monitor (`pncm_windows.py`)
**Equivalent to:** Linux PNCM
**Purpose:** Monitors processes and network connections for anomalies
**Features:**
- Tracks running processes
- Monitors network connections
- Detects listening ports
- Identifies suspicious processes (cmd.exe, powershell.exe, etc.)
- Monitors startup programs
- Baseline comparison
- Continuous monitoring

**Usage:**
```powershell
# Create baseline
python pncm_windows.py --create-baseline

# Check for anomalies
python pncm_windows.py --check

# Continuous monitoring (check every 60 seconds)
python pncm_windows.py --monitor --interval 60

# Export findings
python pncm_windows.py --check --export process-anomalies.json
```

**Detects:**
- New processes not in baseline
- Suspicious process patterns
- New listening ports
- Suspicious network connections
- New startup items
- Processes running as SYSTEM with network activity

---

### 3. Comprehensive Deployment Guide
**File:** `WINDOWS_DEPLOYMENT_GUIDE.md`

Complete guide covering:
- Platform compatibility matrix
- Installation instructions (Windows & Linux)
- Cross-platform deployment strategies
- Centralized monitoring setup
- SIEM integration (Splunk, ELK, Graylog)
- Automation with Task Scheduler and cron
- Best practices and security hardening
- Compliance considerations (HIPAA, PCI-DSS, GDPR)
- Troubleshooting guide
- Quick reference commands

---

## 🚀 Quick Start

### Method 1: Use the Interactive Launcher (Recommended)

1. **Extract all files to a directory** (e.g., `C:\SecurityTools`)
2. **Right-click `security_suite_launcher.bat`**
3. **Select "Run as Administrator"**
4. **Follow the menu prompts**

### Method 2: Manual Execution

1. **Open Command Prompt as Administrator**
2. **Navigate to the tool directory:**
   ```cmd
   cd C:\SecurityTools
   ```
3. **Create baselines:**
   ```cmd
   python fim_windows.py --create-baseline
   python ped_windows.py --create-baseline
   python pncm_windows.py --create-baseline
   ```
4. **Run checks:**
   ```cmd
   python ssh_monitor_windows.py --last-hours 24
   python fim_windows.py --check
   python ped_windows.py --check
   python pncm_windows.py --check
   ```

---

## 📋 Prerequisites

### Required
- Windows 10/11 or Windows Server 2016/2019/2022
- Python 3.6 or higher
- Administrator privileges

### Optional (Enhances functionality)
```powershell
pip install pywin32    # Enhanced Windows Event Log access
pip install wmi        # Alternative event log method
```

---

## 🔧 Installation

### Step 1: Install Python
1. Download from [python.org](https://www.python.org/downloads/)
2. **Important:** Check "Add Python to PATH" during installation
3. Verify: `python --version`

### Step 2: Install Optional Dependencies
```powershell
pip install pywin32
pip install wmi
```

### Step 3: Extract Tools
Extract all files to a permanent location:
- Recommended: `C:\SecurityTools\`
- Alternative: `C:\Program Files\SecurityMonitoring\`

### Step 4: Test Installation
```powershell
cd C:\SecurityTools
python fim_windows.py --create-baseline
```

---

## 📅 Recommended Monitoring Schedule

Create these scheduled tasks for automated monitoring:

### Daily Tasks (Run at 2-3 AM)
```powershell
# File Integrity Monitor
schtasks /create /tn "Security-FIM" /tr "python C:\SecurityTools\fim_windows.py --check --export C:\Logs\fim.json" /sc daily /st 02:00 /ru SYSTEM

# Privilege Escalation Detector
schtasks /create /tn "Security-PED" /tr "python C:\SecurityTools\ped_windows.py --check --export C:\Logs\ped.json" /sc daily /st 03:00 /ru SYSTEM
```

### Frequent Tasks (Every 4-6 hours)
```powershell
# Process & Network Monitor
schtasks /create /tn "Security-PNCM" /tr "python C:\SecurityTools\pncm_windows.py --check --export C:\Logs\pncm.json" /sc hourly /mo 4 /ru SYSTEM

# Event Log Monitor
schtasks /create /tn "Security-EventLog" /tr "python C:\SecurityTools\ssh_monitor_windows.py --last-hours 6 --export C:\Logs\events.json" /sc hourly /mo 6 /ru SYSTEM
```

---

## 📊 Output and Reporting

All tools support JSON export for integration with:
- **SIEM Systems:** Splunk, ELK Stack, Graylog, QRadar
- **Log Management:** Windows Event Collector, Fluentd
- **Security Platforms:** Microsoft Sentinel, Sumo Logic
- **Custom Dashboards:** Grafana, Kibana

**Example JSON Export:**
```powershell
python fim_windows.py --check --export C:\Logs\fim-$(Get-Date -Format 'yyyyMMdd-HHmmss').json
```

---

## 🔒 Security Considerations

### File Permissions
Protect tool files and baselines from tampering:
```powershell
# Set restrictive permissions
icacls "C:\SecurityTools" /grant Administrators:F /inheritance:r
icacls "C:\SecurityTools" /grant SYSTEM:F

# Protect baseline files
icacls "C:\SecurityTools\*.json" /grant Administrators:F /inheritance:r
```

### Network Security
- Use encrypted channels for log transmission
- Implement firewall rules for log collection
- Use VPN for remote monitoring
- Store baselines on separate secure system

### Access Control
- Run tools with dedicated service account
- Use least-privilege principle
- Audit access to monitoring tools
- Rotate credentials regularly

---

## 🐛 Troubleshooting

### "Python not recognized"
**Solution:**
```powershell
# Add Python to PATH
$env:Path += ";C:\Python39;C:\Python39\Scripts"
```

### "Access Denied" errors
**Solution:**
- Ensure Command Prompt is running as Administrator
- Check UAC settings
- Verify account has necessary privileges

### pywin32 errors
**Solution:**
```powershell
pip uninstall pywin32
pip install --upgrade pywin32
python Scripts\pywin32_postinstall.py -install
```

### High CPU usage
**Solution:**
- Increase check intervals
- Use `--no-recursive` flag for FIM
- Reduce monitored paths
- Schedule checks during off-peak hours

---

## 📚 Documentation

Each tool has detailed documentation:
- Full usage examples
- Configuration options
- Output format specifications
- Integration guides

Run any tool with `--help` for detailed options:
```powershell
python fim_windows.py --help
python ped_windows.py --help
python pncm_windows.py --help
python ssh_monitor_windows.py --help
```

---

## 🆚 Comparison with Linux Tools

| Windows Tool | Linux Equivalent | Primary Difference |
|--------------|------------------|-------------------|
| ssh_monitor_windows.py | ssh_monitor.py | Windows Event Logs vs /var/log/auth.log |
| fim_windows.py | fim.py | Windows paths vs Linux paths, NTFS attributes |
| ped_windows.py | ped.py | Windows groups/services vs Linux users/processes |
| pncm_windows.py | pncm.py | Windows Task Manager vs Linux /proc |

All tools maintain feature parity and use similar command-line interfaces for consistency.

---

## 🔄 Integration with Existing Linux Tools

This package is designed to work alongside your existing Linux security tools:

1. **Same JSON format** - Compatible with existing parsers
2. **Similar CLI** - Consistent command structure
3. **Unified reporting** - Combine results from both platforms
4. **Centralized monitoring** - Single SIEM for all systems

See `WINDOWS_DEPLOYMENT_GUIDE.md` for complete mixed-environment setup.

---

## ✅ Feature Comparison

### Cross-Platform Tools (Available on Both)
- ✅ Port Scanner
- ✅ SSL Monitor  
- ✅ Web Log Analyzer

### Platform-Specific Tools
**Windows (This Package):**
- ✅ Event Log Monitor
- ✅ File Integrity Monitor (Windows)
- ✅ Privilege Escalation Detector (Windows)
- ✅ Process & Network Monitor (Windows)

**Linux (Original Package):**
- ✅ SSH Monitor
- ✅ File Integrity Monitor (Linux)
- ✅ Privilege Escalation Detector (Linux)
- ✅ Process & Network Monitor (Linux)

---

## 📞 Support

For issues or questions:
1. Check the tool's `--help` output
2. Review `WINDOWS_DEPLOYMENT_GUIDE.md`
3. Check the troubleshooting section
4. Review log files for error details

---

## 📄 License

MIT License - Use freely for security monitoring

---

## 🎯 Next Steps

1. ✅ Install Python and dependencies
2. ✅ Extract tools to permanent location
3. ✅ Run interactive launcher or create baselines manually
4. ✅ Set up scheduled tasks for automation
5. ✅ Configure SIEM integration if needed
6. ✅ Review `WINDOWS_DEPLOYMENT_GUIDE.md` for advanced configuration

---

**Package Version:** 2.0  
**Compatibility:** Windows 10/11, Windows Server 2016+  
**Created:** November 2025
