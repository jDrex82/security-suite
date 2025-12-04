# Quick Installation Guide
## Windows Security Monitoring Toolkit

---

## 🚀 3 Ways to Install

### Method 1: Interactive Launcher (Easiest)

1. **Extract all files** to `C:\SecurityTools`
2. **Right-click** `security_suite_launcher.bat`
3. **Select** "Run as Administrator"
4. **Use the menu** to run tools

✅ Best for: Manual usage, testing, learning the tools

---

### Method 2: Automated Deployment (Recommended)

1. **Open PowerShell as Administrator**
2. **Navigate to extracted folder:**
   ```powershell
   cd C:\Path\To\Extracted\Files
   ```
3. **Run deployment script:**
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\deploy_windows.ps1 -InstallDependencies -CreateBaselines -CreateScheduledTasks -TestInstallation
   ```

✅ Best for: Production deployment, automated monitoring

---

### Method 3: Manual Setup (Full Control)

#### Step 1: Install Python
- Download from [python.org](https://www.python.org/downloads/)
- ✅ Check "Add Python to PATH"

#### Step 2: Install Dependencies (Optional)
```powershell
pip install pywin32
pip install wmi
```

#### Step 3: Extract Files
Extract to: `C:\SecurityTools`

#### Step 4: Create Baselines
```powershell
cd C:\SecurityTools
python fim_windows.py --create-baseline
python ped_windows.py --create-baseline
python pncm_windows.py --create-baseline
```

#### Step 5: Test
```powershell
python ssh_monitor_windows.py --last-hours 24
python fim_windows.py --check
```

✅ Best for: Custom configurations, troubleshooting

---

## 📝 Deployment Script Options

The PowerShell deployment script supports these options:

```powershell
# Full deployment with everything
.\deploy_windows.ps1 -InstallDependencies -CreateBaselines -CreateScheduledTasks -TestInstallation

# Just install dependencies
.\deploy_windows.ps1 -InstallDependencies

# Just create baselines
.\deploy_windows.ps1 -CreateBaselines

# Just create scheduled tasks
.\deploy_windows.ps1 -CreateScheduledTasks

# Test existing installation
.\deploy_windows.ps1 -TestInstallation

# Remove scheduled tasks
.\deploy_windows.ps1 -UninstallScheduledTasks

# Custom installation path
.\deploy_windows.ps1 -InstallPath "D:\SecurityMonitoring" -CreateBaselines
```

---

## ⚙️ Scheduled Tasks (Created by Deployment Script)

The deployment script creates these automated tasks:

| Task | Schedule | Purpose |
|------|----------|---------|
| Security-FIM-Daily | Daily at 2:00 AM | File integrity check |
| Security-PED-Daily | Daily at 3:00 AM | Privilege escalation check |
| Security-PNCM-4Hours | Every 4 hours | Process/network monitoring |
| Security-EventLog-6Hours | Every 6 hours | Event log analysis |

**View tasks:** Open Task Scheduler (`taskschd.msc`)

---

## 🔍 Verify Installation

### Check Python
```powershell
python --version
# Should show: Python 3.6 or higher
```

### Check Dependencies
```powershell
python -c "import win32evtlog; print('pywin32: OK')"
python -c "import wmi; print('WMI: OK')"
```

### Check Tools
```powershell
cd C:\SecurityTools
python fim_windows.py --help
python ped_windows.py --help
python pncm_windows.py --help
python ssh_monitor_windows.py --help
```

### Test Run
```powershell
# Should show event log analysis
python ssh_monitor_windows.py --last-hours 1
```

---

## 📂 File Structure After Installation

```
C:\SecurityTools\
├── security_suite_launcher.bat      # Interactive launcher
├── ssh_monitor_windows.py           # Event log monitor
├── fim_windows.py                   # File integrity monitor
├── ped_windows.py                   # Privilege escalation detector
├── pncm_windows.py                  # Process/network monitor
├── deploy_windows.ps1               # Deployment script
├── README.md                        # Full documentation
├── WINDOWS_DEPLOYMENT_GUIDE.md      # Complete guide
├── QUICK_INSTALL.md                 # This file
├── fim_baseline_windows.json        # FIM baseline (after creation)
├── ped_baseline_windows.json        # PED baseline (after creation)
├── pncm_baseline_windows.json       # PNCM baseline (after creation)
└── Logs\                            # Log output directory
    ├── fim\
    ├── ped\
    ├── pncm\
    └── events\
```

---

## 🎯 First-Time Usage

### Run Your First Security Check

```powershell
# 1. Open PowerShell as Administrator
# 2. Navigate to tools
cd C:\SecurityTools

# 3. Create baselines (one-time setup)
python fim_windows.py --create-baseline
python ped_windows.py --create-baseline
python pncm_windows.py --create-baseline

# 4. Check event logs (last 24 hours)
python ssh_monitor_windows.py --last-hours 24

# 5. Check for changes
python fim_windows.py --check
python ped_windows.py --check
python pncm_windows.py --check
```

---

## 🔥 Common Commands

### Event Log Analysis
```powershell
# Last 24 hours
python ssh_monitor_windows.py --last-hours 24

# Last 48 hours with export
python ssh_monitor_windows.py --last-hours 48 --export events.json
```

### File Integrity
```powershell
# Create baseline
python fim_windows.py --create-baseline

# Check for changes
python fim_windows.py --check

# Monitor continuously (every 60 seconds)
python fim_windows.py --monitor --interval 60

# Check specific folder
python fim_windows.py --create-baseline --path "C:\Important"
python fim_windows.py --check --path "C:\Important"
```

### Privilege Escalation
```powershell
# Create baseline
python ped_windows.py --create-baseline

# Check for escalation
python ped_windows.py --check

# Monitor continuously (every 5 minutes)
python ped_windows.py --monitor --interval 300
```

### Process & Network
```powershell
# Create baseline
python pncm_windows.py --create-baseline

# Check for anomalies
python pncm_windows.py --check

# Monitor continuously (every 60 seconds)
python pncm_windows.py --monitor --interval 60
```

---

## 🐛 Troubleshooting

### "Python not recognized"
```powershell
# Add Python to PATH (temporary)
$env:Path += ";C:\Python39;C:\Python39\Scripts"

# Or reinstall Python with "Add to PATH" checked
```

### "Access Denied"
- ✅ Run PowerShell/Command Prompt as Administrator
- Right-click → "Run as Administrator"

### "pywin32 import error"
```powershell
pip uninstall pywin32
pip install --upgrade pywin32
python Scripts\pywin32_postinstall.py -install
```

### "No events found"
- Make sure Windows Security Event Log is enabled
- Run as Administrator
- Try: `python ssh_monitor_windows.py --last-hours 168` (last week)

### Script execution disabled
```powershell
# Temporary (current session only)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Permanent (run once)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 📊 View Results

### Console Output
All tools provide formatted output directly in the console.

### JSON Export
```powershell
# Export for SIEM integration
python fim_windows.py --check --export C:\Logs\fim-results.json
python ped_windows.py --check --export C:\Logs\ped-results.json
```

### Scheduled Task Logs
```powershell
# View logs directory
explorer C:\SecurityTools\Logs

# View specific tool logs
explorer C:\SecurityTools\Logs\fim
explorer C:\SecurityTools\Logs\ped
explorer C:\SecurityTools\Logs\pncm
explorer C:\SecurityTools\Logs\events
```

---

## 🔄 Updating Baselines

Baselines should be updated after:
- System updates/patches
- Software installations
- Configuration changes
- Security updates

```powershell
# Backup old baseline
copy fim_baseline_windows.json fim_baseline_windows.json.backup

# Create new baseline
python fim_windows.py --create-baseline
```

---

## 📚 More Information

- **Full Documentation:** `README.md`
- **Deployment Guide:** `WINDOWS_DEPLOYMENT_GUIDE.md`
- **Tool Help:** `python <tool>.py --help`

---

## ✅ Quick Checklist

- [ ] Python 3.6+ installed
- [ ] Running as Administrator
- [ ] Files extracted to `C:\SecurityTools`
- [ ] Optional dependencies installed
- [ ] Baselines created
- [ ] Test run successful
- [ ] Scheduled tasks created (if desired)
- [ ] Documentation reviewed

---

## 🎉 You're Ready!

The toolkit is now installed and ready to use.

**Try the launcher:**
```powershell
cd C:\SecurityTools
.\security_suite_launcher.bat
```

**Or use tools directly:**
```powershell
python ssh_monitor_windows.py --last-hours 24
python fim_windows.py --check
```

For detailed information, see `WINDOWS_DEPLOYMENT_GUIDE.md`

---

**Version:** 2.0  
**Platform:** Windows 10/11, Windows Server 2016+
