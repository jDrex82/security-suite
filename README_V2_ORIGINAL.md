# Complete Security Monitoring Toolkit
## Version 2.0 - Cross-Platform Edition

**Professional Security Monitoring Suite for Windows & Linux Environments**

---

## 📦 Package Overview

This is the complete, unified security monitoring toolkit supporting both Windows and Linux platforms. The package is organized into platform-specific folders with all necessary tools, documentation, and deployment scripts.

### Package Structure

```
complete_security_suite_v2/
├── README.md (this file)
├── windows/
│   ├── 4 Windows-specific Python security tools
│   ├── Interactive launcher (.bat)
│   ├── PowerShell deployment script
│   └── Complete Windows documentation
└── linux/
    ├── 7 Linux-specific Python security tools
    ├── Cross-platform tools (port scanner, SSL monitor, web log analyzer)
    ├── Bash deployment script
    └── Complete Linux documentation
```

---

## 🚀 Quick Start

### For Windows Users

```powershell
# Navigate to Windows folder
cd windows\

# Option 1: Interactive Launcher (Easiest)
# Right-click security_suite_launcher.bat → Run as Administrator

# Option 2: Automated Deployment
.\deploy_windows.ps1 -InstallDependencies -CreateBaselines -CreateScheduledTasks

# Option 3: Manual Setup
python fim_windows.py --create-baseline
python ped_windows.py --create-baseline
python pncm_windows.py --create-baseline
```

**Documentation:** See `windows/README.md` and `windows/QUICK_INSTALL.md`

### For Linux Users

```bash
# Navigate to Linux folder
cd linux/

# Option 1: Quick Start Script
sudo ./QUICKSTART.sh

# Option 2: Manual Setup
sudo python3 fim.py --create-baseline
sudo python3 ped.py --create-baseline
sudo python3 pncm.py --create-baseline
```

**Documentation:** See `linux/README.md` and `linux/COMPLETE_TOOLKIT_README.md`

---

## 🛠️ What's Included

### Windows Tools (`windows/` folder)

#### Platform-Specific Security Tools
- **ssh_monitor_windows.py** - Windows Event Log security monitoring
- **fim_windows.py** - File Integrity Monitor for Windows
- **ped_windows.py** - Privilege Escalation Detector for Windows
- **pncm_windows.py** - Process & Network Connection Monitor for Windows

#### User Interface & Deployment
- **security_suite_launcher.bat** - Interactive menu launcher
- **deploy_windows.ps1** - Automated PowerShell deployment script

#### Documentation (4 files)
- README.md - Main Windows documentation
- QUICK_INSTALL.md - Quick installation guide
- WINDOWS_DEPLOYMENT_GUIDE.md - Comprehensive 28KB deployment guide
- MANIFEST.md - Package inventory

**Total:** 10 files (~158KB)

---

### Linux Tools (`linux/` folder)

#### Cross-Platform Tools (Work on Windows & Linux)
- **port_scanner.py** - Network port scanner with service detection
- **ssl_monitor.py** - SSL/TLS certificate monitoring
- **web_log_analyzer.py** - Web server log analysis

#### Linux-Specific Security Tools
- **ssh_monitor.py** - SSH login attempt monitoring
- **fim.py** - File Integrity Monitor for Linux
- **ped.py** - Privilege Escalation Detector for Linux
- **pncm.py** - Process & Network Connection Monitor for Linux

#### Deployment & Utilities
- **QUICKSTART.sh** - Quick deployment script
- **simulate_ssh_logs.py** - Testing utility
- **simulate_privilege_escalation.sh** - Testing utility
- **simulate_process_attacks.sh** - Testing utility

#### Documentation (10+ files)
- README.md - Main Linux documentation
- COMPLETE_TOOLKIT_README.md - Comprehensive guide
- Individual tool READMEs for each security tool
- Deployment guides (FIM, SSH)
- Healthcare-specific guide

**Total:** 25 files (~300KB)

---

## 📊 Platform Compatibility Matrix

| Tool Category | Windows | Linux | Description |
|--------------|---------|-------|-------------|
| **Port Scanner** | ✅ | ✅ | Network scanning (cross-platform) |
| **SSL Monitor** | ✅ | ✅ | Certificate monitoring (cross-platform) |
| **Web Log Analyzer** | ✅ | ✅ | Log analysis (cross-platform) |
| **Event/SSH Monitor** | ✅ (Event Logs) | ✅ (SSH logs) | Authentication monitoring |
| **File Integrity** | ✅ (Windows) | ✅ (Linux) | File change detection |
| **Privilege Detection** | ✅ (Windows) | ✅ (Linux) | Privilege escalation monitoring |
| **Process Monitor** | ✅ (Windows) | ✅ (Linux) | Process/network monitoring |

---

## 🎯 Use Cases

### Mixed Windows/Linux Environments
- Deploy Windows tools on Windows servers/workstations
- Deploy Linux tools on Linux servers
- Centralize all logs in a single SIEM
- Use consistent JSON export format across platforms
- Unified monitoring and alerting

### Windows-Only Environments
- Navigate to `windows/` folder
- Use Windows-specific tools
- Follow Windows deployment guide

### Linux-Only Environments
- Navigate to `linux/` folder
- Use Linux-specific tools plus cross-platform tools
- Follow Linux deployment guide

### Healthcare/Critical Infrastructure
- Both folders include HIPAA/compliance documentation
- File integrity monitoring for critical systems
- Comprehensive audit trails
- Baseline management for change detection

---

## 📋 System Requirements

### Windows
- Windows 10/11 or Windows Server 2016+
- Python 3.6 or higher
- Administrator privileges
- Optional: pywin32, WMI modules

### Linux
- Modern Linux distribution (Ubuntu 20.04+, RHEL 8+, Debian 11+)
- Python 3.6 or higher
- Root/sudo access
- No external dependencies (pure Python)

### Both Platforms
- 100MB minimum disk space
- Network connectivity for SIEM integration (optional)

---

## 🔄 Integration & Interoperability

### JSON Export (All Tools)
Both Windows and Linux tools export to identical JSON format:
- Compatible with any SIEM (Splunk, ELK, Graylog, QRadar)
- Easy log aggregation
- Consistent field names across platforms
- Timestamp standardization

### Example Integration
```python
# All tools support JSON export
python fim_windows.py --check --export fim-results.json
python fim.py --check --export fim-results.json

# Results can be aggregated together
```

### Centralized Monitoring Setup
1. Deploy platform-specific tools on each system
2. Configure JSON exports
3. Forward to central SIEM/log aggregator
4. Create unified dashboards
5. Set up cross-platform correlation rules

See `windows/WINDOWS_DEPLOYMENT_GUIDE.md` for complete integration examples.

---

## 🚦 Getting Started - Choose Your Path

### Path 1: Windows Administrator
1. Navigate to `windows/` folder
2. Read `QUICK_INSTALL.md`
3. Run `security_suite_launcher.bat` as Administrator
4. Create baselines and start monitoring

### Path 2: Linux Administrator
1. Navigate to `linux/` folder
2. Read `README.md`
3. Run `sudo ./QUICKSTART.sh`
4. Review tool-specific READMEs

### Path 3: Mixed Environment Manager
1. Review this README
2. Read `windows/WINDOWS_DEPLOYMENT_GUIDE.md` (section on mixed environments)
3. Deploy Windows tools on Windows systems
4. Deploy Linux tools on Linux systems
5. Set up centralized log collection
6. Configure SIEM integration

---

## 📚 Documentation Guide

### Windows Documentation (in `windows/` folder)
1. **Start here:** `QUICK_INSTALL.md` - Fast installation guide
2. **Main docs:** `README.md` - Tool descriptions and usage
3. **Advanced:** `WINDOWS_DEPLOYMENT_GUIDE.md` - Complete deployment guide (28KB)
4. **Reference:** `MANIFEST.md` - Package inventory

### Linux Documentation (in `linux/` folder)
1. **Start here:** `README.md` - Overview and quick start
2. **Main docs:** `COMPLETE_TOOLKIT_README.md` - Comprehensive guide
3. **Tools:** Individual `*_README.md` files for each tool
4. **Deployment:** `FIM_DEPLOYMENT.md`, `SSH_DEPLOYMENT.md`
5. **Specialized:** `FIM_HEALTHCARE_GUIDE.md` - Healthcare compliance

### Getting Help
- Each tool supports `--help` flag
- Check tool-specific README files
- Review troubleshooting sections in guides
- Examine example files and test utilities

---

## 🔐 Security & Compliance

### Features Supporting Compliance
- **HIPAA:** File integrity monitoring, access logging, audit trails
- **PCI-DSS:** Log monitoring, integrity checking, access control
- **GDPR:** Data protection monitoring, access logging
- **SOC 2:** Continuous monitoring, change detection

### Security Best Practices
✅ Run tools with appropriate privileges (admin/root)  
✅ Protect baseline files from tampering  
✅ Use encrypted channels for log transmission  
✅ Implement proper access controls  
✅ Regular baseline updates  
✅ Automated monitoring with scheduled tasks  

---

## 🎨 Key Features

### All Tools Include
✅ **Zero Dependencies** - Pure Python standard library (optional modules for enhancements)  
✅ **Production Ready** - Comprehensive error handling and logging  
✅ **JSON Export** - SIEM-ready output format  
✅ **Baseline Comparison** - Detect deviations from known-good state  
✅ **Continuous Monitoring** - Real-time or scheduled monitoring modes  
✅ **Comprehensive Documentation** - Installation to operations  

### Platform-Specific Optimizations
- **Windows:** Event Log integration, NTFS attributes, Task Scheduler, PowerShell
- **Linux:** Syslog integration, systemd services, cron jobs, file permissions

---

## 📈 Recommended Monitoring Schedule

| Tool | Frequency | Reason |
|------|-----------|--------|
| Event/SSH Monitor | Every 6 hours | Timely authentication monitoring |
| File Integrity | Daily (2 AM) | File changes are infrequent |
| Privilege Detection | Daily (3 AM) | Privilege changes are rare |
| Process Monitor | Every 4 hours | Faster anomaly detection |
| SSL Monitor | Daily | Certificate expiration tracking |
| Web Log Analyzer | Hourly | Attack detection needs speed |

---

## 🔧 Installation Size & Requirements

### Windows Package
- **Size:** ~158KB (10 files)
- **Installed:** ~1MB with baselines
- **Logs:** Grows based on frequency (plan 100MB+)

### Linux Package
- **Size:** ~300KB (25 files)
- **Installed:** ~2MB with baselines
- **Logs:** Grows based on frequency (plan 100MB+)

### Total Disk Space Recommendation
- **Minimum:** 500MB (tools + baselines + 30 days logs)
- **Recommended:** 2GB (tools + baselines + 90 days logs + room for growth)

---

## 🆘 Troubleshooting

### Windows Issues
- **Python not found:** Install from python.org, check "Add to PATH"
- **Access denied:** Run as Administrator
- **pywin32 errors:** `pip install --upgrade pywin32`

See `windows/QUICK_INSTALL.md` for complete troubleshooting.

### Linux Issues
- **Permission denied:** Use `sudo`
- **Log file not found:** Script will auto-detect correct location
- **Python version:** Ensure Python 3.6+

See individual tool READMEs in `linux/` folder.

---

## 📞 Support Resources

### Self-Help
1. Check tool's `--help` output
2. Review platform-specific README files
3. Check troubleshooting sections
4. Examine example/test files

### Documentation Hierarchy
```
Main README (this file)
├── Windows
│   ├── QUICK_INSTALL.md (start here)
│   ├── README.md (main docs)
│   └── WINDOWS_DEPLOYMENT_GUIDE.md (advanced)
└── Linux
    ├── README.md (start here)
    ├── COMPLETE_TOOLKIT_README.md (comprehensive)
    └── [Tool]_README.md (specific tools)
```

---

## 🎉 Quick Win - Test in 5 Minutes

### Windows
```powershell
cd windows
python ssh_monitor_windows.py --last-hours 24
```

### Linux
```bash
cd linux
sudo python3 ssh_monitor.py
```

Both commands will immediately show you security monitoring in action!

---

## 📦 What's New in Version 2.0

✅ **Windows Support** - Complete Windows-compatible toolkit  
✅ **Unified Package** - Both platforms in one download  
✅ **Enhanced Documentation** - 28KB deployment guide  
✅ **Automated Deployment** - PowerShell and Bash scripts  
✅ **Interactive Launcher** - Easy Windows menu interface  
✅ **Cross-Platform JSON** - Consistent export format  
✅ **SIEM Integration** - Ready for enterprise deployment  

---

## 🏆 Summary

This package provides enterprise-grade security monitoring for both Windows and Linux:

- **35 Total Files** across both platforms
- **11 Security Monitoring Tools** (4 Windows, 7 Linux/cross-platform)
- **Comprehensive Documentation** (50+ pages)
- **Production Ready** with error handling and logging
- **SIEM Compatible** with JSON export
- **Zero Cost** - MIT License

**Total Package Size:** ~460KB compressed  
**Installation Time:** 5-15 minutes per platform  
**Complexity:** Easy to Moderate  

---

## 🎯 Next Steps

1. **Choose your platform(s):** Windows, Linux, or both
2. **Navigate to appropriate folder:** `cd windows/` or `cd linux/`
3. **Read platform-specific README:** Start with quick install guides
4. **Deploy and test:** Use automated scripts or manual setup
5. **Schedule automation:** Set up Task Scheduler (Windows) or cron (Linux)
6. **Integrate with SIEM:** Configure JSON exports to your log aggregator

---

## 📄 License

MIT License - Free to use for security monitoring purposes

---

## 📊 Version Information

- **Package Version:** 2.0
- **Release Date:** November 2025
- **Compatibility:** 
  - Windows 10/11, Server 2016+
  - Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+, and others)
- **Python Required:** 3.6+

---

**Ready to deploy enterprise security monitoring across your entire infrastructure!**

For detailed platform-specific instructions, navigate to the `windows/` or `linux/` folder and start with the README files.
