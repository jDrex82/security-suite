# File Integrity Monitor (FIM)

A comprehensive Python-based File Integrity Monitor for detecting unauthorized system changes, rootkits, backdoors, and privilege escalation attempts. Critical for security monitoring, compliance, and incident response.

## 🎯 Perfect For

- **Critical Infrastructure Protection** - Monitor sensitive system files
- **Healthcare Security (HIPAA)** - Track access to patient data systems
- **Compliance Auditing** - PCI-DSS, SOC 2, ISO 27001 requirements
- **Incident Response** - Detect compromises and unauthorized modifications
- **Rootkit Detection** - Identify malicious SUID/SGID files
- **Configuration Management** - Alert on unauthorized config changes

## ✨ Features

- ✅ **Cryptographic Hashing** - SHA-256 file integrity verification
- ✅ **Change Detection** - Modified, deleted, and new files
- ✅ **Permission Monitoring** - Track SUID/SGID/permission changes
- ✅ **Ownership Tracking** - Detect UID/GID modifications
- ✅ **SUID/SGID Scanner** - Find elevated privilege binaries
- ✅ **Baseline Management** - Create snapshots for comparison
- ✅ **JSON Reporting** - Export detailed change reports
- ✅ **Recursive Scanning** - Monitor entire directory trees
- ✅ **Zero Dependencies** - Pure Python 3 standard library

## 🚀 Quick Start

### 1. Create Baseline (First Time)
```bash
# Monitor default critical paths
sudo python3 fim.py --create-baseline

# Or specify custom paths
sudo python3 fim.py --create-baseline --paths /etc /usr/local/bin /var/www
```

### 2. Check for Changes
```bash
# Quick integrity check
sudo python3 fim.py --check

# Verbose output with details
sudo python3 fim.py --check --verbose

# Export changes to report
sudo python3 fim.py --check --export security_report.json
```

### 3. Find SUID/SGID Files
```bash
# Scan for elevated privilege binaries
sudo python3 fim.py --find-suid

# Scan specific directories
sudo python3 fim.py --find-suid --paths /usr /opt
```

## 📋 Default Monitored Paths

The FIM monitors these critical system files by default:

```
/etc/passwd          - User accounts
/etc/shadow          - Password hashes
/etc/group           - Group memberships
/etc/sudoers         - Sudo privileges
/etc/ssh/sshd_config - SSH configuration
/etc/hosts           - DNS overrides
/etc/crontab         - Scheduled tasks
/etc/systemd/system  - System services
/root/.ssh/authorized_keys - Root SSH keys
```

## 🔍 What FIM Detects

### File Modifications
- Content changes via hash comparison
- Timestamp of last modification
- Size changes

### Permission Changes
- Mode changes (read/write/execute)
- SUID bit additions/removals
- SGID bit additions/removals
- Sticky bit changes

### Ownership Changes
- User ID (UID) changes
- Group ID (GID) changes

### File System Changes
- New files added
- Files deleted
- Directory structure changes

## 💡 Usage Examples

### Healthcare Environment
```bash
# Monitor patient data and access logs
sudo python3 fim.py --create-baseline --paths \
  /var/log/access.log \
  /etc/hipaa_config \
  /var/www/patient_portal

# Daily integrity check
sudo python3 fim.py --check --export /var/reports/fim_$(date +%Y%m%d).json
```

### Web Server Protection
```bash
# Monitor web application files
sudo python3 fim.py --create-baseline --paths \
  /var/www/html \
  /etc/nginx \
  /etc/apache2 \
  /etc/php

# Check for backdoors and modifications
sudo python3 fim.py --check
```

### System Hardening
```bash
# Find all SUID/SGID binaries
sudo python3 fim.py --find-suid --paths /usr /bin /sbin /opt

# Create baseline after hardening
sudo python3 fim.py --create-baseline

# Regular integrity checks via cron
echo "0 */4 * * * python3 /usr/local/bin/fim.py --check" | sudo crontab -
```

### Incident Response
```bash
# After suspected compromise, check everything
sudo python3 fim.py --check --verbose --export incident_report.json

# Compare against known-good baseline from backup
sudo python3 fim.py --baseline /backup/fim_baseline_good.json --check
```

## 📊 Sample Output

### Creating Baseline
```
======================================================================
Creating File Integrity Baseline
======================================================================

📁 Scanning directory: /etc
📄 Adding file: /etc/passwd
🔐 SUID/SGID detected: /usr/bin/sudo

Processing 847 files...

✅ Baseline created successfully!
📊 Files monitored: 847
💾 Baseline saved to: fim_baseline.json
```

### Detecting Changes
```
======================================================================
File Integrity Check
======================================================================
Baseline created: 2025-10-30T00:41:09.732826
Files in baseline: 847
======================================================================

🗑️  DELETED: /etc/shadow
⚠️  MODIFIED: /etc/passwd
   Old hash: a32d0cd441a8e75d...
   New hash: e1a4de3280044a6e...
   Modified: 2025-10-30 00:41:24
🔑 PERMISSIONS CHANGED: /etc/sudoers
   Old: -rw-r--r--
   New: -rwxrwxrwx
➕ NEW FILE: /tmp/backdoor.php
🚨 SUID BIT CHANGED: /usr/bin/suspicious
   Old: False → New: True

======================================================================
SUMMARY
======================================================================
⚠️  CHANGES DETECTED:
   Modified files: 3
   Deleted files: 1
   New files: 1
   Permission changes: 1
   SUID/SGID changes: 1
```

## 🔐 Security Best Practices

### Baseline Management
1. **Create baseline immediately after system hardening**
2. **Store baseline securely** (read-only location or backup)
3. **Version control baselines** for change tracking
4. **Recreate baselines after approved changes**

### Monitoring Strategy
```bash
# Hourly checks for critical systems
0 * * * * python3 /usr/local/bin/fim.py --check >> /var/log/fim.log

# Daily full scans with reporting
0 2 * * * python3 /usr/local/bin/fim.py --check --export /var/reports/fim_$(date +\%Y\%m\%d).json

# Weekly SUID/SGID audits
0 3 * * 0 python3 /usr/local/bin/fim.py --find-suid --paths /usr /opt >> /var/log/suid_audit.log
```

### Alert Integration
```bash
#!/bin/bash
# Alert script for FIM changes
REPORT="/tmp/fim_check.json"

python3 fim.py --check --export "$REPORT"

if [ $? -ne 0 ]; then
    # Changes detected - send alert
    mail -s "FIM Alert: Changes Detected on $(hostname)" security@company.com < "$REPORT"
    # Or send to Slack, PagerDuty, etc.
fi
```

## 🚨 Common Attack Scenarios Detected

### 1. Backdoor Account Creation
```bash
# Attacker adds user with UID 0 (root privileges)
echo "hacker:x:0:0::/root:/bin/bash" >> /etc/passwd

# FIM Detection:
⚠️  MODIFIED: /etc/passwd
```

### 2. SSH Configuration Tampering
```bash
# Attacker enables root login
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# FIM Detection:
⚠️  MODIFIED: /etc/ssh/sshd_config
```

### 3. Privilege Escalation
```bash
# Attacker makes file SUID root
chmod u+s /tmp/exploit

# FIM Detection:
🚨 SUID BIT CHANGED: /tmp/exploit
```

### 4. Web Shell Installation
```bash
# Attacker uploads PHP backdoor
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php

# FIM Detection:
➕ NEW FILE: /var/www/html/shell.php
```

### 5. Configuration Backdoor
```bash
# Attacker modifies sudoers for passwordless sudo
echo "attacker ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# FIM Detection:
⚠️  MODIFIED: /etc/sudoers
```

### 6. Log Tampering
```bash
# Attacker deletes audit logs
rm /var/log/auth.log

# FIM Detection:
🗑️  DELETED: /var/log/auth.log
```

## 📁 File Structure

```
fim.py                  - Main script
fim_baseline.json       - Baseline snapshot (created by --create-baseline)
fim_report.json         - Change report (created by --export)
```

## 🔧 Installation

### System-Wide Installation
```bash
# Download
curl -O https://raw.githubusercontent.com/yourrepo/fim.py

# Make executable
chmod +x fim.py

# Move to system path
sudo mv fim.py /usr/local/bin/fim

# Create baseline
sudo fim --create-baseline
```

### As Systemd Timer
Create `/etc/systemd/system/fim-check.service`:
```ini
[Unit]
Description=File Integrity Monitor Check
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/bin/fim.py --check --export /var/log/fim/fim_%Y%m%d.json
StandardOutput=journal
StandardError=journal
```

Create `/etc/systemd/system/fim-check.timer`:
```ini
[Unit]
Description=Run FIM checks every 4 hours

[Timer]
OnBootSec=15min
OnUnitActiveSec=4h
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fim-check.timer
```

## 🎓 Advanced Usage

### Multiple Baselines
```bash
# Create separate baselines for different environments
python3 fim.py --create-baseline --paths /etc --baseline /baselines/etc_baseline.json
python3 fim.py --create-baseline --paths /var/www --baseline /baselines/www_baseline.json

# Check against specific baseline
python3 fim.py --check --baseline /baselines/etc_baseline.json
```

### Automated Response
```python
#!/usr/bin/env python3
import subprocess
import json

# Run FIM check
result = subprocess.run(['python3', 'fim.py', '--check', '--export', 'fim_report.json'], 
                       capture_output=True)

if result.returncode != 0:
    with open('fim_report.json', 'r') as f:
        report = json.load(f)
    
    # Check for critical changes
    if report['changes']['suid'] or report['changes']['deleted']:
        # CRITICAL: SUID changes or deleted files
        # Trigger incident response
        subprocess.run(['incident-response-script.sh'])
```

### Compliance Reporting
```bash
# Generate monthly compliance report
python3 fim.py --check --export /compliance/fim_$(date +%Y_%m).json

# Include in audit documentation
python3 generate_compliance_report.py /compliance/fim_*.json
```

## ⚠️ Important Notes

### Permissions
- **Root/sudo required** to access most system files
- Baseline files should be stored securely (read-only)
- Consider using immutable flags: `sudo chattr +i fim_baseline.json`

### Performance
- Large directory scans can take time
- Use `--no-recursive` for shallow scans
- Consider excluding large data directories

### False Positives
- System updates will trigger changes
- Recreate baseline after approved updates
- Use separate baselines for different environments

## 🤝 Integration Examples

### With SIEM
```bash
# Export to JSON for log aggregation
python3 fim.py --check --export - | \
  curl -X POST https://siem.company.com/api/logs \
  -H "Content-Type: application/json" \
  -d @-
```

### With Fail2Ban
```bash
# Ban IPs that modify web files
# See fim_report.json for modified files in /var/www
# Extract source IP from auth logs and ban
```

### With Ansible
```yaml
- name: Run FIM check
  command: python3 /usr/local/bin/fim.py --check
  register: fim_result
  failed_when: fim_result.rc != 0

- name: Alert on changes
  mail:
    subject: "FIM Changes Detected"
    body: "{{ fim_result.stdout }}"
    to: security@company.com
  when: fim_result.rc != 0
```

## 🐛 Troubleshooting

### Permission Denied
```bash
# Solution: Run with sudo
sudo python3 fim.py --create-baseline
```

### Baseline Not Found
```bash
# Solution: Create baseline first
python3 fim.py --create-baseline
```

### Too Many Changes Detected
```bash
# After system updates, recreate baseline
sudo python3 fim.py --create-baseline

# Keep old baseline for reference
mv fim_baseline.json fim_baseline_old.json
```

## 📚 References

- NIST SP 800-53 (System Integrity Monitoring)
- CIS Controls v8 (File Integrity Monitoring)
- HIPAA Security Rule (System Integrity)
- PCI-DSS Requirement 11.5 (File Integrity Monitoring)

## 📄 License

MIT License - Use freely for security monitoring

## 👨‍💻 Author

Created for cybersecurity professionals, system administrators, and compliance officers.

---

**Remember**: FIM is a detective control. Combine with preventive controls like proper access controls, least privilege, and regular patching for comprehensive security.
