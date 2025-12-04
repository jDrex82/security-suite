# FIM for Healthcare & Critical Infrastructure Security

## 🏥 Healthcare Security Use Cases (HIPAA Compliance)

### Overview
File Integrity Monitoring is **REQUIRED** for HIPAA compliance under the Security Rule §164.312(b) - Audit Controls and §164.308(a)(1)(ii)(D) - Information System Activity Review.

### Critical Paths to Monitor in Healthcare

```bash
# Electronic Health Records (EHR) System
sudo python3 fim.py --create-baseline --paths \
  /opt/ehr_system/config \
  /var/ehr/patient_data \
  /etc/ehr

# Medical Device Integration
sudo python3 fim.py --create-baseline --paths \
  /opt/medical_devices \
  /etc/hl7_interface \
  /var/log/device_events

# Patient Portal
sudo python3 fim.py --create-baseline --paths \
  /var/www/patient_portal \
  /etc/nginx/sites-enabled \
  /opt/portal_config

# Database Access
sudo python3 fim.py --create-baseline --paths \
  /etc/mysql \
  /etc/postgresql \
  /var/lib/pgsql/data/pg_hba.conf
```

## 🚨 Healthcare Attack Scenarios

### 1. Ransomware Deployment
**Attack**: Ransomware modifies system files before encrypting data
```
⚠️  MODIFIED: /opt/ehr_system/bin/launcher
➕ NEW FILE: /tmp/.ransom_note.txt
🗑️  DELETED: /etc/cron.d/backup_task
```
**Response**: Immediately isolate system, restore from baseline backup

### 2. Insider Threat - Data Exfiltration
**Attack**: Malicious insider modifies access logs to cover tracks
```
⚠️  MODIFIED: /var/log/access.log
⚠️  MODIFIED: /var/log/audit/audit.log
🔑 PERMISSIONS CHANGED: /var/log/patient_access.log
   Old: -rw-r----- 
   New: -rw-rw-rw-  (World writable!)
```
**Response**: Review all access logs before modification, investigate user activity

### 3. EHR Database Compromise
**Attack**: Attacker modifies database configuration to allow remote access
```
⚠️  MODIFIED: /etc/postgresql/pg_hba.conf
   Added: host all all 0.0.0.0/0 md5
⚠️  MODIFIED: /opt/ehr_system/config/database.yml
   Changed: encryption: enabled → disabled
```
**Response**: Immediately revoke network access, audit all database queries

### 4. Medical Device Tampering
**Attack**: Firmware or configuration changes to medical devices
```
⚠️  MODIFIED: /opt/medical_devices/infusion_pump/firmware.bin
⚠️  MODIFIED: /etc/hl7_interface/device_mapping.conf
```
**Response**: **CRITICAL** - Immediate device quarantine, patient safety check

### 5. Backdoor Installation
**Attack**: Web shell added to patient portal
```
➕ NEW FILE: /var/www/patient_portal/uploads/shell.php
⚠️  MODIFIED: /var/www/patient_portal/.htaccess
```
**Response**: Remove backdoor, audit all file uploads, check for data breach

## 💊 HIPAA Compliance Monitoring

### Required FIM Checks for HIPAA

```bash
#!/bin/bash
# Daily HIPAA compliance check script

echo "=== HIPAA FIM Compliance Check - $(date) ===" | tee -a /var/log/hipaa_fim.log

# 1. Check ePHI system integrity
echo "Checking ePHI systems..." | tee -a /var/log/hipaa_fim.log
sudo python3 fim.py --baseline /secure/ehr_baseline.json --check \
  --export /var/reports/ehr_fim_$(date +%Y%m%d).json

# 2. Check access control files
echo "Checking access controls..." | tee -a /var/log/hipaa_fim.log
sudo python3 fim.py --baseline /secure/access_baseline.json --check \
  --paths /etc/passwd /etc/group /etc/sudoers

# 3. Audit log integrity
echo "Checking audit logs..." | tee -a /var/log/hipaa_fim.log
sudo python3 fim.py --baseline /secure/logs_baseline.json --check \
  --paths /var/log/audit /var/log/auth.log

# 4. SUID/SGID audit (privilege escalation detection)
echo "Checking for unauthorized privilege escalation..." | tee -a /var/log/hipaa_fim.log
sudo python3 fim.py --find-suid --paths /usr /opt /var/www

# Send alerts if changes detected
if [ $? -ne 0 ]; then
    echo "ALERT: Changes detected in HIPAA-critical systems" | \
    mail -s "HIPAA FIM Alert - $(hostname)" compliance@hospital.org
fi
```

### Compliance Documentation

FIM helps demonstrate compliance with:

- **§164.308(a)(1)(ii)(D)** - Information System Activity Review
  - *Evidence*: Daily FIM reports showing system integrity checks

- **§164.312(b)** - Audit Controls
  - *Evidence*: Baseline files + change reports = audit trail

- **§164.312(c)(1)** - Integrity Controls
  - *Evidence*: Hash verification ensures data hasn't been tampered with

- **§164.312(e)(2)(i)** - Integrity
  - *Evidence*: Detection of unauthorized modifications to ePHI systems

## ⚡ Critical Infrastructure Protection

### Power Grid / Utility Systems

```bash
# SCADA system monitoring
sudo python3 fim.py --create-baseline --paths \
  /opt/scada/config \
  /etc/modbus \
  /var/lib/industrial_control

# HMI (Human-Machine Interface) protection
sudo python3 fim.py --create-baseline --paths \
  /opt/hmi_software \
  /etc/industrial_network \
  /var/scada/operator_stations
```

**Critical Alerts for Power Grid:**
```
🚨 MODIFIED: /opt/scada/config/substation_controls.conf
   ⚠️  IMMEDIATE ACTION REQUIRED - Potential grid manipulation

🚨 NEW FILE: /etc/cron.d/suspicious_task
   ⚠️  Possible time-bomb or scheduled attack

🚨 SUID BIT CHANGED: /opt/scada/bin/control_override
   ⚠️  CRITICAL: Unauthorized privilege escalation in control system
```

### Water Treatment Facilities

```bash
# PLC (Programmable Logic Controller) monitoring
sudo python3 fim.py --create-baseline --paths \
  /opt/water_treatment/plc_programs \
  /etc/water_scada \
  /var/lib/treatment_plant

# Chemical dosing system protection
sudo python3 fim.py --create-baseline --paths \
  /opt/chemical_control \
  /etc/dosing_config \
  /var/log/chemical_events
```

**Real-World Example** (Based on Oldsmar Water Treatment Breach):
```
⚠️  MODIFIED: /opt/water_treatment/chemical_dosing.conf
   Old: sodium_hydroxide_level: 100
   New: sodium_hydroxide_level: 11100
   
🚨 CRITICAL PUBLIC SAFETY THREAT - Dangerous chemical levels
```

### Transportation Systems

```bash
# Traffic control systems
sudo python3 fim.py --create-baseline --paths \
  /opt/traffic_control \
  /etc/signal_timing \
  /var/lib/traffic_management

# Railway control
sudo python3 fim.py --create-baseline --paths \
  /opt/railway_signal \
  /etc/train_control \
  /var/rail/switching_logic
```

## 🛡️ Defense-in-Depth Strategy

### Layer 1: Prevention
- Implement least privilege access
- Use SELinux/AppArmor
- Network segmentation
- Strong authentication (MFA)

### Layer 2: Detection (FIM)
```bash
# Continuous monitoring with FIM
*/30 * * * * python3 /usr/local/bin/fim.py --check

# Critical system monitoring (every 5 minutes)
*/5 * * * * python3 /usr/local/bin/fim.py \
  --baseline /critical/baseline.json \
  --check \
  --paths /opt/critical_systems
```

### Layer 3: Response
```bash
#!/bin/bash
# Automated incident response trigger

if python3 fim.py --check --baseline /critical/baseline.json; then
    echo "System integrity maintained"
else
    echo "ALERT: Critical system compromise detected"
    
    # Automated response actions:
    # 1. Alert security team
    /usr/local/bin/alert_security_team.sh
    
    # 2. Capture forensic snapshot
    /usr/local/bin/capture_forensics.sh
    
    # 3. Isolate affected system (if safe)
    # /usr/local/bin/isolate_system.sh
    
    # 4. Document for incident report
    cp fim_report.json /var/incident_response/incident_$(date +%s).json
fi
```

## 📊 Healthcare Security Metrics

### Key Performance Indicators

```bash
# Generate monthly security metrics
python3 fim.py --check --export /reports/fim_monthly.json

# Analyze trends
cat /reports/fim_monthly.json | jq '.changes.modified | length'
# Count: Modified files detected
cat /reports/fim_monthly.json | jq '.changes.suid | length'
# Count: SUID changes (potential privilege escalation)
```

**Metrics Dashboard:**
- Changes detected per day
- Critical system modifications
- SUID/SGID changes (privilege escalation attempts)
- Mean time to detection (MTTD)
- Mean time to response (MTTR)

## 🎯 Incident Response Playbook

### Step 1: Detection (FIM Alert)
```
⚠️  MODIFIED: /var/www/patient_portal/login.php
   Modified: 2025-10-30 02:14:37
```

### Step 2: Initial Assessment
```bash
# Check what changed
diff <(echo "OLD_HASH") <(echo "NEW_HASH")

# Review file contents
sudo cat /var/www/patient_portal/login.php | less

# Check related files
sudo python3 fim.py --check --paths /var/www/patient_portal
```

### Step 3: Containment
```bash
# Isolate affected system
sudo iptables -A INPUT -j DROP
sudo iptables -A OUTPUT -j DROP

# Preserve evidence
sudo dd if=/dev/sda of=/mnt/forensics/disk_image.dd
```

### Step 4: Eradication & Recovery
```bash
# Restore from known-good baseline
sudo rsync -av /backup/known_good/ /var/www/patient_portal/

# Verify restoration
sudo python3 fim.py --check
```

### Step 5: Documentation
- Export FIM report to incident documentation
- Timeline of events
- Root cause analysis
- Lessons learned

## 🔒 Security Hardening Checklist

### Post-FIM Deployment

- [ ] Baseline created immediately after system hardening
- [ ] Baseline stored securely (read-only, off-system backup)
- [ ] Automated monitoring configured (cron/systemd)
- [ ] Alerting integrated (email/SIEM/pager)
- [ ] Incident response playbook documented
- [ ] Team trained on FIM alerts
- [ ] Regular baseline updates scheduled
- [ ] Compliance reports automated
- [ ] False positive handling documented
- [ ] Recovery procedures tested

## 📚 Regulatory References

### HIPAA
- Security Rule §164.308(a)(1)(ii)(D)
- Security Rule §164.312(b)
- Security Rule §164.312(c)(1)

### NIST Cybersecurity Framework
- PR.DS-6: Integrity checking mechanisms
- DE.CM-7: Monitoring for unauthorized activity
- RS.AN-1: Investigate notifications from detection systems

### CIS Controls v8
- Control 3.14: Log sensitive data access
- Control 8.5: Collect detailed audit logs
- Control 11.5: File integrity monitoring

### Critical Infrastructure
- NERC CIP-007: System Security Management
- IEC 62443: Industrial Automation Security
- NIST SP 800-82: ICS Security

## 💡 Pro Tips for Healthcare Environments

1. **Separate Baselines**: Use different baselines for production vs. DR systems
2. **Change Windows**: Schedule baseline updates during maintenance windows
3. **Medical Device Monitoring**: Coordinate with biomedical engineering team
4. **HIPAA Audits**: Keep 6 years of FIM reports for compliance
5. **Vendor Changes**: Recreate baselines after EHR/EMR updates
6. **Patient Safety**: Prioritize medical device alerts over IT systems
7. **Business Associates**: Require FIM for BAAs handling ePHI

## 📞 Emergency Response Contacts

```bash
# Add to /etc/fim_contacts.conf
SECURITY_TEAM="security@hospital.org"
COMPLIANCE_OFFICER="compliance@hospital.org"
INCIDENT_RESPONSE="ir-team@hospital.org"
EMERGENCY_PAGER="+1-555-0199"
```

---

**Remember**: In healthcare and critical infrastructure, FIM isn't just about compliance - it's about patient safety and public welfare. Treat every alert as potentially life-critical until proven otherwise.
