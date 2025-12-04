# SSL/TLS Certificate Monitor

A comprehensive SSL/TLS certificate monitoring tool that tracks certificate health, expiration dates, validates certificate chains, detects weak ciphers, and prevents outages across your infrastructure.

## 🎯 Perfect For

- **Preventing Outages** - Never miss a certificate expiration
- **Healthcare Compliance (HIPAA)** - Ensure encrypted patient data transmission
- **PCI-DSS Compliance** - Monitor payment processing encryption
- **Critical Infrastructure** - Maintain secure SCADA/ICS connections
- **DevOps Teams** - Automated certificate lifecycle management
- **Security Operations** - Continuous security posture monitoring

## ✨ Features

- ✅ **Expiration Monitoring** - Track certificate expiration dates
- ✅ **Certificate Chain Validation** - Verify trust chain integrity
- ✅ **Weak Cipher Detection** - Identify insecure cipher suites
- ✅ **TLS Version Analysis** - Flag outdated protocols (TLS 1.0/1.1)
- ✅ **Hostname Verification** - Validate certificate matches domain
- ✅ **Multi-Target Scanning** - Monitor multiple hosts efficiently
- ✅ **Severity Classification** - CRITICAL, HIGH, MEDIUM, OK
- ✅ **JSON Reporting** - Export for automation and SIEM
- ✅ **Expiration Timeline** - Visual timeline of upcoming expirations
- ✅ **Zero Dependencies** - Pure Python 3 standard library

## 🚀 Quick Start

### Check Single Certificate
```bash
# Check website certificate
python3 ssl_monitor.py example.com

# Check with specific port
python3 ssl_monitor.py mail.example.com:587

# Check with HTTPS URL
python3 ssl_monitor.py https://example.com
```

### Check Multiple Certificates
```bash
# Check multiple sites
python3 ssl_monitor.py example.com google.com github.com

# Read targets from file
python3 ssl_monitor.py -f domains.txt

# Export results
python3 ssl_monitor.py example.com --export cert_report.json
```

### Custom Configuration
```bash
# Longer timeout for slow connections
python3 ssl_monitor.py example.com --timeout 10

# Check all infrastructure hosts
cat servers.txt | xargs python3 ssl_monitor.py
```

## 📊 Sample Output

```
======================================================================
SSL/TLS Certificate Monitor - Starting Checks
======================================================================
Targets: 3
Started: 2025-10-30 15:30:00
======================================================================

[*] Checking example.com:443... ✓ OK
[*] Checking old-server.com:443... 🔴 CRITICAL
[*] Checking mail.example.com:587... 🟡 MEDIUM

======================================================================
SSL/TLS Certificate Report
======================================================================

📊 SUMMARY
──────────────────────────────────────────────────────────────────────
Total certificates checked: 3
Expired: 0
Expiring within 30 days: 1
Weak ciphers detected: 0

Severity breakdown:
  🔴 CRITICAL: 1
  🟠 HIGH: 0
  🟡 MEDIUM: 1
  ✓ OK: 1

🔍 CERTIFICATE DETAILS
──────────────────────────────────────────────────────────────────────

🔴 old-server.com:443
──────────────────────────────────────────────────────────────────────
Common Name: old-server.com
Organization: Example Corp
Issuer: Let's Encrypt Authority X3
Valid from: 2025-08-15
Valid until: 2025-11-08
Days until expiry: 7 days (CRITICAL)

TLS/Cipher Information:
  TLS Version: TLSv1.2
  Cipher Suite: ECDHE-RSA-AES128-GCM-SHA256
  Cipher Strength: 128 bits

⚠️  Issues Detected:
  • CRITICAL: Certificate expires in 7 days or less

🟡 mail.example.com:587
──────────────────────────────────────────────────────────────────────
Common Name: *.example.com
Organization: Example Corp
Issuer: DigiCert SHA2 Secure Server CA
Valid from: 2025-01-15
Valid until: 2025-12-15
Days until expiry: 45 days (MEDIUM)

TLS/Cipher Information:
  TLS Version: TLSv1.2
  Cipher Suite: ECDHE-RSA-AES256-GCM-SHA384
  Cipher Strength: 256 bits

Subject Alternative Names:
  • *.example.com
  • example.com
  • mail.example.com

⚠️  Issues Detected:
  • MEDIUM: Certificate expires in 60 days or less

✓ example.com:443
──────────────────────────────────────────────────────────────────────
Common Name: example.com
Organization: Example Corp
Issuer: Let's Encrypt Authority X3
Valid from: 2025-09-01
Valid until: 2026-12-01
Days until expiry: 365 days

TLS/Cipher Information:
  TLS Version: TLSv1.3
  Cipher Suite: TLS_AES_256_GCM_SHA384
  Cipher Strength: 256 bits

📅 EXPIRATION TIMELINE
──────────────────────────────────────────────────────────────────────

🔴 Expiring This Week (1):
  • old-server.com:443 - 7 days

🟡 Expiring This Month (0):

🟡 Expiring This Quarter (1):
  • mail.example.com:587 - 45 days

🔒 SECURITY RECOMMENDATIONS
──────────────────────────────────────────────────────────────────────
• HIGH: Renew certificates expiring within 30 days
• Implement certificate monitoring and automated renewal
• Set up alerts for certificates expiring within 30 days
• Consider using automated certificate management (Let's Encrypt, ACME)
• Regularly audit certificate chain validity

======================================================================
```

## 🔍 What Gets Detected

### Certificate Issues
```
CRITICAL (Immediate Action Required):
  • Expired certificates (days_until_expiry < 0)
  • Certificates expiring within 7 days

HIGH (Action Required Soon):
  • Certificates expiring within 30 days
  • Weak cipher suites (DES, RC4, 3DES, MD5)
  • Outdated TLS versions (TLS 1.0, TLS 1.1, SSLv2, SSLv3)
  • Encryption strength < 128 bits

MEDIUM (Should Be Addressed):
  • Certificates expiring within 60 days
  • Hostname mismatch with certificate
  • Missing Subject Alternative Names

OK (No Issues):
  • Valid certificate with 60+ days until expiration
  • TLS 1.2+ with strong cipher suites
  • Proper hostname matching
```

### Weak Ciphers Flagged
- DES, 3DES (deprecated)
- RC4 (broken)
- MD5 (cryptographically broken)
- NULL ciphers (no encryption)
- EXPORT ciphers (intentionally weak)
- Anonymous DH (no authentication)
- CBC mode ciphers (BEAST/Lucky13 vulnerable)

### Outdated TLS Versions
- SSLv2, SSLv3 (completely broken)
- TLS 1.0 (deprecated, BEAST attack)
- TLS 1.1 (deprecated, removed from browsers)

## 💡 Usage Examples

### Healthcare Environment (HIPAA)
```bash
# Monitor patient portal certificates
python3 ssl_monitor.py \
    patient-portal.hospital.com \
    ehr-system.hospital.com \
    telehealth.hospital.com \
    --export hipaa_cert_audit.json

# Daily compliance check
python3 ssl_monitor.py -f healthcare_systems.txt \
    >> /var/log/cert_monitoring.log
```

**Healthcare Systems List (healthcare_systems.txt):**
```
patient-portal.hospital.com
ehr-system.hospital.com:8443
medical-devices.hospital.com
telehealth.hospital.com
api.hospital.com
```

### E-commerce / PCI-DSS
```bash
# Monitor payment processing certificates
python3 ssl_monitor.py \
    checkout.example.com \
    api.stripe.com \
    gateway.example.com \
    --export pci_compliance.json

# Weekly PCI-DSS audit
python3 ssl_monitor.py -f payment_systems.txt
```

### Critical Infrastructure
```bash
# Monitor SCADA/ICS web interfaces
python3 ssl_monitor.py \
    scada-hmi.factory.com \
    plc-web.factory.com \
    historian.factory.com \
    --export infrastructure_certs.json

# Check industrial control systems
python3 ssl_monitor.py \
    control-system.grid.local:8443 \
    monitoring.grid.local:9443
```

### Automated Monitoring
```bash
#!/bin/bash
# Daily certificate monitoring script

DOMAINS_FILE="/etc/ssl-monitor/domains.txt"
REPORT_DIR="/var/reports/certificates"
DATE=$(date +%Y%m%d)

# Run scan
python3 ssl_monitor.py -f "$DOMAINS_FILE" \
    --export "${REPORT_DIR}/cert_report_${DATE}.json"

# Check for critical issues
CRITICAL=$(jq '.summary.by_severity.critical' \
    "${REPORT_DIR}/cert_report_${DATE}.json")

if [ "$CRITICAL" -gt 0 ]; then
    echo "CRITICAL: $CRITICAL certificates require immediate attention" | \
        mail -s "Certificate Alert - CRITICAL" devops@company.com
fi

# Check for expiring soon
EXPIRING=$(jq '.summary.expiring_30_days' \
    "${REPORT_DIR}/cert_report_${DATE}.json")

if [ "$EXPIRING" -gt 0 ]; then
    echo "WARNING: $EXPIRING certificates expiring within 30 days" | \
        mail -s "Certificate Alert - Expiring Soon" devops@company.com
fi
```

## 🚨 Real-World Scenarios

### Scenario 1: Prevented Patient Portal Outage
```
[*] Hospital Patient Portal Monitoring
[*] Date: 2025-10-15

Result: 
  Certificate: patient-portal.hospital.com
  Expires: 2025-10-22 (7 days)
  Severity: CRITICAL

Action Taken:
  • Emergency certificate renewal initiated
  • New cert installed with 90-day validity
  • Prevented patient access disruption
  • Maintained HIPAA compliance

Lesson: Automated monitoring prevented service outage
         that could have affected patient care
```

### Scenario 2: E-commerce Security Issue
```
[*] E-commerce Platform Audit
[*] Date: 2025-09-20

Result:
  Certificate: checkout.example.com
  TLS Version: TLSv1.0
  Cipher: DES-CBC3-SHA (weak)
  Severity: HIGH

Action Taken:
  • Upgraded to TLS 1.2 minimum
  • Enabled modern cipher suites only
  • Passed PCI-DSS compliance audit
  • Protected customer payment data

Lesson: Weak cipher detection prevented
         potential PCI-DSS compliance failure
```

### Scenario 3: Critical Infrastructure Protection
```
[*] Power Grid Control System
[*] Date: 2025-08-30

Result:
  Certificate: scada-hmi.grid.local:8443
  Hostname Mismatch: scada-system.local != scada-hmi.grid.local
  Severity: MEDIUM

Action Taken:
  • Generated new certificate with correct SANs
  • Included all valid hostnames
  • Eliminated browser security warnings
  • Maintained secure operator access

Lesson: Hostname verification prevented
         operator access issues and security warnings
```

## 📁 File Structure

```
ssl_monitor.py          - Main monitoring script
cert_report.json        - Example report (created with --export)
domains.txt             - Example target list
```

## 🔧 Command-Line Options

```
usage: ssl_monitor.py [-h] [-f FILE] [--timeout TIMEOUT] [--export EXPORT]
                      [targets ...]

positional arguments:
  targets              Target hostnames or URLs

options:
  -h, --help           Show help message
  -f, --file FILE      Read targets from file (one per line)
  --timeout INT        Connection timeout in seconds (default: 10)
  --export FILE        Export report to JSON file
```

## 🎓 Advanced Usage

### Automated Renewal Integration
```bash
#!/bin/bash
# Check certificates and auto-renew with Let's Encrypt

python3 ssl_monitor.py -f domains.txt --export /tmp/certs.json

# Extract expiring domains
EXPIRING=$(jq -r '.certificates[] | 
    select(.days_until_expiry < 30) | 
    .hostname' /tmp/certs.json)

# Renew with certbot
for domain in $EXPIRING; do
    echo "Renewing $domain..."
    certbot renew --cert-name "$domain" --force-renewal
    
    # Reload web server
    systemctl reload nginx
done
```

### Monitoring Dashboard Integration
```python
#!/usr/bin/env python3
import subprocess
import json
from prometheus_client import Gauge, CollectorRegistry, push_to_gateway

# Run certificate check
subprocess.run([
    'python3', 'ssl_monitor.py',
    '-f', 'domains.txt',
    '--export', '/tmp/certs.json'
])

# Load results
with open('/tmp/certs.json', 'r') as f:
    data = json.load(f)

# Push to Prometheus
registry = CollectorRegistry()
cert_expiry = Gauge('ssl_cert_days_until_expiry', 
                    'Days until SSL cert expires',
                    ['hostname'], registry=registry)

for cert in data['certificates']:
    cert_expiry.labels(hostname=cert['hostname']).set(
        cert['days_until_expiry']
    )

push_to_gateway('pushgateway:9091', job='ssl_monitor', registry=registry)
```

### Slack/Teams Notifications
```python
#!/usr/bin/env python3
import subprocess
import json
import requests

# Run scan
subprocess.run([
    'python3', 'ssl_monitor.py',
    '-f', 'domains.txt',
    '--export', '/tmp/certs.json'
])

# Load results
with open('/tmp/certs.json', 'r') as f:
    data = json.load(f)

# Check for issues
if data['summary']['by_severity']['critical'] > 0:
    message = {
        "text": f"⚠️ CRITICAL: {data['summary']['by_severity']['critical']} "
                f"SSL certificates require immediate attention!",
        "attachments": [{
            "color": "danger",
            "fields": [
                {
                    "title": "Expired",
                    "value": str(data['summary']['expired']),
                    "short": True
                },
                {
                    "title": "Expiring Soon (30 days)",
                    "value": str(data['summary']['expiring_30_days']),
                    "short": True
                }
            ]
        }]
    }
    
    # Send to Slack
    requests.post(
        'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
        json=message
    )
```

### Ansible Playbook Integration
```yaml
---
- name: Monitor SSL Certificates
  hosts: monitoring_server
  tasks:
    - name: Run SSL certificate check
      command: python3 /usr/local/bin/ssl_monitor.py -f /etc/ssl-monitor/domains.txt
      register: ssl_check
      changed_when: false
      
    - name: Parse results
      set_fact:
        cert_data: "{{ ssl_check.stdout | from_json }}"
      
    - name: Alert on critical certificates
      mail:
        subject: "CRITICAL: SSL Certificates Expiring"
        body: "{{ cert_data.summary.by_severity.critical }} certificates need renewal"
        to: devops@company.com
      when: cert_data.summary.by_severity.critical > 0
```

### Grafana Dashboard
```json
{
  "dashboard": {
    "title": "SSL Certificate Monitoring",
    "panels": [
      {
        "title": "Days Until Expiration",
        "type": "graph",
        "targets": [
          {
            "expr": "ssl_cert_days_until_expiry"
          }
        ]
      },
      {
        "title": "Certificates by Severity",
        "type": "pie",
        "targets": [
          {
            "expr": "sum(ssl_cert_severity) by (severity)"
          }
        ]
      }
    ]
  }
}
```

## ⚠️ Important Notes

### Best Practices
- **Monitor Daily**: Run checks at least once per day
- **Alert Thresholds**: Alert at 30 days, escalate at 7 days
- **Automated Renewal**: Use ACME protocol (Let's Encrypt) where possible
- **Certificate Inventory**: Maintain list of all certificates
- **Backup Certificates**: Keep validated backups of certificates and keys

### Common Certificate Issues
```
Issue: "hostname mismatch"
Cause: Certificate CN/SAN doesn't match domain
Fix: Generate new cert with correct hostname(s)

Issue: "self-signed certificate"
Cause: Certificate not signed by trusted CA
Fix: Use proper CA (Let's Encrypt, DigiCert, etc.)

Issue: "expired certificate"
Cause: Certificate past its validity period
Fix: Renew immediately with new certificate

Issue: "weak cipher"
Cause: Server configured with insecure ciphers
Fix: Update server config to use modern ciphers only

Issue: "outdated TLS version"
Cause: Server allows TLS 1.0/1.1
Fix: Configure server for TLS 1.2+ only
```

### Certificate Lifecycle Management
```
1. Certificate Acquisition
   • Generate CSR (Certificate Signing Request)
   • Submit to Certificate Authority
   • Validate domain ownership
   • Receive signed certificate

2. Certificate Installation
   • Install certificate and intermediate chain
   • Configure web server (nginx/apache)
   • Test HTTPS functionality
   • Verify with SSL checker

3. Ongoing Monitoring
   • Daily automated checks
   • 30-day expiration alerts
   • 7-day critical alerts
   • Track cipher/TLS version

4. Certificate Renewal
   • Renew 30+ days before expiration
   • Test new certificate
   • Zero-downtime deployment
   • Update monitoring

5. Certificate Revocation
   • Revoke if compromised
   • Generate new certificate
   • Update all systems
   • Monitor for misuse
```

## 🤝 Integration Examples

### With Nagios
```bash
#!/bin/bash
# Nagios check script for SSL certificates

python3 /usr/local/bin/ssl_monitor.py "$1" --export /tmp/cert_check.json

CRITICAL=$(jq '.summary.by_severity.critical' /tmp/cert_check.json)
HIGH=$(jq '.summary.by_severity.high' /tmp/cert_check.json)

if [ "$CRITICAL" -gt 0 ]; then
    echo "CRITICAL - $CRITICAL certificates expired or expiring within 7 days"
    exit 2
elif [ "$HIGH" -gt 0 ]; then
    echo "WARNING - $HIGH certificates expiring within 30 days"
    exit 1
else
    echo "OK - All certificates valid"
    exit 0
fi
```

### With Zabbix
```python
#!/usr/bin/env python3
import sys
import json
import subprocess

# Run check
result = subprocess.run(
    ['python3', 'ssl_monitor.py', sys.argv[1], '--export', '-'],
    capture_output=True, text=True
)

data = json.loads(result.stdout)
cert = data['certificates'][0]

# Return days until expiry for Zabbix
print(cert['days_until_expiry'])
```

### With Terraform
```hcl
resource "null_resource" "ssl_check" {
  provisioner "local-exec" {
    command = "python3 ssl_monitor.py ${var.domain} --export ssl_report.json"
  }
  
  provisioner "local-exec" {
    when    = destroy
    command = "rm -f ssl_report.json"
  }
}
```

## 📚 References

- RFC 5280 (Internet X.509 Public Key Infrastructure Certificate)
- RFC 8446 (TLS 1.3)
- OWASP Transport Layer Protection Cheat Sheet
- Mozilla SSL Configuration Generator
- SSL Labs Best Practices
- NIST SP 800-52 (Guidelines for TLS Implementations)

## 📄 License

MIT License - Use freely for certificate monitoring

## 👨‍💻 Author

Created for DevOps teams, security operations, and infrastructure engineers.

---

**Remember**: A single expired certificate can cause complete service outages. Automate your certificate monitoring today!
