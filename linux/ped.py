#!/usr/bin/env python3
"""
Privilege Escalation Detector (PED)
Monitors and detects privilege escalation attempts and suspicious privilege changes
Critical for healthcare environments, critical infrastructure, and insider threat detection
"""

import os
import sys
import pwd
import grp
import json
import stat
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict

class PrivilegeEscalationDetector:
    def __init__(self, baseline_file='ped_baseline.json'):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.alerts = defaultdict(list)
        self.severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
    def get_all_users(self):
        """Get all system users with their properties"""
        users = {}
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split(':')
                        if len(parts) >= 7:
                            username = parts[0]
                            users[username] = {
                                'uid': int(parts[2]),
                                'gid': int(parts[3]),
                                'home': parts[5],
                                'shell': parts[6],
                                'is_root_uid': int(parts[2]) == 0,
                                'has_shell': parts[6] not in ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin']
                            }
        except Exception as e:
            print(f"Error reading /etc/passwd: {e}")
        return users
    
    def get_sudoers_config(self):
        """Parse sudoers configuration"""
        sudoers_config = {
            'users': [],
            'groups': [],
            'nopasswd': [],
            'all_commands': []
        }
        
        try:
            # Try to read main sudoers file
            sudoers_files = ['/etc/sudoers']
            
            # Add files from sudoers.d
            sudoers_d = Path('/etc/sudoers.d')
            if sudoers_d.exists():
                sudoers_files.extend([str(f) for f in sudoers_d.iterdir() if f.is_file()])
            
            for sudoers_file in sudoers_files:
                try:
                    with open(sudoers_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            # Skip comments and empty lines
                            if not line or line.startswith('#'):
                                continue
                            
                            # Look for user/group sudo rules
                            if 'ALL=' in line:
                                parts = line.split()
                                if len(parts) > 0:
                                    entity = parts[0]
                                    if entity.startswith('%'):
                                        sudoers_config['groups'].append(entity[1:])
                                    else:
                                        sudoers_config['users'].append(entity)
                                    
                                    if 'NOPASSWD' in line:
                                        sudoers_config['nopasswd'].append(entity)
                                    
                                    if 'ALL' in line.split('=')[1]:
                                        sudoers_config['all_commands'].append(entity)
                except PermissionError:
                    pass  # Skip files we can't read
                except Exception:
                    pass
        except Exception as e:
            print(f"Warning: Could not fully parse sudoers: {e}")
        
        return sudoers_config
    
    def get_group_memberships(self):
        """Get all groups and their members"""
        groups = {}
        try:
            with open('/etc/group', 'r') as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split(':')
                        if len(parts) >= 4:
                            groupname = parts[0]
                            gid = int(parts[2])
                            members = parts[3].split(',') if parts[3] else []
                            groups[groupname] = {
                                'gid': gid,
                                'members': [m for m in members if m],
                                'is_privileged': groupname in ['root', 'sudo', 'wheel', 'admin', 'adm', 'docker']
                            }
        except Exception as e:
            print(f"Error reading /etc/group: {e}")
        return groups
    
    def find_suid_sgid_files(self, paths=None):
        """Find all SUID/SGID files"""
        if paths is None:
            paths = ['/usr', '/bin', '/sbin', '/opt', '/usr/local']
        
        suid_sgid_files = []
        
        for base_path in paths:
            if not os.path.exists(base_path):
                continue
            
            try:
                for root, dirs, files in os.walk(base_path):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        try:
                            stats = os.stat(filepath)
                            if stat.S_ISUID & stats.st_mode or stat.S_ISGID & stats.st_mode:
                                suid_sgid_files.append({
                                    'path': filepath,
                                    'is_suid': bool(stat.S_ISUID & stats.st_mode),
                                    'is_sgid': bool(stat.S_ISGID & stats.st_mode),
                                    'uid': stats.st_uid,
                                    'gid': stats.st_gid,
                                    'mode': oct(stats.st_mode),
                                    'permissions': stat.filemode(stats.st_mode)
                                })
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                continue
        
        return suid_sgid_files
    
    def check_sudo_usage(self, auth_log='/var/log/auth.log'):
        """Check recent sudo usage"""
        sudo_usage = []
        
        if not os.path.exists(auth_log):
            # Try alternative locations
            alt_logs = ['/var/log/secure', '/var/log/syslog']
            for alt in alt_logs:
                if os.path.exists(alt):
                    auth_log = alt
                    break
        
        try:
            with open(auth_log, 'r') as f:
                for line in f:
                    if 'sudo' in line.lower() and 'COMMAND' in line:
                        # Parse sudo command execution
                        sudo_usage.append(line.strip())
        except PermissionError:
            print(f"Warning: Permission denied reading {auth_log}")
        except FileNotFoundError:
            pass
        
        return sudo_usage[-100:]  # Last 100 sudo commands
    
    def check_suspicious_processes(self):
        """Check for processes running as unexpected users"""
        suspicious = []
        
        try:
            # Get process list
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 11:
                            user = parts[0]
                            pid = parts[1]
                            command = ' '.join(parts[10:])
                            
                            # Flag suspicious patterns
                            if user == 'root' and any(x in command.lower() for x in ['nc ', 'netcat', 'bash -i', '/dev/tcp', 'python -c', 'perl -e']):
                                suspicious.append({
                                    'user': user,
                                    'pid': pid,
                                    'command': command,
                                    'reason': 'Root running suspicious network/scripting command'
                                })
        except Exception as e:
            print(f"Warning: Could not check processes: {e}")
        
        return suspicious
    
    def create_baseline(self):
        """Create baseline snapshot of privilege state"""
        print(f"\n{'='*70}")
        print("Creating Privilege Escalation Baseline")
        print(f"{'='*70}\n")
        
        print("📊 Collecting system privilege information...")
        
        baseline = {
            'created': datetime.now().isoformat(),
            'users': self.get_all_users(),
            'groups': self.get_group_memberships(),
            'sudoers': self.get_sudoers_config(),
            'suid_sgid_files': self.find_suid_sgid_files()
        }
        
        # Statistics
        root_uid_users = [u for u, data in baseline['users'].items() if data['is_root_uid']]
        privileged_groups = [g for g, data in baseline['groups'].items() if data['is_privileged']]
        suid_count = len([f for f in baseline['suid_sgid_files'] if f['is_suid']])
        sgid_count = len([f for f in baseline['suid_sgid_files'] if f['is_sgid']])
        
        print(f"\n📋 Baseline Statistics:")
        print(f"   Total users: {len(baseline['users'])}")
        print(f"   Users with UID 0 (root): {len(root_uid_users)}")
        if root_uid_users:
            print(f"      → {', '.join(root_uid_users)}")
        print(f"   Total groups: {len(baseline['groups'])}")
        print(f"   Privileged groups: {len(privileged_groups)}")
        if privileged_groups:
            print(f"      → {', '.join(privileged_groups)}")
        print(f"   Users with sudo access: {len(baseline['sudoers']['users'])}")
        if baseline['sudoers']['users']:
            print(f"      → {', '.join(baseline['sudoers']['users'][:5])}")
        print(f"   NOPASSWD sudo entries: {len(baseline['sudoers']['nopasswd'])}")
        print(f"   SUID files found: {suid_count}")
        print(f"   SGID files found: {sgid_count}")
        
        # Save baseline
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(baseline, f, indent=2)
            print(f"\n✅ Baseline created successfully!")
            print(f"💾 Saved to: {self.baseline_file}")
        except Exception as e:
            print(f"\n❌ Error saving baseline: {e}")
            return False
        
        return True
    
    def load_baseline(self):
        """Load baseline from file"""
        try:
            with open(self.baseline_file, 'r') as f:
                self.baseline = json.load(f)
            return True
        except FileNotFoundError:
            print(f"❌ Baseline file not found: {self.baseline_file}")
            print("   Run with --create-baseline first")
            return False
        except json.JSONDecodeError:
            print(f"❌ Invalid baseline file format")
            return False
    
    def alert(self, severity, category, message, details=None):
        """Add an alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'category': category,
            'message': message,
            'details': details or {}
        }
        self.alerts[category].append(alert)
        self.severity_counts[severity] += 1
        
        # Print alert
        icons = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '⚡', 'LOW': 'ℹ️'}
        print(f"{icons[severity]} [{severity}] {category}: {message}")
        if details:
            for key, value in details.items():
                if isinstance(value, list):
                    print(f"   {key}: {', '.join(str(v) for v in value[:3])}")
                else:
                    print(f"   {key}: {value}")
    
    def check_privilege_escalation(self, check_sudo=True, check_processes=True):
        """Check for privilege escalation attempts"""
        if not self.baseline:
            if not self.load_baseline():
                return False
        
        print(f"\n{'='*70}")
        print("Privilege Escalation Detection")
        print(f"{'='*70}")
        print(f"Baseline created: {self.baseline.get('created', 'Unknown')}")
        print(f"{'='*70}\n")
        
        # Check for new users
        current_users = self.get_all_users()
        baseline_users = self.baseline.get('users', {})
        
        for username, user_data in current_users.items():
            if username not in baseline_users:
                severity = 'CRITICAL' if user_data['is_root_uid'] else 'HIGH'
                self.alert(
                    severity,
                    'NEW_USER',
                    f"New user account created: {username}",
                    {
                        'uid': user_data['uid'],
                        'gid': user_data['gid'],
                        'shell': user_data['shell'],
                        'is_root_uid': user_data['is_root_uid']
                    }
                )
            elif baseline_users[username]['uid'] != user_data['uid']:
                severity = 'CRITICAL' if user_data['is_root_uid'] else 'HIGH'
                self.alert(
                    severity,
                    'UID_CHANGED',
                    f"UID changed for user: {username}",
                    {
                        'old_uid': baseline_users[username]['uid'],
                        'new_uid': user_data['uid']
                    }
                )
        
        # Check for deleted users (potential cover-up)
        for username in baseline_users:
            if username not in current_users:
                self.alert(
                    'MEDIUM',
                    'USER_DELETED',
                    f"User account deleted: {username}",
                    {'uid': baseline_users[username]['uid']}
                )
        
        # Check group memberships
        current_groups = self.get_group_memberships()
        baseline_groups = self.baseline.get('groups', {})
        
        for groupname, group_data in current_groups.items():
            if groupname in baseline_groups:
                baseline_members = set(baseline_groups[groupname]['members'])
                current_members = set(group_data['members'])
                
                new_members = current_members - baseline_members
                if new_members:
                    severity = 'HIGH' if group_data['is_privileged'] else 'MEDIUM'
                    self.alert(
                        severity,
                        'GROUP_MEMBERSHIP_ADDED',
                        f"User(s) added to group '{groupname}'",
                        {
                            'new_members': list(new_members),
                            'is_privileged_group': group_data['is_privileged']
                        }
                    )
                
                removed_members = baseline_members - current_members
                if removed_members and group_data['is_privileged']:
                    self.alert(
                        'LOW',
                        'GROUP_MEMBERSHIP_REMOVED',
                        f"User(s) removed from privileged group '{groupname}'",
                        {'removed_members': list(removed_members)}
                    )
        
        # Check sudoers changes
        current_sudoers = self.get_sudoers_config()
        baseline_sudoers = self.baseline.get('sudoers', {})
        
        new_sudo_users = set(current_sudoers['users']) - set(baseline_sudoers.get('users', []))
        if new_sudo_users:
            self.alert(
                'CRITICAL',
                'SUDO_ACCESS_GRANTED',
                f"New sudo access granted",
                {'users': list(new_sudo_users)}
            )
        
        new_nopasswd = set(current_sudoers['nopasswd']) - set(baseline_sudoers.get('nopasswd', []))
        if new_nopasswd:
            self.alert(
                'CRITICAL',
                'SUDO_NOPASSWD_GRANTED',
                f"NOPASSWD sudo access granted (passwordless sudo!)",
                {'entities': list(new_nopasswd)}
            )
        
        # Check SUID/SGID files
        current_suid = self.find_suid_sgid_files()
        baseline_suid = self.baseline.get('suid_sgid_files', [])
        
        baseline_paths = {f['path']: f for f in baseline_suid}
        current_paths = {f['path']: f for f in current_suid}
        
        for path, file_info in current_paths.items():
            if path not in baseline_paths:
                self.alert(
                    'CRITICAL',
                    'NEW_SUID_SGID',
                    f"New SUID/SGID file detected",
                    {
                        'path': path,
                        'is_suid': file_info['is_suid'],
                        'is_sgid': file_info['is_sgid'],
                        'owner_uid': file_info['uid']
                    }
                )
        
        # Check for SUID/SGID bit changes
        for path in baseline_paths:
            if path in current_paths:
                baseline_f = baseline_paths[path]
                current_f = current_paths[path]
                
                if baseline_f['is_suid'] != current_f['is_suid']:
                    self.alert(
                        'CRITICAL',
                        'SUID_BIT_CHANGED',
                        f"SUID bit changed on file",
                        {
                            'path': path,
                            'old_suid': baseline_f['is_suid'],
                            'new_suid': current_f['is_suid']
                        }
                    )
                
                if baseline_f['is_sgid'] != current_f['is_sgid']:
                    self.alert(
                        'HIGH',
                        'SGID_BIT_CHANGED',
                        f"SGID bit changed on file",
                        {
                            'path': path,
                            'old_sgid': baseline_f['is_sgid'],
                            'new_sgid': current_f['is_sgid']
                        }
                    )
        
        # Check recent sudo usage
        if check_sudo:
            print(f"\n{'='*70}")
            print("Recent Sudo Usage")
            print(f"{'='*70}")
            sudo_commands = self.check_sudo_usage()
            if sudo_commands:
                print(f"Found {len(sudo_commands)} recent sudo commands")
                for cmd in sudo_commands[-10:]:  # Show last 10
                    print(f"   {cmd}")
            else:
                print("No recent sudo usage detected (or insufficient permissions)")
        
        # Check for suspicious processes
        if check_processes:
            print(f"\n{'='*70}")
            print("Suspicious Process Check")
            print(f"{'='*70}")
            suspicious = self.check_suspicious_processes()
            if suspicious:
                for proc in suspicious:
                    self.alert(
                        'HIGH',
                        'SUSPICIOUS_PROCESS',
                        f"Suspicious process running as {proc['user']}",
                        {
                            'pid': proc['pid'],
                            'command': proc['command'][:100],
                            'reason': proc['reason']
                        }
                    )
            else:
                print("No obviously suspicious processes detected")
        
        # Summary
        print(f"\n{'='*70}")
        print("DETECTION SUMMARY")
        print(f"{'='*70}")
        
        total_alerts = sum(self.severity_counts.values())
        if total_alerts == 0:
            print("✅ No privilege escalation detected - System privileges maintained!")
        else:
            print(f"⚠️  {total_alerts} ALERTS DETECTED:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if self.severity_counts[severity] > 0:
                    print(f"   {severity}: {self.severity_counts[severity]}")
            
            print(f"\n📊 Alert Categories:")
            for category, alerts in self.alerts.items():
                print(f"   {category}: {len(alerts)}")
        
        return total_alerts == 0
    
    def export_report(self, output_file='ped_report.json'):
        """Export alerts to JSON report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'baseline_file': self.baseline_file,
            'baseline_created': self.baseline.get('created', 'Unknown'),
            'total_alerts': sum(self.severity_counts.values()),
            'severity_counts': dict(self.severity_counts),
            'alerts': dict(self.alerts)
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n📄 Report exported to: {output_file}")
            return True
        except Exception as e:
            print(f"\n❌ Error exporting report: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(
        description='Privilege Escalation Detector - Monitor suspicious privilege changes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --create-baseline          # Create initial baseline
  %(prog)s --check                    # Check for privilege escalation
  %(prog)s --check --no-sudo          # Skip sudo usage check
  %(prog)s --check --export report.json  # Export alerts to JSON
  
Security Use Cases:
  - Detect unauthorized privilege escalation
  - Monitor insider threat activities
  - Track sudo abuse and misuse
  - Identify backdoor account creation
  - Detect SUID/SGID manipulation
  - Compliance auditing (separation of duties)
  - Incident response and forensics
        """
    )
    
    parser.add_argument('-b', '--baseline',
                       default='ped_baseline.json',
                       help='Baseline file path (default: ped_baseline.json)')
    
    parser.add_argument('--create-baseline',
                       action='store_true',
                       help='Create new privilege baseline')
    
    parser.add_argument('--check',
                       action='store_true',
                       help='Check for privilege escalation')
    
    parser.add_argument('--no-sudo',
                       action='store_true',
                       help='Skip sudo usage analysis')
    
    parser.add_argument('--no-processes',
                       action='store_true',
                       help='Skip process analysis')
    
    parser.add_argument('-e', '--export',
                       help='Export alerts to JSON file')
    
    args = parser.parse_args()
    
    # Create detector instance
    ped = PrivilegeEscalationDetector(baseline_file=args.baseline)
    
    # Execute requested operation
    if args.create_baseline:
        ped.create_baseline()
    
    elif args.check:
        success = ped.check_privilege_escalation(
            check_sudo=not args.no_sudo,
            check_processes=not args.no_processes
        )
        if args.export:
            ped.export_report(args.export)
        sys.exit(0 if success else 1)
    
    else:
        parser.print_help()
        print("\n💡 Tip: Start with --create-baseline to create an initial snapshot")

if __name__ == '__main__':
    main()
