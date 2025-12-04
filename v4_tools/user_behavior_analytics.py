#!/usr/bin/env python3
"""
User Behavior Analytics (UBA)
Detects insider threats, compromised credentials, and abnormal user behavior
Critical for catching human-driven threats that bypass perimeter defenses
"""

import os
import sys
import re
import json
import time
import argparse
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path

class UserBehaviorAnalytics:
    def __init__(self, baseline_file='uba_baseline.json'):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.alerts = defaultdict(list)
        self.severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        # User behavior tracking
        self.user_activity = defaultdict(lambda: {
            'logins': [],
            'failed_logins': [],
            'login_times': [],
            'login_days': set(),
            'sudo_commands': [],
            'file_accesses': [],
            'processes': [],
            'network_connections': [],
            'total_sessions': 0,
            'avg_session_duration': 0
        })
        
        # Thresholds for anomaly detection
        self.thresholds = {
            'max_failed_logins': 5,  # Per hour
            'unusual_hour_start': 22,  # 10 PM
            'unusual_hour_end': 6,  # 6 AM
            'max_sudo_per_hour': 20,
            'max_file_access_per_hour': 1000,
            'max_sessions_per_day': 50,
            'geographic_anomaly_km': 500,  # km between login locations
        }
        
        # Suspicious patterns
        self.suspicious_patterns = {
            'privilege_escalation': [
                r'sudo su\s*-',
                r'sudo\s+bash',
                r'sudo\s+sh',
                r'sudo\s+passwd',
                r'usermod.*-G.*sudo',
            ],
            'data_exfiltration': [
                r'scp\s+.*@',
                r'rsync\s+.*@',
                r'curl\s+.*-T',
                r'wget\s+.*--post-file',
                r'tar\s+.*\|\s*ssh',
            ],
            'credential_theft': [
                r'cat\s+/etc/shadow',
                r'cat\s+/etc/passwd',
                r'cat.*\.ssh/id_rsa',
                r'mimikatz',
                r'secretsdump',
            ],
            'persistence': [
                r'crontab\s+-e',
                r'systemctl.*enable',
                r'\.bashrc',
                r'\.profile',
                r'/etc/rc\.local',
            ]
        }
        
        # Log files to monitor
        self.log_files = {
            'auth': '/var/log/auth.log',
            'auth_backup': '/var/log/auth.log.1',
            'secure': '/var/log/secure',
            'sudo': '/var/log/sudo.log',
            'syslog': '/var/log/syslog',
        }
        
    def parse_auth_log(self, log_file):
        """Parse authentication logs"""
        entries = []
        
        if not os.path.exists(log_file):
            return entries
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # Successful login: "Accepted password for user from IP"
                    if 'Accepted' in line and 'for' in line:
                        match = re.search(r'Accepted \w+ for (\w+) from ([\d\.]+)', line)
                        if match:
                            user, ip = match.groups()
                            timestamp = self._extract_timestamp(line)
                            entries.append({
                                'type': 'login_success',
                                'user': user,
                                'ip': ip,
                                'timestamp': timestamp,
                                'source': log_file
                            })
                    
                    # Failed login: "Failed password for user from IP"
                    elif 'Failed password' in line:
                        match = re.search(r'Failed password for (\w+) from ([\d\.]+)', line)
                        if match:
                            user, ip = match.groups()
                            timestamp = self._extract_timestamp(line)
                            entries.append({
                                'type': 'login_failed',
                                'user': user,
                                'ip': ip,
                                'timestamp': timestamp,
                                'source': log_file
                            })
                    
                    # Sudo commands
                    elif 'sudo:' in line and 'COMMAND=' in line:
                        match = re.search(r'sudo:.*?(\w+)\s+:.*?COMMAND=(.*?)$', line)
                        if match:
                            user, command = match.groups()
                            timestamp = self._extract_timestamp(line)
                            entries.append({
                                'type': 'sudo_command',
                                'user': user,
                                'command': command.strip(),
                                'timestamp': timestamp,
                                'source': log_file
                            })
                    
                    # User creation
                    elif 'new user:' in line or 'useradd' in line:
                        match = re.search(r'new user:.*?name=(\w+)', line)
                        if match:
                            user = match.group(1)
                            timestamp = self._extract_timestamp(line)
                            entries.append({
                                'type': 'user_created',
                                'user': user,
                                'timestamp': timestamp,
                                'source': log_file
                            })
        
        except Exception as e:
            print(f"Warning: Error parsing {log_file}: {e}")
        
        return entries
    
    def _extract_timestamp(self, log_line):
        """Extract timestamp from log line"""
        # Try to extract timestamp (format: Dec  4 10:15:30)
        match = re.match(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', log_line)
        if match:
            timestamp_str = match.group(1)
            try:
                # Add current year
                year = datetime.now().year
                dt = datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                return dt.isoformat()
            except:
                pass
        
        return datetime.now().isoformat()
    
    def analyze_login_patterns(self, entries):
        """Analyze login patterns for anomalies"""
        user_logins = defaultdict(list)
        user_failed = defaultdict(list)
        
        for entry in entries:
            user = entry.get('user', 'unknown')
            timestamp = entry.get('timestamp', '')
            
            if entry['type'] == 'login_success':
                user_logins[user].append(entry)
                
                # Track login times
                try:
                    dt = datetime.fromisoformat(timestamp)
                    hour = dt.hour
                    day = dt.strftime('%Y-%m-%d')
                    
                    self.user_activity[user]['login_times'].append(hour)
                    self.user_activity[user]['login_days'].add(day)
                    self.user_activity[user]['total_sessions'] += 1
                    
                    # Check for unusual hours
                    if hour >= self.thresholds['unusual_hour_start'] or hour < self.thresholds['unusual_hour_end']:
                        self.alerts['unusual_hours'].append({
                            'severity': 'MEDIUM',
                            'description': 'After-hours login detected',
                            'user': user,
                            'time': dt.strftime('%Y-%m-%d %H:%M:%S'),
                            'ip': entry.get('ip', 'unknown'),
                            'hour': hour
                        })
                        self.severity_counts['MEDIUM'] += 1
                
                except Exception:
                    pass
            
            elif entry['type'] == 'login_failed':
                user_failed[user].append(entry)
        
        # Check for brute force attempts
        for user, failures in user_failed.items():
            if len(failures) >= self.thresholds['max_failed_logins']:
                unique_ips = set(f.get('ip', 'unknown') for f in failures)
                
                self.alerts['brute_force'].append({
                    'severity': 'HIGH' if len(failures) > 10 else 'MEDIUM',
                    'description': 'Multiple failed login attempts',
                    'user': user,
                    'attempts': len(failures),
                    'unique_ips': len(unique_ips),
                    'ips': list(unique_ips)[:5],  # First 5 IPs
                    'first_attempt': failures[0].get('timestamp', 'unknown'),
                    'last_attempt': failures[-1].get('timestamp', 'unknown')
                })
                
                severity = 'HIGH' if len(failures) > 10 else 'MEDIUM'
                self.severity_counts[severity] += 1
        
        # Check for excessive sessions per day
        for user, activity in self.user_activity.items():
            days = len(activity['login_days'])
            if days > 0:
                avg_sessions_per_day = activity['total_sessions'] / days
                if avg_sessions_per_day > self.thresholds['max_sessions_per_day']:
                    self.alerts['excessive_sessions'].append({
                        'severity': 'MEDIUM',
                        'description': 'Unusually high number of sessions',
                        'user': user,
                        'total_sessions': activity['total_sessions'],
                        'days': days,
                        'avg_per_day': round(avg_sessions_per_day, 2)
                    })
                    self.severity_counts['MEDIUM'] += 1
    
    def analyze_sudo_commands(self, entries):
        """Analyze sudo command patterns"""
        user_sudo = defaultdict(list)
        
        for entry in entries:
            if entry['type'] == 'sudo_command':
                user = entry.get('user', 'unknown')
                command = entry.get('command', '')
                
                user_sudo[user].append(entry)
                
                # Check for suspicious patterns
                for pattern_type, patterns in self.suspicious_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, command, re.IGNORECASE):
                            severity = 'CRITICAL' if pattern_type in ['credential_theft', 'privilege_escalation'] else 'HIGH'
                            
                            self.alerts[f'suspicious_{pattern_type}'].append({
                                'severity': severity,
                                'description': f'Suspicious {pattern_type.replace("_", " ")} command',
                                'user': user,
                                'command': command[:200],  # Truncate long commands
                                'pattern': pattern,
                                'timestamp': entry.get('timestamp', 'unknown')
                            })
                            self.severity_counts[severity] += 1
        
        # Check for excessive sudo usage
        for user, commands in user_sudo.items():
            if len(commands) > self.thresholds['max_sudo_per_hour']:
                self.alerts['excessive_sudo'].append({
                    'severity': 'MEDIUM',
                    'description': 'Excessive sudo command usage',
                    'user': user,
                    'count': len(commands),
                    'threshold': self.thresholds['max_sudo_per_hour']
                })
                self.severity_counts['MEDIUM'] += 1
    
    def detect_privilege_escalation_attempts(self, entries):
        """Detect attempts to escalate privileges"""
        for entry in entries:
            # User creation by non-root
            if entry['type'] == 'user_created':
                user = entry.get('user', 'unknown')
                if user != 'root':
                    self.alerts['privilege_escalation'].append({
                        'severity': 'HIGH',
                        'description': 'User creation by non-root user',
                        'user': user,
                        'created_user': entry.get('created_user', 'unknown'),
                        'timestamp': entry.get('timestamp', 'unknown')
                    })
                    self.severity_counts['HIGH'] += 1
    
    def detect_geographic_anomalies(self, entries):
        """Detect logins from unusual locations (basic IP-based)"""
        user_ips = defaultdict(set)
        
        for entry in entries:
            if entry['type'] == 'login_success':
                user = entry.get('user', 'unknown')
                ip = entry.get('ip', 'unknown')
                user_ips[user].add(ip)
        
        # Simple check: multiple IPs for same user
        for user, ips in user_ips.items():
            if len(ips) > 5:  # More than 5 different IPs
                self.alerts['geographic_anomaly'].append({
                    'severity': 'MEDIUM',
                    'description': 'Logins from multiple IP addresses',
                    'user': user,
                    'ip_count': len(ips),
                    'ips': list(ips)[:10]  # First 10 IPs
                })
                self.severity_counts['MEDIUM'] += 1
    
    def compare_with_baseline(self):
        """Compare current behavior with baseline"""
        if not os.path.exists(self.baseline_file):
            return
        
        try:
            with open(self.baseline_file, 'r') as f:
                self.baseline = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load baseline: {e}")
            return
        
        baseline_users = set(self.baseline.get('users', []))
        current_users = set(self.user_activity.keys())
        
        # Check for new users
        new_users = current_users - baseline_users
        if new_users:
            for user in new_users:
                self.alerts['new_user'].append({
                    'severity': 'MEDIUM',
                    'description': 'New user activity detected',
                    'user': user,
                    'sessions': self.user_activity[user]['total_sessions']
                })
                self.severity_counts['MEDIUM'] += 1
        
        # Compare login hours
        for user, activity in self.user_activity.items():
            if user in self.baseline.get('user_profiles', {}):
                baseline_hours = set(self.baseline['user_profiles'][user].get('typical_hours', []))
                current_hours = set(activity['login_times'])
                
                unusual_hours = current_hours - baseline_hours
                if len(unusual_hours) > 3:  # More than 3 new hours
                    self.alerts['unusual_login_times'].append({
                        'severity': 'MEDIUM',
                        'description': 'Login at unusual times compared to baseline',
                        'user': user,
                        'unusual_hours': sorted(list(unusual_hours)),
                        'typical_hours': sorted(list(baseline_hours))
                    })
                    self.severity_counts['MEDIUM'] += 1
    
    def scan(self):
        """Scan logs for user behavior anomalies"""
        print(f"\n{'='*70}")
        print("USER BEHAVIOR ANALYTICS - Scan Started")
        print(f"{'='*70}\n")
        
        all_entries = []
        
        # Parse authentication logs
        print("[*] Parsing authentication logs...")
        for log_name, log_path in self.log_files.items():
            if os.path.exists(log_path):
                print(f"[*] Parsing {log_name}: {log_path}")
                entries = self.parse_auth_log(log_path)
                all_entries.extend(entries)
                print(f"    • Found {len(entries)} events")
        
        print(f"\n[+] Total events: {len(all_entries)}")
        
        # Analyze patterns
        print("\n[*] Analyzing login patterns...")
        self.analyze_login_patterns(all_entries)
        
        print("[*] Analyzing sudo command patterns...")
        self.analyze_sudo_commands(all_entries)
        
        print("[*] Detecting privilege escalation attempts...")
        self.detect_privilege_escalation_attempts(all_entries)
        
        print("[*] Detecting geographic anomalies...")
        self.detect_geographic_anomalies(all_entries)
        
        print("[*] Comparing with baseline...")
        self.compare_with_baseline()
        
        return self.alerts
    
    def create_baseline(self):
        """Create baseline of normal user behavior"""
        print(f"\n{'='*70}")
        print("USER BEHAVIOR ANALYTICS - Creating Baseline")
        print(f"{'='*70}\n")
        
        # Parse logs
        all_entries = []
        for log_name, log_path in self.log_files.items():
            if os.path.exists(log_path):
                entries = self.parse_auth_log(log_path)
                all_entries.extend(entries)
        
        # Build user profiles
        user_profiles = defaultdict(lambda: {
            'typical_hours': set(),
            'typical_days': set(),
            'avg_sessions_per_day': 0,
            'common_ips': set()
        })
        
        for entry in all_entries:
            if entry['type'] == 'login_success':
                user = entry.get('user', 'unknown')
                
                try:
                    dt = datetime.fromisoformat(entry.get('timestamp', ''))
                    hour = dt.hour
                    day = dt.strftime('%A')  # Day name
                    
                    user_profiles[user]['typical_hours'].add(hour)
                    user_profiles[user]['typical_days'].add(day)
                    user_profiles[user]['common_ips'].add(entry.get('ip', 'unknown'))
                except:
                    pass
        
        # Convert sets to lists for JSON serialization
        baseline_data = {
            'timestamp': datetime.now().isoformat(),
            'users': list(user_profiles.keys()),
            'user_profiles': {
                user: {
                    'typical_hours': sorted(list(profile['typical_hours'])),
                    'typical_days': list(profile['typical_days']),
                    'common_ips': list(profile['common_ips'])
                }
                for user, profile in user_profiles.items()
            }
        }
        
        # Save baseline
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)
        
        print(f"[+] Baseline created: {self.baseline_file}")
        print(f"[+] Tracked {len(user_profiles)} users")
        print(f"[+] Based on {len(all_entries)} events")
        
        return True
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{'='*70}")
        print("SCAN SUMMARY")
        print(f"{'='*70}\n")
        
        total_alerts = sum(self.severity_counts.values())
        
        print(f"Total Alerts: {total_alerts}")
        print(f"  CRITICAL: {self.severity_counts['CRITICAL']}")
        print(f"  HIGH:     {self.severity_counts['HIGH']}")
        print(f"  MEDIUM:   {self.severity_counts['MEDIUM']}")
        print(f"  LOW:      {self.severity_counts['LOW']}")
        
        if self.user_activity:
            print(f"\nUser Activity Summary:")
            for user, activity in sorted(self.user_activity.items()):
                if activity['total_sessions'] > 0:
                    avg_hour = sum(activity['login_times']) / len(activity['login_times']) if activity['login_times'] else 0
                    print(f"  • {user}: {activity['total_sessions']} sessions, avg login hour: {int(avg_hour)}")
        
        if total_alerts == 0:
            print("\n✓ No suspicious user behavior detected")
        else:
            print(f"\n⚠ {total_alerts} behavioral anomalies detected")
            
            if self.alerts:
                print("\nAlert Breakdown:")
                for alert_type, alerts in self.alerts.items():
                    if alerts:
                        print(f"  • {alert_type.replace('_', ' ').title()}: {len(alerts)}")
    
    def export_results(self, output_file):
        """Export results to JSON"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_alerts': sum(self.severity_counts.values()),
                'severity_counts': self.severity_counts,
            },
            'alerts': dict(self.alerts),
            'user_activity': {
                user: {
                    'total_sessions': activity['total_sessions'],
                    'login_days': list(activity['login_days']),
                    'avg_login_hour': sum(activity['login_times']) / len(activity['login_times']) if activity['login_times'] else 0
                }
                for user, activity in self.user_activity.items()
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Results exported to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='User Behavior Analytics - Detect insider threats and compromised credentials',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create baseline
  python3 user_behavior_analytics.py --baseline
  
  # Run scan
  python3 user_behavior_analytics.py --scan
  
  # Run scan and export results
  python3 user_behavior_analytics.py --scan --export uba_results.json
  
  # Continuous monitoring (24 hours, check every 30 minutes)
  python3 user_behavior_analytics.py --monitor --duration 86400 --interval 1800
        """
    )
    
    parser.add_argument('--baseline', action='store_true',
                       help='Create baseline of normal user behavior')
    parser.add_argument('--scan', action='store_true',
                       help='Scan logs once')
    parser.add_argument('--monitor', action='store_true',
                       help='Continuous monitoring mode')
    parser.add_argument('--duration', type=int, default=3600,
                       help='Monitoring duration in seconds (default: 3600)')
    parser.add_argument('--interval', type=int, default=300,
                       help='Monitoring interval in seconds (default: 300)')
    parser.add_argument('--export', type=str,
                       help='Export results to JSON file')
    parser.add_argument('--baseline-file', type=str, default='uba_baseline.json',
                       help='Baseline file path (default: uba_baseline.json)')
    
    args = parser.parse_args()
    
    if not any([args.baseline, args.scan, args.monitor]):
        parser.print_help()
        sys.exit(1)
    
    uba = UserBehaviorAnalytics(baseline_file=args.baseline_file)
    
    if args.baseline:
        uba.create_baseline()
    
    elif args.scan:
        uba.scan()
        uba.print_summary()
        
        if args.export:
            uba.export_results(args.export)
    
    elif args.monitor:
        print(f"\n{'='*70}")
        print("USER BEHAVIOR ANALYTICS - Continuous Monitoring")
        print(f"{'='*70}\n")
        print(f"Duration: {args.duration} seconds")
        print(f"Interval: {args.interval} seconds")
        print(f"Press Ctrl+C to stop\n")
        
        start_time = time.time()
        iteration = 0
        
        try:
            while time.time() - start_time < args.duration:
                iteration += 1
                print(f"\n[*] Scan iteration {iteration} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                
                uba.scan()
                uba.print_summary()
                
                if args.export:
                    export_file = args.export.replace('.json', f'_{iteration}.json')
                    uba.export_results(export_file)
                
                # Reset for next iteration
                uba.alerts = defaultdict(list)
                uba.severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                uba.user_activity = defaultdict(lambda: {
                    'logins': [],
                    'failed_logins': [],
                    'login_times': [],
                    'login_days': set(),
                    'sudo_commands': [],
                    'file_accesses': [],
                    'processes': [],
                    'network_connections': [],
                    'total_sessions': 0,
                    'avg_session_duration': 0
                })
                
                print(f"\n[*] Sleeping {args.interval} seconds...")
                time.sleep(args.interval)
        
        except KeyboardInterrupt:
            print("\n\n[!] Monitoring stopped by user")
            print(f"[*] Total iterations: {iteration}")

if __name__ == '__main__':
    main()
