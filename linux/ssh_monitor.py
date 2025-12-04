#!/usr/bin/env python3
"""
SSH Login Attempt Monitor
Monitors and reports SSH login attempts from system authentication logs
"""

import re
import sys
from datetime import datetime
from pathlib import Path
import argparse
from collections import defaultdict

class SSHMonitor:
    def __init__(self, log_file='/var/log/auth.log'):
        self.log_file = log_file
        # Try alternative log locations if default doesn't exist
        if not Path(log_file).exists():
            alternatives = ['/var/log/secure', '/var/log/auth.log']
            for alt in alternatives:
                if Path(alt).exists():
                    self.log_file = alt
                    break
        
        # Regex patterns for different SSH events
        self.patterns = {
            'failed_password': re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)'),
            'accepted_password': re.compile(r'Accepted password for (\S+) from (\S+) port (\d+)'),
            'accepted_publickey': re.compile(r'Accepted publickey for (\S+) from (\S+) port (\d+)'),
            'invalid_user': re.compile(r'Invalid user (\S+) from (\S+) port (\d+)'),
            'disconnected': re.compile(r'Disconnected from (?:invalid user )?(\S+) (\S+) port (\d+)'),
            'connection_closed': re.compile(r'Connection closed by (?:invalid user )?(\S+) port (\d+)')
        }
    
    def parse_line(self, line):
        """Parse a log line and extract SSH-related information"""
        if 'sshd' not in line.lower():
            return None
        
        result = {'raw': line.strip(), 'type': 'unknown'}
        
        # Extract timestamp (common syslog format)
        timestamp_match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
        if timestamp_match:
            result['timestamp'] = timestamp_match.group(1)
        
        # Check each pattern
        for event_type, pattern in self.patterns.items():
            match = pattern.search(line)
            if match:
                result['type'] = event_type
                groups = match.groups()
                
                if event_type in ['failed_password', 'accepted_password', 'accepted_publickey', 'invalid_user']:
                    result['user'] = groups[0]
                    result['ip'] = groups[1]
                    result['port'] = groups[2]
                elif event_type == 'disconnected':
                    result['user'] = groups[0]
                    result['ip'] = groups[1]
                    result['port'] = groups[2]
                elif event_type == 'connection_closed':
                    result['ip'] = groups[0]
                    result['port'] = groups[1]
                
                return result
        
        # Return basic info if it's SSH-related but doesn't match specific patterns
        if 'ssh' in line.lower():
            return result
        
        return None
    
    def analyze_log(self, tail_lines=None, follow=False):
        """Analyze the SSH log file"""
        try:
            if not Path(self.log_file).exists():
                print(f"Error: Log file {self.log_file} not found")
                print("Note: You may need root privileges to access SSH logs")
                return
            
            if follow:
                self._follow_log()
            else:
                self._analyze_static(tail_lines)
                
        except PermissionError:
            print(f"Error: Permission denied accessing {self.log_file}")
            print("Try running with sudo: sudo python3 ssh_monitor.py")
        except Exception as e:
            print(f"Error: {e}")
    
    def _analyze_static(self, tail_lines=None):
        """Analyze existing log entries"""
        stats = defaultdict(int)
        failed_attempts = defaultdict(list)
        successful_logins = []
        
        with open(self.log_file, 'r') as f:
            lines = f.readlines()
            
            if tail_lines:
                lines = lines[-tail_lines:]
            
            print(f"\n{'='*70}")
            print(f"SSH Login Attempt Monitor - Analyzing {self.log_file}")
            print(f"{'='*70}\n")
            
            for line in lines:
                parsed = self.parse_line(line)
                if parsed:
                    event_type = parsed['type']
                    stats[event_type] += 1
                    
                    if event_type == 'failed_password':
                        ip = parsed.get('ip', 'unknown')
                        user = parsed.get('user', 'unknown')
                        failed_attempts[ip].append({
                            'user': user,
                            'timestamp': parsed.get('timestamp', 'unknown')
                        })
                        print(f"[FAILED] {parsed.get('timestamp', '')} - User: {user}, IP: {ip}")
                    
                    elif event_type == 'accepted_password':
                        user = parsed.get('user', 'unknown')
                        ip = parsed.get('ip', 'unknown')
                        successful_logins.append({
                            'user': user,
                            'ip': ip,
                            'timestamp': parsed.get('timestamp', 'unknown'),
                            'method': 'password'
                        })
                        print(f"[SUCCESS] {parsed.get('timestamp', '')} - User: {user}, IP: {ip} (password)")
                    
                    elif event_type == 'accepted_publickey':
                        user = parsed.get('user', 'unknown')
                        ip = parsed.get('ip', 'unknown')
                        successful_logins.append({
                            'user': user,
                            'ip': ip,
                            'timestamp': parsed.get('timestamp', 'unknown'),
                            'method': 'publickey'
                        })
                        print(f"[SUCCESS] {parsed.get('timestamp', '')} - User: {user}, IP: {ip} (publickey)")
                    
                    elif event_type == 'invalid_user':
                        user = parsed.get('user', 'unknown')
                        ip = parsed.get('ip', 'unknown')
                        print(f"[INVALID] {parsed.get('timestamp', '')} - Invalid user: {user}, IP: {ip}")
        
        # Print summary
        print(f"\n{'='*70}")
        print("SUMMARY")
        print(f"{'='*70}")
        print(f"\nTotal failed password attempts: {stats['failed_password']}")
        print(f"Total successful password logins: {stats['accepted_password']}")
        print(f"Total successful publickey logins: {stats['accepted_publickey']}")
        print(f"Total invalid user attempts: {stats['invalid_user']}")
        
        if failed_attempts:
            print(f"\n{'='*70}")
            print("TOP ATTACKING IPs")
            print(f"{'='*70}")
            sorted_attackers = sorted(failed_attempts.items(), 
                                     key=lambda x: len(x[1]), 
                                     reverse=True)
            for ip, attempts in sorted_attackers[:10]:
                print(f"{ip}: {len(attempts)} failed attempts")
                # Show unique usernames tried
                unique_users = set(a['user'] for a in attempts)
                print(f"  Usernames tried: {', '.join(list(unique_users)[:5])}")
    
    def _follow_log(self):
        """Follow the log file in real-time (like tail -f)"""
        print(f"Monitoring {self.log_file} in real-time (Ctrl+C to stop)...")
        print(f"{'='*70}\n")
        
        try:
            with open(self.log_file, 'r') as f:
                # Go to end of file
                f.seek(0, 2)
                
                while True:
                    line = f.readline()
                    if not line:
                        import time
                        time.sleep(0.1)
                        continue
                    
                    parsed = self.parse_line(line)
                    if parsed:
                        event_type = parsed['type']
                        timestamp = parsed.get('timestamp', '')
                        
                        if event_type == 'failed_password':
                            user = parsed.get('user', 'unknown')
                            ip = parsed.get('ip', 'unknown')
                            print(f"⚠️  [FAILED] {timestamp} - User: {user}, IP: {ip}")
                        
                        elif event_type in ['accepted_password', 'accepted_publickey']:
                            user = parsed.get('user', 'unknown')
                            ip = parsed.get('ip', 'unknown')
                            method = 'password' if event_type == 'accepted_password' else 'publickey'
                            print(f"✓ [SUCCESS] {timestamp} - User: {user}, IP: {ip} ({method})")
                        
                        elif event_type == 'invalid_user':
                            user = parsed.get('user', 'unknown')
                            ip = parsed.get('ip', 'unknown')
                            print(f"❌ [INVALID] {timestamp} - Invalid user: {user}, IP: {ip}")
        
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped.")

def main():
    parser = argparse.ArgumentParser(
        description='Monitor SSH login attempts from system logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Analyze entire auth.log
  %(prog)s -n 100                   # Analyze last 100 lines
  %(prog)s -f                       # Follow log in real-time
  %(prog)s -l /var/log/secure       # Use custom log file
  sudo %(prog)s -f                  # Monitor with root privileges
        """
    )
    
    parser.add_argument('-l', '--log-file',
                       default='/var/log/auth.log',
                       help='Path to auth log file (default: /var/log/auth.log)')
    
    parser.add_argument('-n', '--lines',
                       type=int,
                       help='Number of lines to analyze from end of file')
    
    parser.add_argument('-f', '--follow',
                       action='store_true',
                       help='Follow the log file in real-time (like tail -f)')
    
    args = parser.parse_args()
    
    monitor = SSHMonitor(args.log_file)
    monitor.analyze_log(tail_lines=args.lines, follow=args.follow)

if __name__ == '__main__':
    main()
