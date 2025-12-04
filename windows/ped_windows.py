#!/usr/bin/env python3
"""
Windows Privilege Escalation Detector (PED)
Monitors Windows systems for privilege escalation attempts and security misconfigurations
Windows equivalent of PED for Linux
"""

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime
from collections import defaultdict
from pathlib import Path

class WindowsPrivilegeEscalationDetector:
    def __init__(self, baseline_file='ped_baseline_windows.json'):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.findings = defaultdict(list)
        
    def check_admin_privileges(self):
        """Check if running with administrator privileges"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def get_user_accounts(self):
        """Get list of user accounts and their properties"""
        users = []
        try:
            # Use net user command
            result = subprocess.run(['net', 'user'], capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                # Parse user list (skips header and footer)
                user_section = False
                for line in lines:
                    if '---' in line:
                        user_section = True
                        continue
                    if user_section and line.strip():
                        # Extract usernames from the formatted output
                        names = line.split()
                        users.extend(names)
            
            # Get detailed info for each user
            user_details = []
            for username in users:
                if username and username != 'The':  # Filter out partial matches
                    details = self.get_user_details(username)
                    if details:
                        user_details.append(details)
            
            return user_details
            
        except Exception as e:
            print(f"Error getting user accounts: {e}")
            return []
    
    def get_user_details(self, username):
        """Get detailed information about a user"""
        try:
            result = subprocess.run(['net', 'user', username], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                return None
            
            details = {'username': username}
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'Account active' in line:
                    details['active'] = 'Yes' in line
                elif 'Account expires' in line:
                    details['expires'] = line.split('Account expires')[-1].strip()
                elif 'Password last set' in line:
                    details['password_last_set'] = line.split('Password last set')[-1].strip()
                elif 'Password expires' in line:
                    details['password_expires'] = line.split('Password expires')[-1].strip()
                elif 'Local Group Memberships' in line:
                    # Next line contains groups
                    groups = []
                    idx = lines.index(line) + 1
                    while idx < len(lines) and lines[idx].strip() and 'Global Group' not in lines[idx]:
                        groups.extend([g.strip('*').strip() for g in lines[idx].split() if g.strip()])
                        idx += 1
                    details['local_groups'] = groups
            
            return details
            
        except Exception as e:
            return None
    
    def get_local_groups(self):
        """Get local security groups and their members"""
        groups = {}
        critical_groups = [
            'Administrators',
            'Power Users', 
            'Remote Desktop Users',
            'Backup Operators',
            'Network Configuration Operators',
            'Remote Management Users'
        ]
        
        for group in critical_groups:
            try:
                result = subprocess.run(['net', 'localgroup', group],
                                      capture_output=True, text=True)
                
                if result.returncode == 0:
                    members = []
                    lines = result.stdout.split('\n')
                    member_section = False
                    
                    for line in lines:
                        if '---' in line:
                            member_section = True
                            continue
                        if member_section and line.strip() and 'completed successfully' not in line:
                            members.append(line.strip())
                    
                    groups[group] = members
                    
            except Exception as e:
                continue
        
        return groups
    
    def check_scheduled_tasks(self):
        """Check for suspicious scheduled tasks"""
        tasks = []
        try:
            result = subprocess.run(['schtasks', '/query', '/fo', 'LIST', '/v'],
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_task = {}
                
                for line in lines:
                    if ': ' in line:
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        if key == 'TaskName':
                            if current_task:
                                tasks.append(current_task)
                            current_task = {'name': value}
                        elif key == 'Run As User':
                            current_task['run_as'] = value
                        elif key == 'Task To Run':
                            current_task['command'] = value
                        elif key == 'Status':
                            current_task['status'] = value
                
                if current_task:
                    tasks.append(current_task)
                    
        except Exception as e:
            print(f"Error checking scheduled tasks: {e}")
        
        return tasks
    
    def check_startup_programs(self):
        """Check startup programs"""
        startup_items = []
        
        # Check registry startup locations
        reg_paths = [
            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        ]
        
        for reg_path in reg_paths:
            try:
                result = subprocess.run(['reg', 'query', reg_path],
                                      capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'REG_' in line:
                            parts = line.strip().split(None, 2)
                            if len(parts) >= 3:
                                startup_items.append({
                                    'location': reg_path,
                                    'name': parts[0],
                                    'type': parts[1],
                                    'value': parts[2] if len(parts) > 2 else ''
                                })
            except Exception:
                continue
        
        return startup_items
    
    def check_services(self):
        """Check Windows services"""
        services = []
        try:
            result = subprocess.run(['sc', 'query', 'state=', 'all'],
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_service = {}
                
                for line in lines:
                    if ': ' in line:
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        if key == 'SERVICE_NAME':
                            if current_service:
                                services.append(current_service)
                            current_service = {'name': value}
                        elif key == 'DISPLAY_NAME':
                            current_service['display_name'] = value
                        elif key == 'STATE':
                            current_service['state'] = value.split()[0]
                        elif key == 'TYPE':
                            current_service['type'] = value
                
                if current_service:
                    services.append(current_service)
                    
        except Exception as e:
            print(f"Error checking services: {e}")
        
        return services
    
    def check_shared_folders(self):
        """Check network shares"""
        shares = []
        try:
            result = subprocess.run(['net', 'share'], capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip() and not line.startswith('Share') and not line.startswith('-'):
                        parts = line.split()
                        if len(parts) >= 2:
                            shares.append({
                                'name': parts[0],
                                'path': parts[1] if len(parts) > 1 else ''
                            })
        except Exception as e:
            print(f"Error checking shares: {e}")
        
        return shares
    
    def check_firewall_status(self):
        """Check Windows Firewall status"""
        try:
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'],
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                profiles = {}
                current_profile = None
                
                for line in result.stdout.split('\n'):
                    if 'Profile Settings' in line:
                        current_profile = line.split()[0]
                        profiles[current_profile] = {}
                    elif current_profile and line.strip():
                        if 'State' in line and 'ON' in line:
                            profiles[current_profile]['enabled'] = True
                        elif 'State' in line and 'OFF' in line:
                            profiles[current_profile]['enabled'] = False
                
                return profiles
        except Exception as e:
            return {}
    
    def create_baseline(self):
        """Create security baseline"""
        print("Creating security baseline...")
        print("This may take a few minutes...\n")
        
        self.baseline = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'users': self.get_user_accounts(),
            'groups': self.get_local_groups(),
            'scheduled_tasks': self.check_scheduled_tasks(),
            'startup_programs': self.check_startup_programs(),
            'services': self.check_services(),
            'shares': self.check_shared_folders(),
            'firewall': self.check_firewall_status()
        }
        
        # Save baseline
        with open(self.baseline_file, 'w') as f:
            json.dump(self.baseline, f, indent=2)
        
        print(f"Baseline created and saved to {self.baseline_file}")
        print(f"  Users: {len(self.baseline['users'])}")
        print(f"  Groups: {len(self.baseline['groups'])}")
        print(f"  Scheduled Tasks: {len(self.baseline['scheduled_tasks'])}")
        print(f"  Startup Programs: {len(self.baseline['startup_programs'])}")
        print(f"  Services: {len(self.baseline['services'])}")
        print(f"  Network Shares: {len(self.baseline['shares'])}")
    
    def load_baseline(self):
        """Load baseline from file"""
        try:
            with open(self.baseline_file, 'r') as f:
                self.baseline = json.load(f)
            print(f"Loaded baseline from {self.baseline_file}")
            print(f"Created: {self.baseline.get('timestamp', 'Unknown')}")
            return True
        except FileNotFoundError:
            print(f"Error: Baseline file {self.baseline_file} not found")
            print("Run with --create-baseline first")
            return False
    
    def check_privilege_escalation(self):
        """Check for privilege escalation indicators"""
        if not self.baseline:
            if not self.load_baseline():
                return
        
        print("\nChecking for privilege escalation indicators...\n")
        
        # Get current state
        current_state = {
            'users': self.get_user_accounts(),
            'groups': self.get_local_groups(),
            'scheduled_tasks': self.check_scheduled_tasks(),
            'startup_programs': self.check_startup_programs(),
            'services': self.check_services(),
            'shares': self.check_shared_folders(),
            'firewall': self.check_firewall_status()
        }
        
        # Compare users
        baseline_users = {u['username']: u for u in self.baseline['users']}
        current_users = {u['username']: u for u in current_state['users']}
        
        # New users
        new_users = set(current_users.keys()) - set(baseline_users.keys())
        if new_users:
            for user in new_users:
                self.findings['new_users'].append({
                    'username': user,
                    'details': current_users[user]
                })
        
        # Deleted users
        deleted_users = set(baseline_users.keys()) - set(current_users.keys())
        if deleted_users:
            for user in deleted_users:
                self.findings['deleted_users'].append({'username': user})
        
        # Check group memberships
        for group, members in current_state['groups'].items():
            baseline_members = set(self.baseline['groups'].get(group, []))
            current_members = set(members)
            
            new_members = current_members - baseline_members
            if new_members:
                for member in new_members:
                    self.findings['new_group_members'].append({
                        'group': group,
                        'member': member
                    })
        
        # Check scheduled tasks
        baseline_tasks = {t['name']: t for t in self.baseline['scheduled_tasks']}
        current_tasks = {t['name']: t for t in current_state['scheduled_tasks']}
        
        new_tasks = set(current_tasks.keys()) - set(baseline_tasks.keys())
        if new_tasks:
            for task in new_tasks:
                self.findings['new_scheduled_tasks'].append(current_tasks[task])
        
        # Check startup programs
        baseline_startup = {f"{s['location']}\\{s['name']}" for s in self.baseline['startup_programs']}
        current_startup = {f"{s['location']}\\{s['name']}" for s in current_state['startup_programs']}
        
        new_startup = current_startup - baseline_startup
        if new_startup:
            for item in current_state['startup_programs']:
                key = f"{item['location']}\\{item['name']}"
                if key in new_startup:
                    self.findings['new_startup_programs'].append(item)
        
        # Check services
        baseline_services = {s['name']: s for s in self.baseline['services']}
        current_services = {s['name']: s for s in current_state['services']}
        
        new_services = set(current_services.keys()) - set(baseline_services.keys())
        if new_services:
            for service in new_services:
                self.findings['new_services'].append(current_services[service])
        
        # Check shares
        baseline_shares = {s['name'] for s in self.baseline['shares']}
        current_shares = {s['name'] for s in current_state['shares']}
        
        new_shares = current_shares - baseline_shares
        if new_shares:
            for share in current_state['shares']:
                if share['name'] in new_shares:
                    self.findings['new_shares'].append(share)
        
        # Print report
        self.print_report()
        
        return len(self.findings) > 0
    
    def print_report(self):
        """Print privilege escalation report"""
        print("="*70)
        print(" PRIVILEGE ESCALATION DETECTION REPORT")
        print("="*70)
        
        if not any(self.findings.values()):
            print("\n✓ No privilege escalation indicators detected")
            print("\n" + "="*70)
            return
        
        if self.findings['new_users']:
            print(f"\n[NEW USER ACCOUNTS: {len(self.findings['new_users'])}]")
            print("-" * 70)
            for user in self.findings['new_users']:
                print(f"  ⚠ New user: {user['username']}")
                if 'local_groups' in user['details']:
                    print(f"     Groups: {', '.join(user['details']['local_groups'])}")
        
        if self.findings['new_group_members']:
            print(f"\n[NEW GROUP MEMBERSHIPS: {len(self.findings['new_group_members'])}]")
            print("-" * 70)
            for item in self.findings['new_group_members']:
                print(f"  ⚠ {item['member']} added to {item['group']}")
        
        if self.findings['new_scheduled_tasks']:
            print(f"\n[NEW SCHEDULED TASKS: {len(self.findings['new_scheduled_tasks'])}]")
            print("-" * 70)
            for task in self.findings['new_scheduled_tasks'][:10]:
                print(f"  ⚠ Task: {task['name']}")
                print(f"     Run As: {task.get('run_as', 'N/A')}")
                print(f"     Command: {task.get('command', 'N/A')[:80]}")
        
        if self.findings['new_startup_programs']:
            print(f"\n[NEW STARTUP PROGRAMS: {len(self.findings['new_startup_programs'])}]")
            print("-" * 70)
            for item in self.findings['new_startup_programs']:
                print(f"  ⚠ {item['name']}")
                print(f"     Location: {item['location']}")
                print(f"     Value: {item['value'][:80]}")
        
        if self.findings['new_services']:
            print(f"\n[NEW SERVICES: {len(self.findings['new_services'])}]")
            print("-" * 70)
            for service in self.findings['new_services'][:10]:
                print(f"  ⚠ {service['name']}")
                print(f"     Display Name: {service.get('display_name', 'N/A')}")
                print(f"     State: {service.get('state', 'N/A')}")
        
        if self.findings['new_shares']:
            print(f"\n[NEW NETWORK SHARES: {len(self.findings['new_shares'])}]")
            print("-" * 70)
            for share in self.findings['new_shares']:
                print(f"  ⚠ Share: {share['name']}")
                print(f"     Path: {share['path']}")
        
        print("\n" + "="*70)
        print("⚠ WARNING: Privilege escalation indicators detected!")
        print("="*70)
    
    def export_findings(self, filename='ped_findings_windows.json'):
        """Export findings to JSON"""
        output = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'findings': dict(self.findings)
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\nFindings exported to {filename}")
    
    def monitor_continuous(self, interval=300):
        """Continuously monitor for privilege escalation"""
        import time
        
        print(f"Starting continuous monitoring (checking every {interval} seconds)")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Checking for privilege escalation...")
                
                findings = self.check_privilege_escalation()
                
                if findings:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    self.export_findings(f'ped_findings_{timestamp}.json')
                
                print(f"\nNext check in {interval} seconds...")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user")

def main():
    parser = argparse.ArgumentParser(
        description='Windows Privilege Escalation Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create baseline
  python ped_windows.py --create-baseline
  
  # Check for privilege escalation
  python ped_windows.py --check
  
  # Continuous monitoring
  python ped_windows.py --monitor --interval 300
  
  # Export findings
  python ped_windows.py --check --export findings.json

Note: Run as Administrator for full system access.
        """
    )
    
    parser.add_argument('--create-baseline', action='store_true',
                       help='Create security baseline')
    parser.add_argument('--check', action='store_true',
                       help='Check for privilege escalation')
    parser.add_argument('--monitor', action='store_true',
                       help='Continuous monitoring mode')
    parser.add_argument('--baseline-file', type=str, default='ped_baseline_windows.json',
                       help='Baseline file path')
    parser.add_argument('--export', type=str, metavar='FILE',
                       help='Export findings to JSON file')
    parser.add_argument('--interval', type=int, default=300,
                       help='Check interval in seconds for monitoring mode')
    
    args = parser.parse_args()
    
    # Check if running on Windows
    if sys.platform != 'win32':
        print("Error: This script is designed for Windows systems only.")
        print("For Linux systems, use ped.py instead.")
        sys.exit(1)
    
    ped = WindowsPrivilegeEscalationDetector(baseline_file=args.baseline_file)
    
    # Check admin privileges
    if not ped.check_admin_privileges():
        print("⚠ WARNING: Not running as Administrator")
        print("Some checks may fail without elevated privileges\n")
    
    if args.create_baseline:
        ped.create_baseline()
    elif args.check:
        findings = ped.check_privilege_escalation()
        if args.export:
            ped.export_findings(args.export)
        sys.exit(0 if not findings else 1)
    elif args.monitor:
        if not ped.load_baseline():
            print("\nCreating initial baseline for monitoring...")
            ped.create_baseline()
        ped.monitor_continuous(interval=args.interval)
    else:
        parser.print_help()
        print("\nPlease specify --create-baseline, --check, or --monitor")
        sys.exit(1)

if __name__ == '__main__':
    main()
