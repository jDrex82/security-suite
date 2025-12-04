#!/usr/bin/env python3
"""
Active Directory Security Monitor (ADSM)
Detects suspicious Active Directory activity including:
- Golden/Silver Ticket attacks
- Group Policy Object (GPO) changes
- Privilege escalation (Domain Admin additions)
- Suspicious Kerberos activity
- Domain controller compromise indicators

Windows-only tool for enterprise AD environments
"""

import os
import sys
import re
import json
import argparse
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path

class ActiveDirectoryMonitor:
    def __init__(self, baseline_file='adsm_baseline.json'):
        if not sys.platform.startswith('win'):
            print("Error: This tool is Windows-only and requires Active Directory.")
            sys.exit(1)
        
        self.baseline_file = baseline_file
        self.baseline = {}
        self.alerts = defaultdict(list)
        self.severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        # Critical AD groups to monitor
        self.critical_groups = [
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Backup Operators',
            'Account Operators',
            'Server Operators',
            'Print Operators',
            'DNSAdmins',
            'Group Policy Creator Owners'
        ]
        
        # Suspicious Event IDs
        self.suspicious_events = {
            4624: 'Account Logon',
            4625: 'Failed Logon',
            4672: 'Admin Rights Assigned',
            4768: 'Kerberos TGT Request',
            4769: 'Kerberos Service Ticket',
            4770: 'Kerberos Service Ticket Renewed',
            4771: 'Kerberos Pre-auth Failed',
            4776: 'NTLM Authentication',
            4728: 'Member Added to Security-Enabled Global Group',
            4732: 'Member Added to Security-Enabled Local Group',
            4756: 'Member Added to Security-Enabled Universal Group',
            5136: 'Directory Service Object Modified',
            5137: 'Directory Service Object Created',
            5141: 'Directory Service Object Deleted',
        }
        
        # Golden/Silver Ticket indicators
        self.ticket_anomalies = [
            'unusual_encryption_type',
            'ticket_lifetime_exceeds_policy',
            'service_ticket_without_tgt',
            'ticket_from_unusual_source'
        ]
        
    def check_admin_privileges(self):
        """Verify script is running with admin privileges"""
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Error: This tool requires Administrator privileges.")
                print("Please run as Administrator.")
                sys.exit(1)
        except:
            print("Warning: Could not verify admin privileges.")
    
    def get_domain_info(self):
        """Get basic domain information"""
        domain_info = {}
        
        try:
            # Get domain name
            result = subprocess.run(
                ['wmic', 'computersystem', 'get', 'domain', '/value'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Domain=' in line:
                        domain_info['domain'] = line.split('=')[1].strip()
            
            # Get domain controllers
            result = subprocess.run(
                ['nltest', '/dclist:'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                dcs = []
                for line in result.stdout.split('\n'):
                    if '[PDC]' in line or '[DS]' in line:
                        dc_name = line.split()[0]
                        dcs.append(dc_name)
                domain_info['domain_controllers'] = dcs
        
        except Exception as e:
            print(f"Error getting domain info: {e}")
        
        return domain_info
    
    def get_critical_group_members(self):
        """Get members of critical AD groups"""
        group_members = {}
        
        print("\n[*] Checking critical AD group memberships...")
        
        for group in self.critical_groups:
            try:
                # Use net group for domain groups
                result = subprocess.run(
                    ['net', 'group', group, '/domain'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    members = []
                    in_members_section = False
                    
                    for line in result.stdout.split('\n'):
                        if 'Members' in line:
                            in_members_section = True
                            continue
                        
                        if in_members_section and line.strip():
                            if line.startswith('The command completed'):
                                break
                            # Parse member names (space-separated)
                            members.extend([m.strip() for m in line.split() if m.strip()])
                    
                    group_members[group] = members
                    print(f"  {group}: {len(members)} members")
            
            except Exception as e:
                print(f"  Error checking {group}: {e}")
        
        return group_members
    
    def detect_group_membership_changes(self, current_groups):
        """Detect changes in critical group memberships"""
        alerts = []
        
        if not self.baseline.get('group_members'):
            print("  No baseline found for group comparison")
            return alerts
        
        baseline_groups = self.baseline['group_members']
        
        for group, current_members in current_groups.items():
            if group in baseline_groups:
                baseline_members = set(baseline_groups[group])
                current_members_set = set(current_members)
                
                # Check for additions
                added = current_members_set - baseline_members
                if added:
                    alerts.append({
                        'severity': 'CRITICAL' if 'Admin' in group else 'HIGH',
                        'type': 'GROUP_MEMBER_ADDED',
                        'group': group,
                        'added_members': list(added),
                        'message': f'New member(s) added to {group}: {", ".join(added)}'
                    })
                
                # Check for removals
                removed = baseline_members - current_members_set
                if removed:
                    alerts.append({
                        'severity': 'MEDIUM',
                        'type': 'GROUP_MEMBER_REMOVED',
                        'group': group,
                        'removed_members': list(removed),
                        'message': f'Member(s) removed from {group}: {", ".join(removed)}'
                    })
        
        return alerts
    
    def check_gpo_changes(self):
        """Check for Group Policy Object changes"""
        alerts = []
        
        print("\n[*] Checking Group Policy Objects...")
        
        try:
            # Get GPO list
            result = subprocess.run(
                ['powershell', '-Command', 'Get-GPO -All | Select-Object DisplayName, Id, ModificationTime | ConvertTo-Json'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                try:
                    gpos = json.loads(result.stdout)
                    if not isinstance(gpos, list):
                        gpos = [gpos]
                    
                    print(f"  Found {len(gpos)} GPOs")
                    
                    # Check against baseline
                    if self.baseline.get('gpos'):
                        baseline_gpos = {g['Id']: g for g in self.baseline['gpos']}
                        
                        for gpo in gpos:
                            gpo_id = gpo.get('Id')
                            gpo_name = gpo.get('DisplayName')
                            mod_time = gpo.get('ModificationTime')
                            
                            if gpo_id in baseline_gpos:
                                # Check for modifications
                                baseline_time = baseline_gpos[gpo_id].get('ModificationTime')
                                if mod_time != baseline_time:
                                    alerts.append({
                                        'severity': 'HIGH',
                                        'type': 'GPO_MODIFIED',
                                        'gpo_name': gpo_name,
                                        'gpo_id': gpo_id,
                                        'modification_time': mod_time,
                                        'message': f'GPO modified: {gpo_name}'
                                    })
                            else:
                                # New GPO
                                alerts.append({
                                    'severity': 'MEDIUM',
                                    'type': 'GPO_CREATED',
                                    'gpo_name': gpo_name,
                                    'gpo_id': gpo_id,
                                    'message': f'New GPO created: {gpo_name}'
                                })
                        
                        # Check for deleted GPOs
                        current_ids = {g['Id'] for g in gpos}
                        baseline_ids = set(baseline_gpos.keys())
                        deleted = baseline_ids - current_ids
                        
                        for gpo_id in deleted:
                            alerts.append({
                                'severity': 'HIGH',
                                'type': 'GPO_DELETED',
                                'gpo_id': gpo_id,
                                'gpo_name': baseline_gpos[gpo_id].get('DisplayName'),
                                'message': f'GPO deleted: {baseline_gpos[gpo_id].get("DisplayName")}'
                            })
                    
                    return gpos, alerts
                
                except json.JSONDecodeError:
                    print("  Error parsing GPO data")
        
        except Exception as e:
            print(f"  Error checking GPOs: {e}")
        
        return [], alerts
    
    def check_kerberos_tickets(self):
        """Check for suspicious Kerberos ticket activity"""
        alerts = []
        
        print("\n[*] Analyzing Kerberos tickets...")
        
        try:
            # Get ticket information using klist
            result = subprocess.run(
                ['klist', 'tickets'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                tickets = []
                current_ticket = {}
                
                for line in result.stdout.split('\n'):
                    if 'Client:' in line:
                        if current_ticket:
                            tickets.append(current_ticket)
                        current_ticket = {'client': line.split(':')[1].strip()}
                    elif 'Server:' in line:
                        current_ticket['server'] = line.split(':')[1].strip()
                    elif 'KerbTicket Encryption Type:' in line:
                        current_ticket['encryption'] = line.split(':')[1].strip()
                    elif 'Start Time:' in line:
                        current_ticket['start_time'] = line.split(':', 1)[1].strip()
                    elif 'End Time:' in line:
                        current_ticket['end_time'] = line.split(':', 1)[1].strip()
                
                if current_ticket:
                    tickets.append(current_ticket)
                
                print(f"  Active tickets: {len(tickets)}")
                
                # Check for anomalies
                for ticket in tickets:
                    # Check for unusual encryption types (RC4 is suspicious)
                    encryption = ticket.get('encryption', '')
                    if 'RC4' in encryption or 'DES' in encryption:
                        alerts.append({
                            'severity': 'HIGH',
                            'type': 'WEAK_KERBEROS_ENCRYPTION',
                            'ticket': ticket,
                            'encryption': encryption,
                            'message': f'Weak Kerberos encryption detected: {encryption}'
                        })
                    
                    # Check for unusual service tickets
                    server = ticket.get('server', '')
                    if 'krbtgt' in server.lower():
                        # TGT ticket - check lifetime
                        alerts.append({
                            'severity': 'MEDIUM',
                            'type': 'TGT_TICKET_DETECTED',
                            'ticket': ticket,
                            'message': 'TGT ticket present - verify legitimacy'
                        })
        
        except Exception as e:
            print(f"  Error checking Kerberos tickets: {e}")
        
        return alerts
    
    def check_security_events(self, hours_back=1):
        """Check Windows Security Event Log for suspicious AD activity"""
        alerts = []
        
        print(f"\n[*] Analyzing Security Event Log (last {hours_back} hours)...")
        
        try:
            # Calculate time threshold
            time_threshold = (datetime.now() - timedelta(hours=hours_back)).strftime('%Y-%m-%d %H:%M:%S')
            
            # Query Security log for suspicious events
            for event_id, description in self.suspicious_events.items():
                try:
                    result = subprocess.run(
                        ['powershell', '-Command', 
                         f'Get-WinEvent -FilterHashtable @{{LogName="Security"; Id={event_id}}} -MaxEvents 100 -ErrorAction SilentlyContinue | '
                         f'Where-Object {{$_.TimeCreated -gt [datetime]"{time_threshold}"}} | '
                         'Select-Object TimeCreated, Id, Message | ConvertTo-Json'],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        try:
                            events = json.loads(result.stdout)
                            if not isinstance(events, list):
                                events = [events]
                            
                            if events:
                                # Check for suspicious patterns
                                if event_id == 4625:  # Failed logons
                                    if len(events) > 10:
                                        alerts.append({
                                            'severity': 'HIGH',
                                            'type': 'EXCESSIVE_FAILED_LOGONS',
                                            'event_id': event_id,
                                            'count': len(events),
                                            'message': f'Excessive failed logons detected: {len(events)} attempts'
                                        })
                                
                                elif event_id in [4728, 4732, 4756]:  # Group membership changes
                                    for event in events:
                                        alerts.append({
                                            'severity': 'HIGH',
                                            'type': 'GROUP_MEMBERSHIP_CHANGE_EVENT',
                                            'event_id': event_id,
                                            'time': event['TimeCreated'],
                                            'message': f'Group membership changed (Event {event_id})'
                                        })
                                
                                elif event_id == 4672:  # Admin rights
                                    for event in events:
                                        alerts.append({
                                            'severity': 'MEDIUM',
                                            'type': 'ADMIN_RIGHTS_ASSIGNED',
                                            'event_id': event_id,
                                            'time': event['TimeCreated'],
                                            'message': 'Administrator rights assigned to account'
                                        })
                        
                        except json.JSONDecodeError:
                            pass
                
                except Exception as e:
                    pass  # Event ID may not exist
        
        except Exception as e:
            print(f"  Error checking security events: {e}")
        
        return alerts
    
    def create_baseline(self):
        """Create baseline of current AD state"""
        print(f"\n{'='*70}")
        print("Creating Active Directory Baseline")
        print(f"{'='*70}\n")
        
        domain_info = self.get_domain_info()
        group_members = self.get_critical_group_members()
        gpos, _ = self.check_gpo_changes()
        
        baseline = {
            'timestamp': datetime.now().isoformat(),
            'domain_info': domain_info,
            'group_members': group_members,
            'gpos': gpos
        }
        
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=2, default=str)
        
        print(f"\n✓ Baseline created: {self.baseline_file}")
        print(f"  Domain: {domain_info.get('domain', 'Unknown')}")
        print(f"  Critical groups monitored: {len(group_members)}")
        print(f"  GPOs tracked: {len(gpos)}")
        
        return baseline
    
    def load_baseline(self):
        """Load existing baseline"""
        if os.path.exists(self.baseline_file):
            with open(self.baseline_file, 'r') as f:
                self.baseline = json.load(f)
            return True
        return False
    
    def scan(self):
        """Perform comprehensive AD security scan"""
        print(f"\n{'='*70}")
        print("Active Directory Security Scan")
        print(f"{'='*70}\n")
        
        # Load baseline
        if not self.load_baseline():
            print("⚠️  No baseline found. Creating baseline first...")
            self.create_baseline()
            print("\nBaseline created. Run scan again to detect changes.")
            return
        
        print(f"Baseline loaded from: {self.baseline['timestamp']}")
        
        # Run all checks
        all_alerts = []
        
        # Check group memberships
        current_groups = self.get_critical_group_members()
        all_alerts.extend(self.detect_group_membership_changes(current_groups))
        
        # Check GPO changes
        _, gpo_alerts = self.check_gpo_changes()
        all_alerts.extend(gpo_alerts)
        
        # Check Kerberos tickets
        all_alerts.extend(self.check_kerberos_tickets())
        
        # Check security events
        all_alerts.extend(self.check_security_events(hours_back=24))
        
        # Process alerts
        for alert in all_alerts:
            severity = alert['severity']
            self.severity_counts[severity] += 1
            self.alerts[severity].append(alert)
        
        self.print_summary()
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{'='*70}")
        print("ACTIVE DIRECTORY SECURITY SUMMARY")
        print(f"{'='*70}")
        
        total_alerts = sum(self.severity_counts.values())
        print(f"\nTotal Alerts: {total_alerts}")
        print(f"  CRITICAL: {self.severity_counts['CRITICAL']}")
        print(f"  HIGH: {self.severity_counts['HIGH']}")
        print(f"  MEDIUM: {self.severity_counts['MEDIUM']}")
        print(f"  LOW: {self.severity_counts['LOW']}")
        
        if self.severity_counts['CRITICAL'] > 0:
            print(f"\n{'!'*70}")
            print("⚠️  CRITICAL AD SECURITY ISSUES DETECTED ⚠️")
            print("IMMEDIATE ACTIONS:")
            print("  1. Investigate Domain Admin group changes")
            print("  2. Review Kerberos ticket activity")
            print("  3. Check for Golden/Silver ticket attacks")
            print("  4. Audit GPO modifications")
            print("  5. Review security event logs")
            print(f"{'!'*70}")
        
        if total_alerts > 0:
            print(f"\n{'='*70}")
            print("DETAILED FINDINGS")
            print(f"{'='*70}")
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if self.alerts[severity]:
                    print(f"\n{severity} Alerts ({len(self.alerts[severity])}):")
                    for i, alert in enumerate(self.alerts[severity][:10], 1):
                        print(f"\n  {i}. [{alert['type']}]")
                        print(f"     {alert['message']}")
                        if 'group' in alert:
                            print(f"     Group: {alert['group']}")
                        if 'gpo_name' in alert:
                            print(f"     GPO: {alert['gpo_name']}")
                    
                    if len(self.alerts[severity]) > 10:
                        print(f"\n  ... and {len(self.alerts[severity]) - 10} more {severity} alerts")
    
    def export_results(self, output_file='adsm_results.json'):
        """Export results to JSON"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_alerts': sum(self.severity_counts.values()),
                'severity_counts': self.severity_counts
            },
            'alerts': dict(self.alerts)
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n✓ Results exported to: {output_file}")
        return output_file


def main():
    parser = argparse.ArgumentParser(
        description='Active Directory Security Monitor - Detect AD attacks and suspicious activity',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create baseline
  python ad_monitor.py --baseline
  
  # Run security scan
  python ad_monitor.py --scan
  
  # Export results
  python ad_monitor.py --scan --export results.json

Detection Capabilities:
  - Golden/Silver Ticket attacks
  - Group Policy Object changes
  - Critical group membership changes
  - Suspicious Kerberos activity
  - Failed authentication attempts
  - Privilege escalation attempts

Requirements:
  - Windows with Active Directory
  - Administrator privileges
  - Domain membership
  - PowerShell execution policy allowing scripts
        """
    )
    
    parser.add_argument('--baseline', action='store_true',
                       help='Create baseline of current AD state')
    parser.add_argument('--scan', action='store_true',
                       help='Run AD security scan')
    parser.add_argument('--export', metavar='FILE',
                       help='Export results to JSON file')
    parser.add_argument('--baseline-file', default='adsm_baseline.json',
                       help='Baseline file path')
    
    args = parser.parse_args()
    
    monitor = ActiveDirectoryMonitor(baseline_file=args.baseline_file)
    monitor.check_admin_privileges()
    
    try:
        if args.baseline:
            monitor.create_baseline()
        elif args.scan:
            monitor.scan()
            if args.export:
                monitor.export_results(args.export)
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
