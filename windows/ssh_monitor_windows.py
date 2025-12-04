#!/usr/bin/env python3
"""
Windows Event Log Monitor
Monitors Windows Security Event Logs for authentication attempts and security events
Windows equivalent of SSH Monitor for Linux
"""

import sys
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

# Try to import Windows-specific modules
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
    print("Warning: pywin32 not available. Some features will be limited.")
    print("Install with: pip install pywin32")

class WindowsEventLogMonitor:
    """Monitor Windows Event Logs for security events"""
    
    # Event IDs for security monitoring
    EVENT_IDS = {
        4624: 'Successful Login',
        4625: 'Failed Login',
        4634: 'Logoff',
        4648: 'Login with Explicit Credentials',
        4672: 'Special Privileges Assigned',
        4720: 'User Account Created',
        4722: 'User Account Enabled',
        4723: 'Password Change Attempt',
        4724: 'Password Reset Attempt',
        4725: 'User Account Disabled',
        4726: 'User Account Deleted',
        4732: 'Member Added to Security-Enabled Local Group',
        4733: 'Member Removed from Security-Enabled Local Group',
        4735: 'Security-Enabled Local Group Changed',
        4738: 'User Account Changed',
        4740: 'User Account Locked Out',
        4767: 'User Account Unlocked',
        4768: 'Kerberos TGT Requested',
        4769: 'Kerberos Service Ticket Requested',
        4771: 'Kerberos Pre-authentication Failed',
        4776: 'Domain Controller Attempted to Validate Credentials',
        4778: 'Session Reconnected',
        4779: 'Session Disconnected',
        4794: 'Directory Services Restore Mode Password Set',
        4798: 'Local Group Membership Enumerated',
        4799: 'Security-Enabled Local Group Membership Enumerated',
        5140: 'Network Share Accessed',
        5142: 'Network Share Added',
        5144: 'Network Share Deleted',
    }
    
    def __init__(self, server='localhost', log_type='Security'):
        self.server = server
        self.log_type = log_type
        self.events = []
        self.stats = defaultdict(int)
        
    def read_events_native(self, hours=24):
        """Read events using pywin32 (requires pywin32 package)"""
        if not WINDOWS_AVAILABLE:
            print("Error: pywin32 module not available")
            print("Please install: pip install pywin32")
            return []
        
        try:
            hand = win32evtlog.OpenEventLog(self.server, self.log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = 0
            events = []
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            while True:
                event_records = win32evtlog.ReadEventLog(hand, flags, 0)
                if not event_records:
                    break
                
                for event in event_records:
                    # Convert time to datetime
                    event_time = datetime.fromtimestamp(int(event.TimeGenerated))
                    
                    # Check if event is within time window
                    if event_time < cutoff_time:
                        win32evtlog.CloseEventLog(hand)
                        return events
                    
                    event_id = event.EventID & 0xFFFF  # Mask to get actual event ID
                    
                    # Only process security-relevant events
                    if event_id in self.EVENT_IDS:
                        event_data = {
                            'timestamp': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'event_id': event_id,
                            'event_type': self.EVENT_IDS.get(event_id, 'Unknown'),
                            'source': event.SourceName,
                            'computer': event.ComputerName,
                            'strings': event.StringInserts if event.StringInserts else []
                        }
                        events.append(event_data)
                        self.stats[event_id] += 1
                    
                    total += 1
                    if total % 1000 == 0:
                        print(f"Processed {total} events...", end='\r')
            
            win32evtlog.CloseEventLog(hand)
            return events
            
        except Exception as e:
            print(f"Error reading event log: {e}")
            return []
    
    def read_events_wmi(self, hours=24):
        """Alternative method using WMI (more compatible but slower)"""
        try:
            import wmi
            c = wmi.WMI()
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Query security log
            query = f"SELECT * FROM Win32_NTLogEvent WHERE Logfile = '{self.log_type}'"
            events = []
            
            for event in c.query(query):
                try:
                    # Parse time generated
                    time_str = event.TimeGenerated.split('.')[0]
                    event_time = datetime.strptime(time_str, '%Y%m%d%H%M%S')
                    
                    if event_time < cutoff_time:
                        continue
                    
                    event_id = event.EventCode
                    
                    if event_id in self.EVENT_IDS:
                        event_data = {
                            'timestamp': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'event_id': event_id,
                            'event_type': self.EVENT_IDS.get(event_id, 'Unknown'),
                            'source': event.SourceName,
                            'computer': event.ComputerName,
                            'message': event.Message
                        }
                        events.append(event_data)
                        self.stats[event_id] += 1
                
                except Exception as e:
                    continue
            
            return events
            
        except ImportError:
            print("Error: WMI module not available")
            print("Please install: pip install wmi")
            return []
        except Exception as e:
            print(f"Error reading event log via WMI: {e}")
            return []
    
    def analyze_events(self, events):
        """Analyze events for security concerns"""
        failed_logins = defaultdict(list)
        successful_logins = []
        privileged_operations = []
        account_changes = []
        
        for event in events:
            event_id = event['event_id']
            
            # Failed login attempts
            if event_id in [4625, 4771]:
                username = self._extract_username(event)
                ip = self._extract_ip(event)
                failed_logins[username].append({
                    'timestamp': event['timestamp'],
                    'ip': ip,
                    'event_type': event['event_type']
                })
            
            # Successful logins
            elif event_id == 4624:
                successful_logins.append({
                    'timestamp': event['timestamp'],
                    'username': self._extract_username(event),
                    'logon_type': self._extract_logon_type(event),
                    'ip': self._extract_ip(event)
                })
            
            # Privileged operations
            elif event_id in [4672, 4794]:
                privileged_operations.append({
                    'timestamp': event['timestamp'],
                    'username': self._extract_username(event),
                    'event_type': event['event_type']
                })
            
            # Account changes
            elif event_id in [4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767]:
                account_changes.append({
                    'timestamp': event['timestamp'],
                    'event_type': event['event_type'],
                    'target': self._extract_username(event),
                    'by': self._extract_actor(event)
                })
        
        return {
            'failed_logins': dict(failed_logins),
            'successful_logins': successful_logins,
            'privileged_operations': privileged_operations,
            'account_changes': account_changes
        }
    
    def _extract_username(self, event):
        """Extract username from event"""
        if 'strings' in event and len(event['strings']) > 5:
            return event['strings'][5]
        elif 'message' in event:
            # Try to extract from message
            import re
            match = re.search(r'Account Name:\s+(\S+)', event['message'])
            if match:
                return match.group(1)
        return 'Unknown'
    
    def _extract_ip(self, event):
        """Extract IP address from event"""
        if 'strings' in event and len(event['strings']) > 18:
            return event['strings'][18]
        elif 'message' in event:
            import re
            match = re.search(r'Source Network Address:\s+(\S+)', event['message'])
            if match:
                return match.group(1)
        return 'Unknown'
    
    def _extract_logon_type(self, event):
        """Extract logon type from event"""
        if 'strings' in event and len(event['strings']) > 8:
            logon_type = event['strings'][8]
            types = {
                '2': 'Interactive',
                '3': 'Network',
                '4': 'Batch',
                '5': 'Service',
                '7': 'Unlock',
                '8': 'NetworkCleartext',
                '9': 'NewCredentials',
                '10': 'RemoteInteractive',
                '11': 'CachedInteractive'
            }
            return types.get(logon_type, f'Type {logon_type}')
        return 'Unknown'
    
    def _extract_actor(self, event):
        """Extract the user who performed the action"""
        if 'strings' in event and len(event['strings']) > 1:
            return event['strings'][1]
        return 'System'
    
    def print_report(self, analysis):
        """Print formatted analysis report"""
        print("\n" + "="*70)
        print(" WINDOWS EVENT LOG SECURITY ANALYSIS")
        print("="*70)
        
        # Event statistics
        print("\nEvent Statistics:")
        print("-" * 70)
        for event_id in sorted(self.stats.keys()):
            print(f"  {self.EVENT_IDS.get(event_id, 'Unknown'):40} : {self.stats[event_id]:>5}")
        
        # Failed login attempts
        if analysis['failed_logins']:
            print("\n" + "="*70)
            print(" FAILED LOGIN ATTEMPTS")
            print("="*70)
            for username, attempts in sorted(analysis['failed_logins'].items(), 
                                            key=lambda x: len(x[1]), reverse=True)[:20]:
                print(f"\n{username}: {len(attempts)} failed attempts")
                for attempt in attempts[:5]:
                    print(f"  {attempt['timestamp']} from {attempt['ip']} - {attempt['event_type']}")
                if len(attempts) > 5:
                    print(f"  ... and {len(attempts) - 5} more")
        
        # Successful logins
        if analysis['successful_logins']:
            print("\n" + "="*70)
            print(" RECENT SUCCESSFUL LOGINS")
            print("="*70)
            for login in analysis['successful_logins'][:20]:
                print(f"  {login['timestamp']} - {login['username']:20} "
                      f"({login['logon_type']:15}) from {login['ip']}")
        
        # Privileged operations
        if analysis['privileged_operations']:
            print("\n" + "="*70)
            print(" PRIVILEGED OPERATIONS")
            print("="*70)
            for op in analysis['privileged_operations'][:20]:
                print(f"  {op['timestamp']} - {op['username']:20} - {op['event_type']}")
        
        # Account changes
        if analysis['account_changes']:
            print("\n" + "="*70)
            print(" ACCOUNT CHANGES")
            print("="*70)
            for change in analysis['account_changes'][:20]:
                print(f"  {change['timestamp']} - {change['event_type']}")
                print(f"    Target: {change['target']}, By: {change['by']}")
        
        print("\n" + "="*70)
    
    def export_json(self, analysis, filename='event_log_analysis.json'):
        """Export analysis to JSON file"""
        output = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'statistics': dict(self.stats),
            'analysis': analysis
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\nAnalysis exported to {filename}")

def main():
    parser = argparse.ArgumentParser(
        description='Windows Event Log Security Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssh_monitor_windows.py
  python ssh_monitor_windows.py --last-hours 48
  python ssh_monitor_windows.py --export results.json
  python ssh_monitor_windows.py --method wmi

Note: This script requires administrator privileges to read Security Event Logs.
      Run from an elevated command prompt or PowerShell.
        """
    )
    
    parser.add_argument('--last-hours', type=int, default=24,
                       help='Number of hours to analyze (default: 24)')
    parser.add_argument('--export', type=str, metavar='FILE',
                       help='Export results to JSON file')
    parser.add_argument('--method', choices=['native', 'wmi'], default='native',
                       help='Method to read events (native requires pywin32, wmi requires WMI)')
    parser.add_argument('--server', default='localhost',
                       help='Remote server name (default: localhost)')
    
    args = parser.parse_args()
    
    # Check if running on Windows
    if sys.platform != 'win32':
        print("Error: This script is designed for Windows systems only.")
        print("For Linux systems, use ssh_monitor.py instead.")
        sys.exit(1)
    
    print(f"Windows Event Log Security Monitor")
    print(f"Analyzing last {args.last_hours} hours of Security Event Log...")
    print(f"Server: {args.server}")
    print()
    
    monitor = WindowsEventLogMonitor(server=args.server)
    
    # Read events
    if args.method == 'native':
        events = monitor.read_events_native(hours=args.last_hours)
    else:
        events = monitor.read_events_wmi(hours=args.last_hours)
    
    if not events:
        print("\nNo relevant security events found in the specified time period.")
        print("\nTroubleshooting:")
        print("1. Make sure you're running as Administrator")
        print("2. Check if Security Event Log is enabled")
        print("3. Install required modules: pip install pywin32")
        sys.exit(1)
    
    print(f"\nFound {len(events)} security-relevant events")
    
    # Analyze events
    analysis = monitor.analyze_events(events)
    
    # Print report
    monitor.print_report(analysis)
    
    # Export if requested
    if args.export:
        monitor.export_json(analysis, args.export)
    
    # Summary statistics
    print("\nSummary:")
    print(f"  Failed Login Attempts: {sum(len(v) for v in analysis['failed_logins'].values())}")
    print(f"  Successful Logins: {len(analysis['successful_logins'])}")
    print(f"  Privileged Operations: {len(analysis['privileged_operations'])}")
    print(f"  Account Changes: {len(analysis['account_changes'])}")

if __name__ == '__main__':
    main()
