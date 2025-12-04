#!/usr/bin/env python3
"""
Windows Process and Network Connection Monitor (PNCM)
Monitors processes and network connections for anomalies
Windows equivalent of PNCM for Linux
"""

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime
from collections import defaultdict
from pathlib import Path

class WindowsProcessNetworkMonitor:
    def __init__(self, baseline_file='pncm_baseline_windows.json'):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.findings = defaultdict(list)
        
    def get_processes(self):
        """Get list of running processes"""
        processes = []
        try:
            # Use tasklist with verbose output
            result = subprocess.run(['tasklist', '/FO', 'CSV', '/V'],
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                # Parse CSV output (skip header)
                for line in lines[1:]:
                    if line.strip():
                        parts = [p.strip('"') for p in line.split('","')]
                        if len(parts) >= 8:
                            processes.append({
                                'name': parts[0],
                                'pid': parts[1],
                                'session_name': parts[2],
                                'session': parts[3],
                                'mem_usage': parts[4],
                                'status': parts[5],
                                'username': parts[6],
                                'cpu_time': parts[7] if len(parts) > 7 else 'N/A',
                                'window_title': parts[8] if len(parts) > 8 else 'N/A'
                            })
        except Exception as e:
            print(f"Error getting processes: {e}")
        
        return processes
    
    def get_network_connections(self):
        """Get active network connections"""
        connections = []
        try:
            # Use netstat to get connections
            result = subprocess.run(['netstat', '-ano'],
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if any(proto in line for proto in ['TCP', 'UDP']):
                        parts = line.split()
                        if len(parts) >= 4:
                            connection = {
                                'protocol': parts[0],
                                'local_address': parts[1],
                                'foreign_address': parts[2]
                            }
                            
                            if parts[0] == 'TCP':
                                connection['state'] = parts[3]
                                connection['pid'] = parts[4] if len(parts) > 4 else 'N/A'
                            else:  # UDP
                                connection['state'] = 'N/A'
                                connection['pid'] = parts[3] if len(parts) > 3 else 'N/A'
                            
                            connections.append(connection)
        except Exception as e:
            print(f"Error getting network connections: {e}")
        
        return connections
    
    def get_listening_ports(self):
        """Get listening ports"""
        listening = []
        try:
            result = subprocess.run(['netstat', '-an'],
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'LISTENING' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            listening.append({
                                'protocol': parts[0],
                                'local_address': parts[1],
                                'state': 'LISTENING'
                            })
        except Exception as e:
            print(f"Error getting listening ports: {e}")
        
        return listening
    
    def get_process_details(self, pid):
        """Get detailed information about a process"""
        try:
            # Get process info using wmic
            result = subprocess.run(['wmic', 'process', 'where', f'ProcessId={pid}',
                                   'get', 'ExecutablePath,CommandLine,ParentProcessId',
                                   '/format:list'],
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                details = {}
                for line in result.stdout.split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        details[key.strip()] = value.strip()
                return details
        except Exception:
            pass
        
        return {}
    
    def get_startup_processes(self):
        """Get processes that start automatically"""
        startup = []
        
        # Check Task Manager startup items using wmic
        try:
            result = subprocess.run(['wmic', 'startup', 'get', 
                                   'Caption,Command,Location,User', '/format:csv'],
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines[1:]:  # Skip header
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) >= 4:
                            startup.append({
                                'caption': parts[1] if len(parts) > 1 else 'N/A',
                                'command': parts[2] if len(parts) > 2 else 'N/A',
                                'location': parts[3] if len(parts) > 3 else 'N/A',
                                'user': parts[4] if len(parts) > 4 else 'N/A'
                            })
        except Exception as e:
            print(f"Error getting startup processes: {e}")
        
        return startup
    
    def analyze_suspicious_processes(self, processes):
        """Identify potentially suspicious processes"""
        suspicious = []
        
        # Known suspicious patterns
        suspicious_patterns = [
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'regsvr32.exe', 'rundll32.exe', 'mshta.exe'
        ]
        
        # Check for suspicious process names
        for process in processes:
            name = process['name'].lower()
            
            # Check patterns
            if any(pattern in name for pattern in suspicious_patterns):
                # Get more details
                if process['pid'].isdigit():
                    details = self.get_process_details(process['pid'])
                    if details:
                        process['details'] = details
                suspicious.append(process)
            
            # Check for processes running as SYSTEM with network activity
            if 'SYSTEM' in process.get('username', ''):
                suspicious.append(process)
        
        return suspicious
    
    def analyze_suspicious_connections(self, connections):
        """Identify potentially suspicious network connections"""
        suspicious = []
        
        # Check for unusual ports
        suspicious_ports = [
            4444, 5555, 6666, 7777, 8888, 9999,  # Common backdoor ports
            31337, 12345, 54321,  # Known malware ports
        ]
        
        for conn in connections:
            # Extract port from address
            try:
                if ':' in conn['foreign_address']:
                    port = int(conn['foreign_address'].split(':')[-1])
                    if port in suspicious_ports:
                        suspicious.append({
                            **conn,
                            'reason': f'Suspicious port: {port}'
                        })
                
                # Check for connections to unexpected addresses
                foreign = conn['foreign_address']
                if not any(x in foreign for x in ['0.0.0.0', '127.0.0.1', '::1', '*:*']):
                    if conn['state'] not in ['TIME_WAIT', 'CLOSE_WAIT', 'N/A']:
                        # This is an active external connection
                        pass  # Could add more logic here
                        
            except (ValueError, IndexError):
                continue
        
        return suspicious
    
    def create_baseline(self):
        """Create baseline of normal system state"""
        print("Creating baseline...")
        print("This may take a few minutes...\n")
        
        print("Gathering process information...")
        processes = self.get_processes()
        print(f"  Found {len(processes)} processes")
        
        print("Gathering network connections...")
        connections = self.get_network_connections()
        print(f"  Found {len(connections)} connections")
        
        print("Gathering listening ports...")
        listening = self.get_listening_ports()
        print(f"  Found {len(listening)} listening ports")
        
        print("Gathering startup processes...")
        startup = self.get_startup_processes()
        print(f"  Found {len(startup)} startup items")
        
        self.baseline = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'processes': processes,
            'connections': connections,
            'listening_ports': listening,
            'startup_processes': startup,
            'process_names': sorted(list(set(p['name'] for p in processes))),
            'listening_port_list': sorted(list(set(
                p['local_address'] for p in listening
            )))
        }
        
        # Save baseline
        with open(self.baseline_file, 'w') as f:
            json.dump(self.baseline, f, indent=2)
        
        print(f"\nBaseline created and saved to {self.baseline_file}")
    
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
    
    def check_anomalies(self):
        """Check for anomalies compared to baseline"""
        if not self.baseline:
            if not self.load_baseline():
                return
        
        print("\nChecking for anomalies...\n")
        
        # Get current state
        print("Gathering current state...")
        current_processes = self.get_processes()
        current_connections = self.get_network_connections()
        current_listening = self.get_listening_ports()
        current_startup = self.get_startup_processes()
        
        # Compare processes
        baseline_process_names = set(self.baseline['process_names'])
        current_process_names = set(p['name'] for p in current_processes)
        
        new_processes = current_process_names - baseline_process_names
        if new_processes:
            for name in new_processes:
                matching = [p for p in current_processes if p['name'] == name]
                for process in matching:
                    self.findings['new_processes'].append(process)
        
        # Check for suspicious processes
        suspicious_procs = self.analyze_suspicious_processes(current_processes)
        if suspicious_procs:
            self.findings['suspicious_processes'].extend(suspicious_procs)
        
        # Compare listening ports
        baseline_listening = set(self.baseline['listening_port_list'])
        current_listening = set(p['local_address'] for p in current_listening)
        
        new_listening = current_listening - baseline_listening
        if new_listening:
            for port in current_listening:
                if port in new_listening:
                    matching = [p for p in current_listening if p['local_address'] == port]
                    if matching:
                        self.findings['new_listening_ports'].append(
                            next(p for p in current_listening if p['local_address'] == port)
                        )
        
        # Check for suspicious connections
        suspicious_conns = self.analyze_suspicious_connections(current_connections)
        if suspicious_conns:
            self.findings['suspicious_connections'].extend(suspicious_conns)
        
        # Compare startup processes
        baseline_startup = set(s['command'] for s in self.baseline.get('startup_processes', []))
        current_startup_cmds = set(s['command'] for s in current_startup)
        
        new_startup = current_startup_cmds - baseline_startup
        if new_startup:
            for cmd in new_startup:
                matching = [s for s in current_startup if s['command'] == cmd]
                if matching:
                    self.findings['new_startup_items'].extend(matching)
        
        # Print report
        self.print_report()
        
        return len(self.findings) > 0
    
    def print_report(self):
        """Print anomaly detection report"""
        print("="*70)
        print(" PROCESS AND NETWORK ANOMALY DETECTION REPORT")
        print("="*70)
        
        if not any(self.findings.values()):
            print("\n✓ No anomalies detected")
            print("\n" + "="*70)
            return
        
        if self.findings['new_processes']:
            print(f"\n[NEW PROCESSES: {len(self.findings['new_processes'])}]")
            print("-" * 70)
            for proc in self.findings['new_processes'][:20]:
                print(f"  ⚠ Process: {proc['name']}")
                print(f"     PID: {proc['pid']}")
                print(f"     User: {proc['username']}")
                if 'details' in proc:
                    if 'ExecutablePath' in proc['details']:
                        print(f"     Path: {proc['details']['ExecutablePath']}")
        
        if self.findings['suspicious_processes']:
            print(f"\n[SUSPICIOUS PROCESSES: {len(self.findings['suspicious_processes'])}]")
            print("-" * 70)
            for proc in self.findings['suspicious_processes'][:20]:
                print(f"  ⚠ Process: {proc['name']}")
                print(f"     PID: {proc['pid']}")
                print(f"     User: {proc['username']}")
                if 'details' in proc:
                    if 'CommandLine' in proc['details']:
                        cmd = proc['details']['CommandLine']
                        print(f"     Command: {cmd[:100]}")
        
        if self.findings['new_listening_ports']:
            print(f"\n[NEW LISTENING PORTS: {len(self.findings['new_listening_ports'])}]")
            print("-" * 70)
            for port in self.findings['new_listening_ports']:
                print(f"  ⚠ {port['protocol']}: {port['local_address']}")
        
        if self.findings['suspicious_connections']:
            print(f"\n[SUSPICIOUS CONNECTIONS: {len(self.findings['suspicious_connections'])}]")
            print("-" * 70)
            for conn in self.findings['suspicious_connections'][:20]:
                print(f"  ⚠ {conn['protocol']}: {conn['local_address']} -> {conn['foreign_address']}")
                print(f"     State: {conn['state']}, PID: {conn['pid']}")
                if 'reason' in conn:
                    print(f"     Reason: {conn['reason']}")
        
        if self.findings['new_startup_items']:
            print(f"\n[NEW STARTUP ITEMS: {len(self.findings['new_startup_items'])}]")
            print("-" * 70)
            for item in self.findings['new_startup_items']:
                print(f"  ⚠ {item['caption']}")
                print(f"     Command: {item['command'][:80]}")
                print(f"     Location: {item['location']}")
        
        print("\n" + "="*70)
        print("⚠ WARNING: Anomalies detected!")
        print("="*70)
    
    def export_findings(self, filename='pncm_findings_windows.json'):
        """Export findings to JSON"""
        output = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'findings': dict(self.findings)
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\nFindings exported to {filename}")
    
    def monitor_continuous(self, interval=60):
        """Continuously monitor for anomalies"""
        import time
        
        print(f"Starting continuous monitoring (checking every {interval} seconds)")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Checking for anomalies...")
                
                findings = self.check_anomalies()
                
                if findings:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    self.export_findings(f'pncm_findings_{timestamp}.json')
                
                print(f"\nNext check in {interval} seconds...")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user")

def main():
    parser = argparse.ArgumentParser(
        description='Windows Process and Network Connection Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create baseline
  python pncm_windows.py --create-baseline
  
  # Check for anomalies
  python pncm_windows.py --check
  
  # Continuous monitoring
  python pncm_windows.py --monitor --interval 60
  
  # Export findings
  python pncm_windows.py --check --export findings.json

Note: Run as Administrator for full system access.
        """
    )
    
    parser.add_argument('--create-baseline', action='store_true',
                       help='Create baseline of normal system state')
    parser.add_argument('--check', action='store_true',
                       help='Check for anomalies')
    parser.add_argument('--monitor', action='store_true',
                       help='Continuous monitoring mode')
    parser.add_argument('--baseline-file', type=str, default='pncm_baseline_windows.json',
                       help='Baseline file path')
    parser.add_argument('--export', type=str, metavar='FILE',
                       help='Export findings to JSON file')
    parser.add_argument('--interval', type=int, default=60,
                       help='Check interval in seconds for monitoring mode')
    
    args = parser.parse_args()
    
    # Check if running on Windows
    if sys.platform != 'win32':
        print("Error: This script is designed for Windows systems only.")
        print("For Linux systems, use pncm.py instead.")
        sys.exit(1)
    
    pncm = WindowsProcessNetworkMonitor(baseline_file=args.baseline_file)
    
    if args.create_baseline:
        pncm.create_baseline()
    elif args.check:
        findings = pncm.check_anomalies()
        if args.export:
            pncm.export_findings(args.export)
        sys.exit(0 if not findings else 1)
    elif args.monitor:
        if not pncm.load_baseline():
            print("\nCreating initial baseline for monitoring...")
            pncm.create_baseline()
        pncm.monitor_continuous(interval=args.interval)
    else:
        parser.print_help()
        print("\nPlease specify --create-baseline, --check, or --monitor")
        sys.exit(1)

if __name__ == '__main__':
    main()
