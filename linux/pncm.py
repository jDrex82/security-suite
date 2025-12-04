#!/usr/bin/env python3
"""
Process & Network Connection Monitor (PNCM)
Detects suspicious processes, network connections, and data exfiltration attempts
Critical for detecting malware, C2 communications, and insider threats
"""

import os
import sys
import re
import json
import socket
import argparse
import subprocess
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path

class ProcessNetworkMonitor:
    def __init__(self, baseline_file='pncm_baseline.json'):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.alerts = defaultdict(list)
        self.severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        # Suspicious patterns
        self.suspicious_commands = [
            r'nc\s+-l',  # Netcat listener
            r'bash\s+-i',  # Interactive bash
            r'/dev/tcp/',  # Bash TCP socket
            r'python.*-c.*socket',  # Python socket
            r'perl.*socket',  # Perl socket
            r'ruby.*socket',  # Ruby socket
            r'php.*fsockopen',  # PHP socket
            r'ncat|socat',  # Alternative netcat
            r'cryptonight|xmrig|minergate',  # Crypto miners
            r'wget.*\|.*sh',  # Download and execute
            r'curl.*\|.*bash',  # Download and execute
            r'base64.*-d.*\|',  # Base64 decode pipe
            r'powershell',  # PowerShell (suspicious on Linux)
            r'vssadmin.*delete.*shadows',  # Shadow copy deletion
            r'wmic.*process.*call.*create',  # WMIC
        ]
        
        self.suspicious_ports = {
            4444: 'Common Metasploit',
            4445: 'Common Metasploit',
            1337: 'Common hacker port',
            31337: 'Elite hacker port',
            6667: 'IRC (potential botnet)',
            6697: 'IRC SSL',
            8333: 'Bitcoin',
            3333: 'Mining pool',
            9050: 'Tor SOCKS',
            9150: 'Tor Browser',
        }
        
        # Known good processes (whitelist)
        self.known_good_processes = {
            'systemd', 'sshd', 'cron', 'dbus-daemon', 'rsyslogd',
            'bash', 'sh', 'ps', 'top', 'htop', 'python3', 'python',
            'grep', 'awk', 'sed', 'vim', 'nano', 'less', 'more',
            'sudo', 'su', 'login', 'getty'
        }
        
        # Suspicious network destinations
        self.suspicious_tlds = ['.onion', '.bit', '.ru', '.cn', '.kp']
        
    def get_processes(self):
        """Get all running processes with details"""
        processes = []
        
        try:
            # Use ps to get process list
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.split(None, 10)
                        if len(parts) >= 11:
                            processes.append({
                                'user': parts[0],
                                'pid': parts[1],
                                'cpu': parts[2],
                                'mem': parts[3],
                                'vsz': parts[4],
                                'rss': parts[5],
                                'tty': parts[6],
                                'stat': parts[7],
                                'start': parts[8],
                                'time': parts[9],
                                'command': parts[10]
                            })
        except Exception as e:
            print(f"Warning: Could not get process list: {e}")
        
        return processes
    
    def get_network_connections(self):
        """Get all network connections"""
        connections = []
        
        # Try multiple methods to get network connections
        methods = [
            (['ss', '-tunap'], self._parse_ss_output),
            (['netstat', '-tunap'], self._parse_netstat_output),
        ]
        
        for cmd, parser in methods:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    connections = parser(result.stdout)
                    if connections:
                        break
            except FileNotFoundError:
                continue
            except Exception as e:
                print(f"Warning: Error getting connections with {cmd[0]}: {e}")
        
        return connections
    
    def _parse_ss_output(self, output):
        """Parse ss command output"""
        connections = []
        lines = output.split('\n')[1:]  # Skip header
        
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        state = parts[0] if parts[0] != 'tcp' and parts[0] != 'udp' else parts[1]
                        local = parts[4] if len(parts) >= 5 else parts[3]
                        remote = parts[5] if len(parts) >= 6 else ''
                        
                        # Extract process info
                        process_info = ''
                        for part in parts:
                            if 'pid=' in part or 'users:' in part:
                                process_info = part
                                break
                        
                        connections.append({
                            'protocol': parts[0] if parts[0] in ['tcp', 'udp'] else 'tcp',
                            'state': state,
                            'local_addr': local.rsplit(':', 1)[0] if ':' in local else local,
                            'local_port': local.rsplit(':', 1)[1] if ':' in local else '',
                            'remote_addr': remote.rsplit(':', 1)[0] if ':' in remote else remote,
                            'remote_port': remote.rsplit(':', 1)[1] if ':' in remote else '',
                            'process': process_info
                        })
                    except Exception:
                        continue
        
        return connections
    
    def _parse_netstat_output(self, output):
        """Parse netstat command output"""
        connections = []
        lines = output.split('\n')[2:]  # Skip headers
        
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 6:
                    try:
                        local = parts[3]
                        remote = parts[4]
                        
                        connections.append({
                            'protocol': parts[0],
                            'state': parts[5] if len(parts) >= 6 else '',
                            'local_addr': local.rsplit(':', 1)[0] if ':' in local else local,
                            'local_port': local.rsplit(':', 1)[1] if ':' in local else '',
                            'remote_addr': remote.rsplit(':', 1)[0] if ':' in remote else remote,
                            'remote_port': remote.rsplit(':', 1)[1] if ':' in remote else '',
                            'process': parts[6] if len(parts) >= 7 else ''
                        })
                    except Exception:
                        continue
        
        return connections
    
    def get_listening_ports(self):
        """Get all listening ports"""
        listening = []
        
        try:
            result = subprocess.run(
                ['ss', '-tlnp'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')[1:]
                for line in lines:
                    if line.strip() and 'LISTEN' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            local = parts[3]
                            port = local.rsplit(':', 1)[1] if ':' in local else ''
                            process = parts[5] if len(parts) >= 6 else ''
                            
                            listening.append({
                                'port': port,
                                'address': local.rsplit(':', 1)[0] if ':' in local else local,
                                'process': process
                            })
        except FileNotFoundError:
            # Try netstat
            try:
                result = subprocess.run(
                    ['netstat', '-tlnp'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')[2:]
                    for line in lines:
                        if line.strip() and 'LISTEN' in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                local = parts[3]
                                port = local.rsplit(':', 1)[1] if ':' in local else ''
                                process = parts[6] if len(parts) >= 7 else ''
                                
                                listening.append({
                                    'port': port,
                                    'address': local.rsplit(':', 1)[0] if ':' in local else local,
                                    'process': process
                                })
            except Exception:
                pass
        except Exception as e:
            print(f"Warning: Could not get listening ports: {e}")
        
        return listening
    
    def check_suspicious_process(self, process):
        """Check if a process is suspicious"""
        command = process['command'].lower()
        suspicions = []
        
        # Check against suspicious command patterns
        for pattern in self.suspicious_commands:
            if re.search(pattern, command, re.IGNORECASE):
                suspicions.append(f"Matches suspicious pattern: {pattern}")
        
        # Check for processes running from /tmp or /dev/shm
        if '/tmp/' in command or '/dev/shm/' in command:
            suspicions.append("Running from temporary directory")
        
        # Check for hidden processes (starting with .)
        cmd_parts = command.split()
        if cmd_parts:
            exe = cmd_parts[0].split('/')[-1]
            if exe.startswith('.') and exe not in ['.', '..']:
                suspicions.append("Hidden process name (starts with .)")
        
        # Check for high CPU usage
        try:
            if float(process['cpu']) > 80.0:
                suspicions.append(f"High CPU usage: {process['cpu']}%")
        except ValueError:
            pass
        
        # Check for processes running as root that shouldn't be
        if process['user'] == 'root':
            exe_name = command.split()[0].split('/')[-1]
            if exe_name not in self.known_good_processes:
                if any(x in exe_name for x in ['miner', 'crypto', 'bitcoin', 'xmr']):
                    suspicions.append("Potential cryptocurrency miner running as root")
        
        return suspicions
    
    def check_suspicious_connection(self, conn):
        """Check if a network connection is suspicious"""
        suspicions = []
        
        # Check for connections to suspicious ports
        try:
            remote_port = int(conn['remote_port']) if conn['remote_port'] else 0
            if remote_port in self.suspicious_ports:
                suspicions.append(f"Suspicious port: {remote_port} ({self.suspicious_ports[remote_port]})")
        except ValueError:
            pass
        
        # Check for connections to suspicious TLDs
        remote_addr = conn['remote_addr']
        for tld in self.suspicious_tlds:
            if tld in remote_addr:
                suspicions.append(f"Suspicious TLD: {tld}")
        
        # Check for connections to localhost from remote (potential tunnel)
        if conn['local_addr'] == '127.0.0.1' and conn['remote_addr'] not in ['127.0.0.1', '', '0.0.0.0']:
            suspicions.append("Connection to localhost from remote address")
        
        # Check for non-standard SSH ports
        try:
            local_port = int(conn['local_port']) if conn['local_port'] else 0
            remote_port = int(conn['remote_port']) if conn['remote_port'] else 0
            
            if local_port in [2222, 2223, 8022, 8222] or remote_port in [2222, 2223, 8022, 8222]:
                suspicions.append("Non-standard SSH port")
        except ValueError:
            pass
        
        # Check for connections to RFC1918 addresses from internet-facing services
        if conn['local_addr'] not in ['127.0.0.1', '0.0.0.0', '::1']:
            if self._is_private_ip(conn['remote_addr']) and not self._is_private_ip(conn['local_addr']):
                suspicions.append("External connection to private IP")
        
        return suspicions
    
    def _is_private_ip(self, ip):
        """Check if IP is private"""
        try:
            # Handle IPv6 and IPv4
            if ':' in ip:
                return False  # Simplified - treat IPv6 as non-private for now
            
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.0.0.0/8
            if first == 10:
                return True
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True
            # 127.0.0.0/8
            if first == 127:
                return True
            
            return False
        except Exception:
            return False
    
    def create_baseline(self):
        """Create baseline of normal system behavior"""
        print(f"\n{'='*70}")
        print("Creating Process & Network Baseline")
        print(f"{'='*70}\n")
        
        print("📊 Collecting system behavior information...")
        
        # Get current state
        processes = self.get_processes()
        connections = self.get_network_connections()
        listening = self.get_listening_ports()
        
        baseline = {
            'created': datetime.now().isoformat(),
            'processes': {
                'count': len(processes),
                'users': list(set(p['user'] for p in processes)),
                'commands': [p['command'].split()[0] for p in processes if p['command']],
            },
            'connections': {
                'count': len(connections),
                'remote_ips': list(set(c['remote_addr'] for c in connections if c['remote_addr'] and c['remote_addr'] != '*')),
                'remote_ports': list(set(c['remote_port'] for c in connections if c['remote_port'])),
            },
            'listening_ports': [
                {'port': l['port'], 'process': l['process']}
                for l in listening
            ]
        }
        
        print(f"\n📋 Baseline Statistics:")
        print(f"   Total processes: {baseline['processes']['count']}")
        print(f"   Unique users running processes: {len(baseline['processes']['users'])}")
        print(f"   Active connections: {baseline['connections']['count']}")
        print(f"   Listening ports: {len(baseline['listening_ports'])}")
        
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
    
    def monitor(self, check_baseline=True):
        """Monitor processes and network connections"""
        print(f"\n{'='*70}")
        print("Process & Network Connection Monitor")
        print(f"{'='*70}\n")
        
        # Get current state
        print("📊 Collecting current system state...")
        processes = self.get_processes()
        connections = self.get_network_connections()
        listening = self.get_listening_ports()
        
        print(f"\n📋 Current State:")
        print(f"   Active processes: {len(processes)}")
        print(f"   Network connections: {len(connections)}")
        print(f"   Listening ports: {len(listening)}")
        
        # Check for suspicious processes
        print(f"\n{'='*70}")
        print("Suspicious Process Detection")
        print(f"{'='*70}\n")
        
        suspicious_procs = []
        for proc in processes:
            suspicions = self.check_suspicious_process(proc)
            if suspicions:
                suspicious_procs.append((proc, suspicions))
                
                severity = 'CRITICAL' if any('miner' in s.lower() or 'tmp' in s.lower() for s in suspicions) else 'HIGH'
                self.alert(
                    severity,
                    'SUSPICIOUS_PROCESS',
                    f"Suspicious process detected: {proc['command'][:60]}",
                    {
                        'pid': proc['pid'],
                        'user': proc['user'],
                        'cpu': proc['cpu'],
                        'reasons': suspicions
                    }
                )
        
        if not suspicious_procs:
            print("✅ No obviously suspicious processes detected")
        
        # Check for suspicious connections
        print(f"\n{'='*70}")
        print("Suspicious Network Connection Detection")
        print(f"{'='*70}\n")
        
        suspicious_conns = []
        for conn in connections:
            if conn['remote_addr'] and conn['remote_addr'] not in ['*', '', '0.0.0.0', '::', '127.0.0.1']:
                suspicions = self.check_suspicious_connection(conn)
                if suspicions:
                    suspicious_conns.append((conn, suspicions))
                    
                    severity = 'CRITICAL' if any('4444' in s or 'metasploit' in s.lower() for s in suspicions) else 'HIGH'
                    self.alert(
                        severity,
                        'SUSPICIOUS_CONNECTION',
                        f"Suspicious connection: {conn['local_addr']}:{conn['local_port']} -> {conn['remote_addr']}:{conn['remote_port']}",
                        {
                            'protocol': conn['protocol'],
                            'state': conn['state'],
                            'process': conn['process'],
                            'reasons': suspicions
                        }
                    )
        
        if not suspicious_conns:
            print("✅ No obviously suspicious connections detected")
        
        # Check listening ports
        print(f"\n{'='*70}")
        print("Listening Ports Analysis")
        print(f"{'='*70}\n")
        
        for listen in listening:
            try:
                port_num = int(listen['port'])
                if port_num in self.suspicious_ports:
                    self.alert(
                        'HIGH',
                        'SUSPICIOUS_LISTENER',
                        f"Suspicious port listening: {listen['port']}",
                        {
                            'reason': self.suspicious_ports[port_num],
                            'address': listen['address'],
                            'process': listen['process']
                        }
                    )
            except ValueError:
                pass
        
        # Compare with baseline if requested
        if check_baseline and self.baseline:
            print(f"\n{'='*70}")
            print("Baseline Comparison")
            print(f"{'='*70}\n")
            
            baseline_ports = set(l['port'] for l in self.baseline.get('listening_ports', []))
            current_ports = set(l['port'] for l in listening)
            
            new_ports = current_ports - baseline_ports
            if new_ports:
                self.alert(
                    'MEDIUM',
                    'NEW_LISTENING_PORT',
                    f"New listening ports detected",
                    {'ports': list(new_ports)}
                )
            
            removed_ports = baseline_ports - current_ports
            if removed_ports:
                self.alert(
                    'LOW',
                    'REMOVED_LISTENING_PORT',
                    f"Listening ports no longer active",
                    {'ports': list(removed_ports)}
                )
        
        # Resource usage analysis
        print(f"\n{'='*70}")
        print("Resource Usage Analysis")
        print(f"{'='*70}\n")
        
        # Top CPU consumers
        try:
            top_cpu = sorted(
                [p for p in processes if p['cpu']],
                key=lambda x: float(x['cpu']),
                reverse=True
            )[:5]
            
            if top_cpu:
                print("🔥 Top CPU Consumers:")
                for proc in top_cpu:
                    print(f"   {proc['cpu']}% - {proc['user']} - {proc['command'][:50]}")
        except Exception:
            pass
        
        # Top memory consumers
        try:
            top_mem = sorted(
                [p for p in processes if p['mem']],
                key=lambda x: float(x['mem']),
                reverse=True
            )[:5]
            
            if top_mem:
                print(f"\n💾 Top Memory Consumers:")
                for proc in top_mem:
                    print(f"   {proc['mem']}% - {proc['user']} - {proc['command'][:50]}")
        except Exception:
            pass
        
        # Summary
        print(f"\n{'='*70}")
        print("DETECTION SUMMARY")
        print(f"{'='*70}")
        
        total_alerts = sum(self.severity_counts.values())
        if total_alerts == 0:
            print("✅ No suspicious activity detected - System appears normal!")
        else:
            print(f"⚠️  {total_alerts} ALERTS DETECTED:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if self.severity_counts[severity] > 0:
                    print(f"   {severity}: {self.severity_counts[severity]}")
            
            print(f"\n📊 Alert Categories:")
            for category, alerts in self.alerts.items():
                print(f"   {category}: {len(alerts)}")
        
        return total_alerts == 0
    
    def export_report(self, output_file='pncm_report.json'):
        """Export monitoring results to JSON"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'baseline_file': self.baseline_file,
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
        description='Process & Network Connection Monitor - Detect suspicious behavior',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --create-baseline          # Create baseline of normal behavior
  %(prog)s --monitor                  # Monitor for suspicious activity
  %(prog)s --monitor --no-baseline    # Monitor without baseline comparison
  %(prog)s --monitor --export report.json  # Export results
  
Security Use Cases:
  - Detect malware and suspicious processes
  - Identify C2 (Command & Control) communications
  - Monitor data exfiltration attempts
  - Track cryptocurrency miners
  - Detect unauthorized network listeners
  - Identify reverse shells and backdoors
  - Monitor resource abuse
        """
    )
    
    parser.add_argument('-b', '--baseline',
                       default='pncm_baseline.json',
                       help='Baseline file path (default: pncm_baseline.json)')
    
    parser.add_argument('--create-baseline',
                       action='store_true',
                       help='Create new behavior baseline')
    
    parser.add_argument('--monitor',
                       action='store_true',
                       help='Monitor for suspicious activity')
    
    parser.add_argument('--no-baseline',
                       action='store_true',
                       help='Skip baseline comparison')
    
    parser.add_argument('-e', '--export',
                       help='Export results to JSON file')
    
    args = parser.parse_args()
    
    # Create monitor instance
    pncm = ProcessNetworkMonitor(baseline_file=args.baseline)
    
    # Load baseline if exists and needed
    if not args.no_baseline and not args.create_baseline:
        try:
            with open(args.baseline, 'r') as f:
                pncm.baseline = json.load(f)
        except FileNotFoundError:
            print(f"Note: No baseline found at {args.baseline}")
    
    # Execute requested operation
    if args.create_baseline:
        pncm.create_baseline()
    
    elif args.monitor:
        success = pncm.monitor(check_baseline=not args.no_baseline)
        if args.export:
            pncm.export_report(args.export)
        sys.exit(0 if success else 1)
    
    else:
        parser.print_help()
        print("\n💡 Tip: Start with --create-baseline to create a behavior baseline")
        print("        Then use --monitor to detect suspicious activity")

if __name__ == '__main__':
    main()
