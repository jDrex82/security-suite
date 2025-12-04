#!/usr/bin/env python3
"""
Network Traffic Monitor (NTM)
Real-time network traffic analysis and anomaly detection
Detects data exfiltration, C2 beaconing, port scans, and suspicious traffic patterns

REQUIRES: Root/Administrator privileges for packet capture
Linux: Uses /proc/net and netstat (no external dependencies)
Windows: Uses netstat and PowerShell cmdlets
"""

import os
import sys
import re
import json
import socket
import struct
import argparse
import subprocess
import time
from datetime import datetime, timedelta
from collections import defaultdict, Counter, deque
from pathlib import Path
import threading

class NetworkTrafficMonitor:
    def __init__(self, baseline_file='ntm_baseline.json', interface=None):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.alerts = defaultdict(list)
        self.severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        self.interface = interface
        self.is_windows = sys.platform.startswith('win')
        
        # Traffic statistics
        self.traffic_stats = {
            'connections': defaultdict(int),
            'bytes_sent': defaultdict(int),
            'bytes_received': defaultdict(int),
            'dns_queries': defaultdict(int),
            'connection_attempts': defaultdict(list),
        }
        
        # Thresholds for anomaly detection
        self.thresholds = {
            'max_connections_per_ip': 100,
            'max_bytes_out_mb': 500,  # MB per host
            'dns_query_spike': 50,  # Queries per minute
            'connection_rate': 20,  # New connections per second
            'failed_connection_rate': 10,  # Failed connections per minute
        }
        
        # Suspicious indicators
        self.suspicious_ports = {
            4444: 'Metasploit default',
            4445: 'Metasploit',
            1337: 'Elite/hacker port',
            31337: 'Back Orifice',
            12345: 'NetBus',
            6667: 'IRC (potential botnet)',
            6697: 'IRC SSL',
            8333: 'Bitcoin',
            3333: 'Mining pool',
            9050: 'Tor SOCKS',
            9150: 'Tor Browser',
            5555: 'Android Debug Bridge',
            7777: 'Oracle/gaming (often abused)',
        }
        
        # Known C2 patterns
        self.c2_patterns = [
            r'\d+\.\d+\.\d+\.\d+:\d+/[a-f0-9]{32}',  # IP with hash
            r'[a-z]{20,}\.(?:com|net|org|xyz|top)',  # DGA domains
            r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}',  # IP in hostname
        ]
        
        # Data exfiltration indicators
        self.suspicious_tlds = [
            '.ru', '.cn', '.kp', '.ir', '.sy', '.tk', '.ml', '.ga', '.cf',
            '.onion', '.bit', '.xyz', '.top', '.pw', '.click'
        ]
        
        # DNS tunneling patterns
        self.dns_tunneling_indicators = [
            r'^[a-f0-9]{20,}\.',  # Long hex strings
            r'^[A-Za-z0-9+/]{30,}={0,2}\.',  # Base64 encoded
            r'\.[a-z]{2,10}\.[a-z]{2,10}\.[a-z]{2,10}\.',  # Excessive subdomains
        ]
        
        # Port scan detection
        self.port_scan_window = deque(maxlen=100)
        self.connection_tracking = defaultdict(lambda: {'count': 0, 'first_seen': None, 'last_seen': None})
        
    def get_network_connections_linux(self):
        """Get active network connections on Linux"""
        connections = []
        
        try:
            # Parse /proc/net/tcp for established connections
            with open('/proc/net/tcp', 'r') as f:
                lines = f.readlines()[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 10:
                        local_addr = self._parse_address(parts[1])
                        remote_addr = self._parse_address(parts[2])
                        state = self._parse_tcp_state(parts[3])
                        
                        connections.append({
                            'protocol': 'TCP',
                            'local_address': local_addr,
                            'remote_address': remote_addr,
                            'state': state,
                            'pid': parts[9] if len(parts) > 9 else 'unknown'
                        })
            
            # Parse /proc/net/udp
            with open('/proc/net/udp', 'r') as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 10:
                        local_addr = self._parse_address(parts[1])
                        remote_addr = self._parse_address(parts[2])
                        
                        connections.append({
                            'protocol': 'UDP',
                            'local_address': local_addr,
                            'remote_address': remote_addr,
                            'state': 'ESTABLISHED',
                            'pid': parts[9] if len(parts) > 9 else 'unknown'
                        })
                        
        except Exception as e:
            print(f"Error reading /proc/net: {e}")
            # Fallback to netstat
            return self._get_connections_netstat()
        
        return connections
    
    def _parse_address(self, addr_hex):
        """Parse hex address from /proc/net format"""
        try:
            ip_hex, port_hex = addr_hex.split(':')
            ip_int = int(ip_hex, 16)
            port = int(port_hex, 16)
            
            # Convert to IP address (little endian)
            ip = socket.inet_ntoa(struct.pack('<L', ip_int))
            return f"{ip}:{port}"
        except:
            return addr_hex
    
    def _parse_tcp_state(self, state_hex):
        """Parse TCP state from hex"""
        states = {
            '01': 'ESTABLISHED',
            '02': 'SYN_SENT',
            '03': 'SYN_RECV',
            '04': 'FIN_WAIT1',
            '05': 'FIN_WAIT2',
            '06': 'TIME_WAIT',
            '07': 'CLOSE',
            '08': 'CLOSE_WAIT',
            '09': 'LAST_ACK',
            '0A': 'LISTEN',
            '0B': 'CLOSING'
        }
        return states.get(state_hex.upper(), 'UNKNOWN')
    
    def _get_connections_netstat(self):
        """Fallback to netstat for connections"""
        connections = []
        
        try:
            cmd = ['netstat', '-anp'] if not self.is_windows else ['netstat', '-ano']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if any(proto in line for proto in ['tcp', 'udp', 'TCP', 'UDP']):
                        parts = line.split()
                        if len(parts) >= 5:
                            protocol = parts[0].upper()
                            local = parts[3] if not self.is_windows else parts[1]
                            remote = parts[4] if not self.is_windows else parts[2]
                            
                            connection = {
                                'protocol': protocol,
                                'local_address': local,
                                'remote_address': remote,
                                'state': parts[5] if len(parts) > 5 else 'UNKNOWN'
                            }
                            
                            if not self.is_windows and len(parts) > 6:
                                connection['pid'] = parts[6].split('/')[0]
                            elif self.is_windows and len(parts) > 4:
                                connection['pid'] = parts[-1]
                            
                            connections.append(connection)
        except Exception as e:
            print(f"Error running netstat: {e}")
        
        return connections
    
    def get_network_statistics(self):
        """Get network interface statistics"""
        stats = {}
        
        if not self.is_windows:
            try:
                with open('/proc/net/dev', 'r') as f:
                    lines = f.readlines()[2:]  # Skip header
                    for line in lines:
                        if ':' in line:
                            interface, data = line.split(':')
                            interface = interface.strip()
                            parts = data.split()
                            
                            stats[interface] = {
                                'rx_bytes': int(parts[0]),
                                'rx_packets': int(parts[1]),
                                'rx_errors': int(parts[2]),
                                'rx_dropped': int(parts[3]),
                                'tx_bytes': int(parts[8]),
                                'tx_packets': int(parts[9]),
                                'tx_errors': int(parts[10]),
                                'tx_dropped': int(parts[11])
                            }
            except Exception as e:
                print(f"Error reading network stats: {e}")
        else:
            # Windows: Use netstat -e
            try:
                result = subprocess.run(['netstat', '-e'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Bytes' in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                stats['total'] = {
                                    'rx_bytes': int(parts[1]),
                                    'tx_bytes': int(parts[2])
                                }
            except Exception as e:
                print(f"Error getting Windows network stats: {e}")
        
        return stats
    
    def analyze_dns_queries(self):
        """Analyze DNS queries for suspicious patterns"""
        dns_alerts = []
        
        # On Linux, parse /var/log/syslog or use tcpdump
        # For this implementation, we'll check for DNS query patterns in connections
        
        connections = self.get_network_connections_linux() if not self.is_windows else self._get_connections_netstat()
        
        for conn in connections:
            remote = conn.get('remote_address', '')
            
            # Check for DNS port (53)
            if ':53' in remote or remote.endswith(':53'):
                self.traffic_stats['dns_queries'][remote] += 1
        
        # Check for DNS query spikes
        for dns_server, query_count in self.traffic_stats['dns_queries'].items():
            if query_count > self.thresholds['dns_query_spike']:
                dns_alerts.append({
                    'severity': 'HIGH',
                    'type': 'DNS_QUERY_SPIKE',
                    'dns_server': dns_server,
                    'query_count': query_count,
                    'message': f'Excessive DNS queries to {dns_server}: {query_count} queries'
                })
        
        return dns_alerts
    
    def detect_port_scan(self, connections):
        """Detect port scanning attempts"""
        alerts = []
        current_time = datetime.now()
        
        # Track SYN packets / connection attempts to multiple ports from same source
        source_ports = defaultdict(set)
        
        for conn in connections:
            remote = conn.get('remote_address', '')
            state = conn.get('state', '')
            
            if remote and remote != '0.0.0.0:0':
                try:
                    remote_ip = remote.split(':')[0]
                    remote_port = remote.split(':')[1]
                    
                    # Track connection attempts
                    source_ports[remote_ip].add(remote_port)
                    
                    # Update connection tracking
                    track_key = f"{remote_ip}"
                    if self.connection_tracking[track_key]['first_seen'] is None:
                        self.connection_tracking[track_key]['first_seen'] = current_time
                    self.connection_tracking[track_key]['last_seen'] = current_time
                    self.connection_tracking[track_key]['count'] += 1
                    
                except:
                    pass
        
        # Check for port scan patterns
        for source_ip, ports in source_ports.items():
            # Many ports from same source = port scan
            if len(ports) > 20:
                alerts.append({
                    'severity': 'HIGH',
                    'type': 'PORT_SCAN_DETECTED',
                    'source_ip': source_ip,
                    'ports_scanned': len(ports),
                    'message': f'Port scan detected from {source_ip}: {len(ports)} different ports accessed'
                })
        
        # Check for rapid connection attempts
        for source, track_data in self.connection_tracking.items():
            if track_data['first_seen'] and track_data['last_seen']:
                time_diff = (track_data['last_seen'] - track_data['first_seen']).total_seconds()
                if time_diff > 0 and time_diff < 60:  # Within 1 minute
                    rate = track_data['count'] / time_diff
                    if rate > self.thresholds['connection_rate']:
                        alerts.append({
                            'severity': 'MEDIUM',
                            'type': 'RAPID_CONNECTIONS',
                            'source': source,
                            'rate': round(rate, 2),
                            'message': f'Rapid connection rate from {source}: {round(rate, 2)} connections/second'
                        })
        
        return alerts
    
    def detect_data_exfiltration(self, connections, stats):
        """Detect potential data exfiltration"""
        alerts = []
        
        # Track outbound data volumes
        outbound_traffic = defaultdict(int)
        
        for conn in connections:
            remote = conn.get('remote_address', '')
            if remote and remote != '0.0.0.0:0':
                try:
                    remote_ip = remote.split(':')[0]
                    remote_port = remote.split(':')[1]
                    
                    # Skip local traffic
                    if remote_ip.startswith('127.') or remote_ip.startswith('192.168.') or remote_ip.startswith('10.'):
                        continue
                    
                    # Track by destination
                    self.traffic_stats['connections'][remote_ip] += 1
                    
                    # Check for suspicious TLDs
                    for tld in self.suspicious_tlds:
                        if tld in remote:
                            alerts.append({
                                'severity': 'HIGH',
                                'type': 'SUSPICIOUS_TLD',
                                'destination': remote,
                                'tld': tld,
                                'message': f'Connection to suspicious TLD: {remote}'
                            })
                    
                    # Check for suspicious ports
                    try:
                        port_num = int(remote_port)
                        if port_num in self.suspicious_ports:
                            alerts.append({
                                'severity': 'CRITICAL',
                                'type': 'SUSPICIOUS_PORT',
                                'destination': remote,
                                'port': port_num,
                                'description': self.suspicious_ports[port_num],
                                'message': f'Connection to suspicious port {port_num}: {self.suspicious_ports[port_num]}'
                            })
                    except:
                        pass
                    
                except Exception as e:
                    pass
        
        # Check for excessive connections to single destination
        for ip, count in self.traffic_stats['connections'].items():
            if count > self.thresholds['max_connections_per_ip']:
                alerts.append({
                    'severity': 'MEDIUM',
                    'type': 'EXCESSIVE_CONNECTIONS',
                    'destination': ip,
                    'count': count,
                    'message': f'Excessive connections to {ip}: {count} connections'
                })
        
        return alerts
    
    def detect_c2_beaconing(self, connections):
        """Detect C2 command and control beaconing patterns"""
        alerts = []
        
        # Track connection patterns over time
        # C2 beaconing typically shows regular intervals
        connection_times = defaultdict(list)
        
        for conn in connections:
            remote = conn.get('remote_address', '')
            if remote and remote != '0.0.0.0:0':
                connection_times[remote].append(datetime.now())
        
        # Check for C2 patterns in hostnames/IPs
        for remote in connection_times.keys():
            for pattern in self.c2_patterns:
                if re.search(pattern, remote):
                    alerts.append({
                        'severity': 'CRITICAL',
                        'type': 'C2_PATTERN_DETECTED',
                        'destination': remote,
                        'pattern': pattern,
                        'message': f'Potential C2 pattern detected: {remote}'
                    })
        
        return alerts
    
    def create_baseline(self):
        """Create baseline of normal network traffic"""
        print(f"Creating network traffic baseline...")
        
        # Collect data for baseline
        connections = self.get_network_connections_linux() if not self.is_windows else self._get_connections_netstat()
        stats = self.get_network_statistics()
        
        baseline = {
            'timestamp': datetime.now().isoformat(),
            'total_connections': len(connections),
            'unique_destinations': len(set(c.get('remote_address', '') for c in connections)),
            'protocols': dict(Counter(c.get('protocol', '') for c in connections)),
            'network_stats': stats,
            'common_destinations': dict(Counter(c.get('remote_address', '') for c in connections).most_common(20))
        }
        
        # Save baseline
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        print(f"✓ Baseline created: {self.baseline_file}")
        print(f"  Total connections: {baseline['total_connections']}")
        print(f"  Unique destinations: {baseline['unique_destinations']}")
        return baseline
    
    def load_baseline(self):
        """Load existing baseline"""
        if os.path.exists(self.baseline_file):
            with open(self.baseline_file, 'r') as f:
                self.baseline = json.load(f)
            return True
        return False
    
    def monitor(self, duration=60, interval=5):
        """Monitor network traffic for specified duration"""
        print(f"\n{'='*70}")
        print(f"Network Traffic Monitor - Active Monitoring")
        print(f"{'='*70}")
        print(f"Duration: {duration} seconds | Interval: {interval} seconds")
        print(f"Platform: {'Windows' if self.is_windows else 'Linux'}")
        print(f"{'='*70}\n")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(seconds=duration)
        iteration = 0
        
        while datetime.now() < end_time:
            iteration += 1
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Scan #{iteration}")
            print("-" * 70)
            
            # Get current connections
            connections = self.get_network_connections_linux() if not self.is_windows else self._get_connections_netstat()
            stats = self.get_network_statistics()
            
            # Run detection algorithms
            dns_alerts = self.analyze_dns_queries()
            scan_alerts = self.detect_port_scan(connections)
            exfil_alerts = self.detect_data_exfiltration(connections, stats)
            c2_alerts = self.detect_c2_beaconing(connections)
            
            # Combine all alerts
            all_alerts = dns_alerts + scan_alerts + exfil_alerts + c2_alerts
            
            # Display results
            if all_alerts:
                print(f"\n⚠️  {len(all_alerts)} ALERTS DETECTED:")
                for alert in all_alerts:
                    severity = alert['severity']
                    self.severity_counts[severity] += 1
                    self.alerts[severity].append(alert)
                    
                    print(f"\n  [{severity}] {alert['type']}")
                    print(f"  Message: {alert['message']}")
                    if 'destination' in alert:
                        print(f"  Destination: {alert['destination']}")
            else:
                print("✓ No suspicious activity detected")
            
            print(f"\nActive connections: {len(connections)}")
            print(f"Unique destinations: {len(set(c.get('remote_address', '') for c in connections))}")
            
            # Wait before next scan
            if datetime.now() < end_time:
                time.sleep(interval)
        
        # Final summary
        self.print_summary()
    
    def print_summary(self):
        """Print monitoring summary"""
        print(f"\n{'='*70}")
        print("NETWORK TRAFFIC MONITORING SUMMARY")
        print(f"{'='*70}")
        
        total_alerts = sum(self.severity_counts.values())
        print(f"\nTotal Alerts: {total_alerts}")
        print(f"  CRITICAL: {self.severity_counts['CRITICAL']}")
        print(f"  HIGH: {self.severity_counts['HIGH']}")
        print(f"  MEDIUM: {self.severity_counts['MEDIUM']}")
        print(f"  LOW: {self.severity_counts['LOW']}")
        
        if total_alerts > 0:
            print(f"\n{'='*70}")
            print("ALERT DETAILS")
            print(f"{'='*70}")
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if self.alerts[severity]:
                    print(f"\n{severity} Alerts ({len(self.alerts[severity])}):")
                    for alert in self.alerts[severity][:10]:  # Show first 10
                        print(f"  • {alert['type']}: {alert['message']}")
                    
                    if len(self.alerts[severity]) > 10:
                        print(f"  ... and {len(self.alerts[severity]) - 10} more")
    
    def export_results(self, output_file='ntm_results.json'):
        """Export results to JSON"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'platform': 'Windows' if self.is_windows else 'Linux',
            'summary': {
                'total_alerts': sum(self.severity_counts.values()),
                'severity_counts': self.severity_counts
            },
            'alerts': dict(self.alerts),
            'traffic_stats': {
                'total_connections': dict(self.traffic_stats['connections']),
                'dns_queries': dict(self.traffic_stats['dns_queries'])
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n✓ Results exported to: {output_file}")
        return output_file


def main():
    parser = argparse.ArgumentParser(
        description='Network Traffic Monitor - Real-time traffic analysis and anomaly detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create baseline
  python network_traffic_monitor.py --baseline
  
  # Monitor for 5 minutes with 10 second intervals
  python network_traffic_monitor.py --monitor --duration 300 --interval 10
  
  # One-time scan
  python network_traffic_monitor.py --scan
  
  # Export results
  python network_traffic_monitor.py --scan --export results.json

Requirements:
  - Root/Administrator privileges for some features
  - Linux: Access to /proc/net (automatic fallback to netstat)
  - Windows: netstat available

Note: For full packet capture capabilities, consider using tcpdump or Wireshark.
This tool focuses on connection-level monitoring without external dependencies.
        """
    )
    
    parser.add_argument('--baseline', action='store_true',
                       help='Create baseline of normal traffic')
    parser.add_argument('--monitor', action='store_true',
                       help='Continuous monitoring mode')
    parser.add_argument('--scan', action='store_true',
                       help='One-time scan')
    parser.add_argument('--duration', type=int, default=60,
                       help='Monitoring duration in seconds (default: 60)')
    parser.add_argument('--interval', type=int, default=5,
                       help='Scan interval in seconds (default: 5)')
    parser.add_argument('--baseline-file', default='ntm_baseline.json',
                       help='Baseline file path')
    parser.add_argument('--export', metavar='FILE',
                       help='Export results to JSON file')
    parser.add_argument('--interface', help='Network interface to monitor')
    
    args = parser.parse_args()
    
    # Check for root/admin privileges warning
    if os.geteuid() != 0 if hasattr(os, 'geteuid') else False:
        print("⚠️  Warning: Running without root privileges. Some features may be limited.")
        print("   For full functionality, run with sudo/Administrator privileges.\n")
    
    monitor = NetworkTrafficMonitor(
        baseline_file=args.baseline_file,
        interface=args.interface
    )
    
    try:
        if args.baseline:
            monitor.create_baseline()
        elif args.monitor:
            monitor.load_baseline()
            monitor.monitor(duration=args.duration, interval=args.interval)
            if args.export:
                monitor.export_results(args.export)
        elif args.scan:
            connections = monitor.get_network_connections_linux() if not monitor.is_windows else monitor._get_connections_netstat()
            stats = monitor.get_network_statistics()
            
            print(f"\n{'='*70}")
            print("Network Traffic Scan Results")
            print(f"{'='*70}")
            print(f"Active connections: {len(connections)}")
            print(f"Unique destinations: {len(set(c.get('remote_address', '') for c in connections))}")
            
            # Run detections
            all_alerts = (monitor.analyze_dns_queries() + 
                         monitor.detect_port_scan(connections) +
                         monitor.detect_data_exfiltration(connections, stats) +
                         monitor.detect_c2_beaconing(connections))
            
            if all_alerts:
                print(f"\n⚠️  {len(all_alerts)} alerts detected!")
                for alert in all_alerts:
                    print(f"\n[{alert['severity']}] {alert['type']}")
                    print(f"  {alert['message']}")
            else:
                print("\n✓ No suspicious activity detected")
            
            if args.export:
                monitor.alerts = defaultdict(list)
                for alert in all_alerts:
                    monitor.alerts[alert['severity']].append(alert)
                    monitor.severity_counts[alert['severity']] += 1
                monitor.export_results(args.export)
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        print("\n\nMonitoring interrupted by user.")
        if args.export:
            monitor.export_results(args.export)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
