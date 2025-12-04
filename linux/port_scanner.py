#!/usr/bin/env python3
"""
Network Port Scanner & Service Detector
Multi-threaded port scanning with service detection and vulnerability checks
Perfect for critical infrastructure protection and network security auditing
"""

import socket
import sys
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import threading

class PortScanner:
    """Professional network port scanner with service detection"""
    
    # Common services and their typical ports
    COMMON_PORTS = {
        20: 'FTP Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
        587: 'SMTP Submission', 993: 'IMAPS', 995: 'POP3S',
        1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB'
    }
    
    # Service banners for identification
    SERVICE_SIGNATURES = {
        'SSH': [b'SSH-', b'OpenSSH'],
        'FTP': [b'220', b'FTP'],
        'HTTP': [b'HTTP/', b'Server:'],
        'SMTP': [b'220', b'SMTP'],
        'POP3': [b'+OK'],
        'IMAP': [b'* OK'],
        'MySQL': [b'\x00\x00\x00\x0a'],
    }
    
    # Known vulnerabilities based on service/version
    VULNERABILITIES = {
        'telnet': 'CRITICAL: Telnet uses unencrypted communication',
        'ftp': 'HIGH: FTP transmits credentials in plaintext',
        'http': 'MEDIUM: Unencrypted HTTP on port 80',
        'smb': 'HIGH: SMB exposed - potential for EternalBlue-style attacks',
        'redis': 'HIGH: Redis often misconfigured without authentication',
        'mongodb': 'HIGH: MongoDB often exposed without authentication',
        'vnc': 'MEDIUM: VNC can have weak authentication',
        'rdp': 'MEDIUM: RDP exposed - brute force target',
        'elasticsearch': 'HIGH: Elasticsearch often exposed without auth'
    }
    
    def __init__(self, target, timeout=1.0, threads=50):
        """
        Initialize port scanner
        
        Args:
            target: IP address or hostname to scan
            timeout: Socket timeout in seconds
            threads: Number of concurrent scanning threads
        """
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.results = {}
        self.lock = threading.Lock()
        
        # Resolve hostname to IP
        try:
            self.ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"Error: Could not resolve hostname {target}")
            sys.exit(1)
    
    def scan_port(self, port):
        """
        Scan a single port
        
        Returns:
            dict: Port information if open, None otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))
            
            if result == 0:
                # Port is open, try to grab banner
                service_name = self.COMMON_PORTS.get(port, 'Unknown')
                banner = self.grab_banner(sock, port)
                
                port_info = {
                    'port': port,
                    'state': 'open',
                    'service': service_name,
                    'banner': banner,
                    'detected_service': self.identify_service(banner, port)
                }
                
                # Check for known vulnerabilities
                vuln = self.check_vulnerability(port, service_name.lower())
                if vuln:
                    port_info['vulnerability'] = vuln
                
                sock.close()
                return port_info
            
            sock.close()
            return None
            
        except socket.timeout:
            return None
        except socket.error:
            return None
        except Exception as e:
            return None
    
    def grab_banner(self, sock, port):
        """
        Attempt to grab service banner
        
        Args:
            sock: Connected socket
            port: Port number
            
        Returns:
            str: Banner text or empty string
        """
        try:
            sock.settimeout(2.0)
            
            # Send protocol-specific probes
            if port in [80, 8080, 8443]:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 25:
                pass  # SMTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            else:
                sock.send(b'\r\n')
            
            banner = sock.recv(1024)
            return banner.decode('utf-8', errors='ignore').strip()
        except:
            return ''
    
    def identify_service(self, banner, port):
        """
        Identify service from banner
        
        Args:
            banner: Banner string
            port: Port number
            
        Returns:
            str: Identified service name
        """
        if not banner:
            return self.COMMON_PORTS.get(port, 'Unknown')
        
        banner_bytes = banner.encode('utf-8', errors='ignore')
        
        for service, signatures in self.SERVICE_SIGNATURES.items():
            for sig in signatures:
                if sig in banner_bytes:
                    return service
        
        return self.COMMON_PORTS.get(port, 'Unknown')
    
    def check_vulnerability(self, port, service):
        """
        Check for known vulnerabilities
        
        Args:
            port: Port number
            service: Service name
            
        Returns:
            str: Vulnerability description or None
        """
        # Check by port number
        if port == 23:
            return self.VULNERABILITIES['telnet']
        elif port == 21:
            return self.VULNERABILITIES['ftp']
        elif port == 80:
            return self.VULNERABILITIES['http']
        elif port == 445:
            return self.VULNERABILITIES['smb']
        elif port == 6379:
            return self.VULNERABILITIES['redis']
        elif port == 27017:
            return self.VULNERABILITIES['mongodb']
        elif port == 5900:
            return self.VULNERABILITIES['vnc']
        elif port == 3389:
            return self.VULNERABILITIES['rdp']
        elif port == 9200:
            return self.VULNERABILITIES['elasticsearch']
        
        # Check by service name
        for key, vuln in self.VULNERABILITIES.items():
            if key in service.lower():
                return vuln
        
        return None
    
    def scan_ports(self, ports):
        """
        Scan multiple ports with threading
        
        Args:
            ports: List of ports to scan
        """
        print(f"\n{'='*70}")
        print(f"Network Port Scanner - Starting Scan")
        print(f"{'='*70}")
        print(f"Target: {self.target} ({self.ip})")
        print(f"Ports: {len(ports)} ports")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            
            completed = 0
            total = len(ports)
            
            for future in as_completed(future_to_port):
                completed += 1
                port = future_to_port[future]
                
                try:
                    result = future.result()
                    if result:
                        with self.lock:
                            self.open_ports.append(result)
                            print(f"[+] Port {result['port']}/tcp OPEN - {result['service']}")
                            if result.get('banner'):
                                print(f"    Banner: {result['banner'][:80]}")
                            if result.get('vulnerability'):
                                print(f"    ⚠️  {result['vulnerability']}")
                except Exception as e:
                    pass
                
                # Progress indicator
                if completed % 100 == 0:
                    print(f"\r[*] Progress: {completed}/{total} ports scanned", end='', flush=True)
        
        print(f"\n")
    
    def generate_report(self):
        """Generate comprehensive scan report"""
        print(f"\n{'='*70}")
        print(f"Scan Report - {self.target} ({self.ip})")
        print(f"{'='*70}\n")
        
        if not self.open_ports:
            print("No open ports detected.")
            return
        
        # Sort by port number
        self.open_ports.sort(key=lambda x: x['port'])
        
        # Summary statistics
        print(f"📊 SUMMARY")
        print(f"{'─'*70}")
        print(f"Total open ports: {len(self.open_ports)}")
        
        # Group by service
        services = defaultdict(int)
        vulnerabilities = []
        
        for port in self.open_ports:
            services[port['service']] += 1
            if port.get('vulnerability'):
                vulnerabilities.append(port)
        
        print(f"Unique services: {len(services)}")
        print(f"Vulnerabilities: {len(vulnerabilities)}\n")
        
        # Service breakdown
        print(f"🔍 SERVICES DETECTED")
        print(f"{'─'*70}")
        for service, count in sorted(services.items(), key=lambda x: x[1], reverse=True):
            print(f"  {service}: {count} port(s)")
        print()
        
        # Detailed port information
        print(f"🔓 OPEN PORTS")
        print(f"{'─'*70}")
        print(f"{'Port':<8} {'State':<10} {'Service':<20} {'Detected':<15}")
        print(f"{'─'*70}")
        
        for port in self.open_ports:
            print(f"{port['port']:<8} {port['state']:<10} {port['service']:<20} {port['detected_service']:<15}")
            if port.get('banner') and len(port['banner']) > 0:
                print(f"         Banner: {port['banner'][:70]}")
        
        # Vulnerability report
        if vulnerabilities:
            print(f"\n⚠️  VULNERABILITIES DETECTED")
            print(f"{'─'*70}")
            for port in vulnerabilities:
                print(f"Port {port['port']}/tcp ({port['service']})")
                print(f"  {port['vulnerability']}\n")
        
        # Security recommendations
        print(f"\n🔒 SECURITY RECOMMENDATIONS")
        print(f"{'─'*70}")
        
        recommendations = []
        
        if any(p['port'] == 23 for p in self.open_ports):
            recommendations.append("• CRITICAL: Disable Telnet (port 23) - use SSH instead")
        
        if any(p['port'] == 21 for p in self.open_ports):
            recommendations.append("• HIGH: Replace FTP (port 21) with SFTP/FTPS")
        
        if any(p['port'] in [80, 8080] for p in self.open_ports):
            recommendations.append("• MEDIUM: Implement HTTPS for all web services")
        
        if any(p['port'] == 3389 for p in self.open_ports):
            recommendations.append("• MEDIUM: Restrict RDP access, use VPN, enable NLA")
        
        if any(p['port'] in [3306, 5432, 1433, 27017] for p in self.open_ports):
            recommendations.append("• HIGH: Database ports exposed - restrict to localhost/VPN")
        
        if any(p['port'] in [6379, 9200] for p in self.open_ports):
            recommendations.append("• HIGH: Data store exposed - enable authentication and firewall")
        
        if len(self.open_ports) > 20:
            recommendations.append("• MEDIUM: Large attack surface - close unnecessary ports")
        
        if recommendations:
            for rec in recommendations:
                print(rec)
        else:
            print("✓ No critical security issues detected")
        
        print(f"\n{'='*70}\n")
    
    def export_json(self, filename):
        """
        Export results to JSON file
        
        Args:
            filename: Output filename
        """
        report = {
            'scan_info': {
                'target': self.target,
                'ip': self.ip,
                'timestamp': datetime.now().isoformat(),
                'total_open_ports': len(self.open_ports)
            },
            'open_ports': self.open_ports,
            'summary': {
                'services': dict(defaultdict(int)),
                'vulnerabilities': len([p for p in self.open_ports if p.get('vulnerability')])
            }
        }
        
        # Calculate service counts
        for port in self.open_ports:
            report['summary']['services'][port['service']] = \
                report['summary']['services'].get(port['service'], 0) + 1
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report exported to: {filename}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Network Port Scanner & Service Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan common ports
  python3 port_scanner.py 192.168.1.1
  
  # Scan specific port range
  python3 port_scanner.py 192.168.1.1 -p 1-1000
  
  # Scan specific ports
  python3 port_scanner.py example.com -p 22,80,443,3306
  
  # Fast scan with more threads
  python3 port_scanner.py 10.0.0.1 -t 100
  
  # Export results
  python3 port_scanner.py 192.168.1.1 --export scan_report.json
  
  # Full scan (all 65535 ports - SLOW!)
  python3 port_scanner.py 192.168.1.1 --full
        """
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='common',
                       help='Ports to scan: "common", "1-1000", or "22,80,443"')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=float, default=1.0,
                       help='Socket timeout in seconds (default: 1.0)')
    parser.add_argument('--full', action='store_true',
                       help='Scan all 65535 ports (SLOW!)')
    parser.add_argument('--export', help='Export results to JSON file')
    
    args = parser.parse_args()
    
    # Determine ports to scan
    if args.full:
        ports = list(range(1, 65536))
    elif args.ports == 'common':
        # Common ports for typical services
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
                 8080, 8443, 9200, 27017]
    elif '-' in args.ports:
        # Port range: 1-1000
        start, end = args.ports.split('-')
        ports = list(range(int(start), int(end) + 1))
    else:
        # Comma-separated: 22,80,443
        ports = [int(p.strip()) for p in args.ports.split(',')]
    
    # Initialize scanner
    scanner = PortScanner(args.target, timeout=args.timeout, threads=args.threads)
    
    # Perform scan
    scanner.scan_ports(ports)
    
    # Generate report
    scanner.generate_report()
    
    # Export if requested
    if args.export:
        scanner.export_json(args.export)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
