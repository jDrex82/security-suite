#!/usr/bin/env python3
"""
SSL/TLS Certificate Monitor
Track certificate health, expiration, and security across infrastructure
Perfect for preventing outages and maintaining security compliance
"""

import ssl
import socket
import sys
import argparse
import json
from datetime import datetime, timedelta
from urllib.parse import urlparse
import re

class CertificateMonitor:
    """Professional SSL/TLS certificate monitoring and analysis"""
    
    # Weak cipher suites (considered insecure)
    WEAK_CIPHERS = [
        'DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon',
        '3DES', 'CBC', 'SHA1'  # Weak or deprecated
    ]
    
    # Minimum recommended key sizes
    MIN_KEY_SIZES = {
        'RSA': 2048,
        'DSA': 2048,
        'EC': 256
    }
    
    def __init__(self, timeout=10):
        """
        Initialize certificate monitor
        
        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout
        self.results = []
    
    def parse_target(self, target):
        """
        Parse target URL or hostname:port
        
        Args:
            target: URL, hostname, or hostname:port
            
        Returns:
            tuple: (hostname, port)
        """
        # Try to parse as URL
        if '://' in target:
            parsed = urlparse(target)
            hostname = parsed.netloc.split(':')[0]
            port = parsed.port or (443 if parsed.scheme == 'https' else 443)
        elif ':' in target:
            # hostname:port format
            hostname, port = target.split(':', 1)
            port = int(port)
        else:
            # Just hostname, assume 443
            hostname = target
            port = 443
        
        return hostname, port
    
    def get_certificate(self, hostname, port=443):
        """
        Retrieve SSL certificate from host
        
        Args:
            hostname: Target hostname
            port: Target port (default 443)
            
        Returns:
            dict: Certificate information or None
        """
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Get certificate chain
                    cert_bin = ssock.getpeercert(binary_form=True)
                    
                    return {
                        'cert': cert,
                        'cipher': cipher,
                        'version': version,
                        'cert_bin': cert_bin
                    }
        
        except socket.timeout:
            print(f"[!] Timeout connecting to {hostname}:{port}")
            return None
        except socket.gaierror:
            print(f"[!] Could not resolve hostname: {hostname}")
            return None
        except ssl.SSLError as e:
            print(f"[!] SSL error for {hostname}:{port}: {e}")
            return None
        except Exception as e:
            print(f"[!] Error connecting to {hostname}:{port}: {e}")
            return None
    
    def parse_certificate(self, cert_data, hostname, port):
        """
        Parse and analyze certificate information
        
        Args:
            cert_data: Certificate data from get_certificate
            hostname: Target hostname
            port: Target port
            
        Returns:
            dict: Parsed certificate information or None if parsing fails
        """
        cert = cert_data['cert']
        cipher = cert_data['cipher']
        version = cert_data['version']
        
        # Parse dates with error handling for different certificate formats
        try:
            # Try standard format first
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        except (KeyError, ValueError) as e:
            # Handle missing or malformed date fields
            print(f"[!] Warning: Could not parse certificate dates for {hostname}:{port}")
            print(f"    Error: {str(e)}")
            print(f"    Certificate may be in an unsupported format")
            
            # Try to continue with default values
            now = datetime.now()
            not_before = now
            not_after = now
            days_until_expiry = -999  # Indicates parsing error
        else:
            # Calculate days until expiration (only if dates parsed successfully)
            now = datetime.now()
            days_until_expiry = (not_after - now).days
        
        # Get subject information with error handling
        try:
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
        except (KeyError, ValueError, TypeError) as e:
            print(f"[!] Warning: Could not parse certificate subject/issuer for {hostname}:{port}")
            subject = {}
            issuer = {}
        
        # Get Subject Alternative Names (SANs)
        san_list = []
        try:
            if 'subjectAltName' in cert:
                san_list = [san[1] for san in cert['subjectAltName']]
        except (KeyError, ValueError, TypeError):
            pass  # SANs are optional
        
        # Analyze cipher suite
        cipher_name = cipher[0] if cipher else 'Unknown'
        cipher_strength = cipher[2] if cipher and len(cipher) > 2 else 0
        
        # Check for weak ciphers
        is_weak_cipher = any(weak in cipher_name for weak in self.WEAK_CIPHERS)
        
        # Determine severity
        severity = self.determine_severity(days_until_expiry, is_weak_cipher, version)
        
        result = {
            'hostname': hostname,
            'port': port,
            'common_name': subject.get('commonName', 'N/A'),
            'organization': subject.get('organizationName', 'N/A'),
            'issuer_cn': issuer.get('commonName', 'N/A'),
            'issuer_org': issuer.get('organizationName', 'N/A'),
            'not_before': not_before.isoformat(),
            'not_after': not_after.isoformat(),
            'days_until_expiry': days_until_expiry,
            'is_expired': days_until_expiry < 0,
            'san_list': san_list,
            'serial_number': cert.get('serialNumber', 'N/A'),
            'version': cert.get('version', 'N/A'),
            'signature_algorithm': cert.get('signatureAlgorithm', 'N/A'),
            'tls_version': version,
            'cipher_suite': cipher_name,
            'cipher_strength': cipher_strength,
            'is_weak_cipher': is_weak_cipher,
            'severity': severity,
            'issues': []
        }
        
        # Identify issues (skip if dates couldn't be parsed)
        if days_until_expiry != -999:  # Only check if dates were parsed successfully
            if days_until_expiry < 0:
                result['issues'].append('CRITICAL: Certificate has expired')
            elif days_until_expiry <= 7:
                result['issues'].append('CRITICAL: Certificate expires in 7 days or less')
            elif days_until_expiry <= 30:
                result['issues'].append('HIGH: Certificate expires in 30 days or less')
            elif days_until_expiry <= 60:
                result['issues'].append('MEDIUM: Certificate expires in 60 days or less')
        else:
            result['issues'].append('WARNING: Could not verify certificate expiration dates')
        
        if is_weak_cipher:
            result['issues'].append(f'HIGH: Weak cipher suite detected: {cipher_name}')
        
        if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
            result['issues'].append(f'HIGH: Outdated TLS version: {version}')
        
        if cipher_strength < 128:
            result['issues'].append(f'HIGH: Weak encryption strength: {cipher_strength} bits')
        
        # Check if hostname matches certificate
        hostname_matches = self.verify_hostname(hostname, subject.get('commonName'), san_list)
        if not hostname_matches:
            result['issues'].append('MEDIUM: Hostname does not match certificate')
        
        return result
    
    def determine_severity(self, days_until_expiry, is_weak_cipher, tls_version):
        """
        Determine overall severity level
        
        Args:
            days_until_expiry: Days until certificate expires
            is_weak_cipher: Whether cipher is weak
            tls_version: TLS version string
            
        Returns:
            str: Severity level (CRITICAL, HIGH, MEDIUM, LOW, OK)
        """
        if days_until_expiry < 0:
            return 'CRITICAL'
        elif days_until_expiry <= 7:
            return 'CRITICAL'
        elif days_until_expiry <= 30 or is_weak_cipher or tls_version in ['TLSv1', 'TLSv1.1']:
            return 'HIGH'
        elif days_until_expiry <= 60:
            return 'MEDIUM'
        else:
            return 'OK'
    
    def verify_hostname(self, hostname, cn, san_list):
        """
        Verify if hostname matches certificate
        
        Args:
            hostname: Target hostname
            cn: Common Name from certificate
            san_list: List of Subject Alternative Names
            
        Returns:
            bool: True if hostname matches
        """
        # Check common name
        if cn and self.match_hostname(hostname, cn):
            return True
        
        # Check SANs
        for san in san_list:
            if self.match_hostname(hostname, san):
                return True
        
        return False
    
    def match_hostname(self, hostname, pattern):
        """
        Match hostname against certificate pattern (supports wildcards)
        
        Args:
            hostname: Target hostname
            pattern: Certificate hostname pattern
            
        Returns:
            bool: True if matches
        """
        if pattern == hostname:
            return True
        
        # Handle wildcard certificates (*.example.com)
        if pattern.startswith('*.'):
            pattern_parts = pattern.split('.')
            hostname_parts = hostname.split('.')
            
            if len(pattern_parts) == len(hostname_parts):
                # Compare all parts except the first (wildcard)
                return pattern_parts[1:] == hostname_parts[1:]
        
        return False
    
    def check_certificate(self, target):
        """
        Check certificate for a target
        
        Args:
            target: Target hostname or URL
        """
        hostname, port = self.parse_target(target)
        
        print(f"[*] Checking {hostname}:{port}...", end=' ')
        
        cert_data = self.get_certificate(hostname, port)
        
        if cert_data:
            result = self.parse_certificate(cert_data, hostname, port)
            self.results.append(result)
            
            # Print quick status
            if result['severity'] == 'CRITICAL':
                print("🔴 CRITICAL")
            elif result['severity'] == 'HIGH':
                print("🟠 HIGH")
            elif result['severity'] == 'MEDIUM':
                print("🟡 MEDIUM")
            else:
                print("✓ OK")
        else:
            print("❌ FAILED")
    
    def check_multiple(self, targets):
        """
        Check multiple targets
        
        Args:
            targets: List of target hostnames or URLs
        """
        print(f"\n{'='*70}")
        print(f"SSL/TLS Certificate Monitor - Starting Checks")
        print(f"{'='*70}")
        print(f"Targets: {len(targets)}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        for target in targets:
            self.check_certificate(target)
        
        print()
    
    def generate_report(self):
        """Generate comprehensive certificate report"""
        if not self.results:
            print("No certificate data to report.")
            return
        
        print(f"\n{'='*70}")
        print(f"SSL/TLS Certificate Report")
        print(f"{'='*70}\n")
        
        # Summary statistics
        total = len(self.results)
        expired = len([r for r in self.results if r['is_expired']])
        expiring_soon = len([r for r in self.results if 0 < r['days_until_expiry'] <= 30])
        weak_ciphers = len([r for r in self.results if r['is_weak_cipher']])
        critical = len([r for r in self.results if r['severity'] == 'CRITICAL'])
        high = len([r for r in self.results if r['severity'] == 'HIGH'])
        medium = len([r for r in self.results if r['severity'] == 'MEDIUM'])
        
        print(f"📊 SUMMARY")
        print(f"{'─'*70}")
        print(f"Total certificates checked: {total}")
        print(f"Expired: {expired}")
        print(f"Expiring within 30 days: {expiring_soon}")
        print(f"Weak ciphers detected: {weak_ciphers}")
        print(f"")
        print(f"Severity breakdown:")
        print(f"  🔴 CRITICAL: {critical}")
        print(f"  🟠 HIGH: {high}")
        print(f"  🟡 MEDIUM: {medium}")
        print(f"  ✓ OK: {total - critical - high - medium}\n")
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'OK': 4}
        sorted_results = sorted(self.results, key=lambda x: (severity_order[x['severity']], x['days_until_expiry']))
        
        # Detailed certificate information
        print(f"🔍 CERTIFICATE DETAILS")
        print(f"{'─'*70}\n")
        
        for result in sorted_results:
            severity_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🔵',
                'OK': '✓'
            }[result['severity']]
            
            print(f"{severity_icon} {result['hostname']}:{result['port']}")
            print(f"{'─'*70}")
            print(f"Common Name: {result['common_name']}")
            print(f"Organization: {result['organization']}")
            print(f"Issuer: {result['issuer_cn']}")
            
            # Expiration info with color coding
            if result['is_expired']:
                exp_status = "EXPIRED"
            elif result['days_until_expiry'] <= 7:
                exp_status = f"{result['days_until_expiry']} days (CRITICAL)"
            elif result['days_until_expiry'] <= 30:
                exp_status = f"{result['days_until_expiry']} days (HIGH)"
            elif result['days_until_expiry'] <= 60:
                exp_status = f"{result['days_until_expiry']} days (MEDIUM)"
            else:
                exp_status = f"{result['days_until_expiry']} days"
            
            print(f"Valid from: {result['not_before'][:10]}")
            print(f"Valid until: {result['not_after'][:10]}")
            print(f"Days until expiry: {exp_status}")
            
            print(f"\nTLS/Cipher Information:")
            print(f"  TLS Version: {result['tls_version']}")
            print(f"  Cipher Suite: {result['cipher_suite']}")
            print(f"  Cipher Strength: {result['cipher_strength']} bits")
            
            if result['san_list']:
                print(f"\nSubject Alternative Names:")
                for san in result['san_list'][:5]:  # Show first 5
                    print(f"  • {san}")
                if len(result['san_list']) > 5:
                    print(f"  ... and {len(result['san_list']) - 5} more")
            
            if result['issues']:
                print(f"\n⚠️  Issues Detected:")
                for issue in result['issues']:
                    print(f"  • {issue}")
            
            print()
        
        # Expiration timeline
        print(f"📅 EXPIRATION TIMELINE")
        print(f"{'─'*70}")
        
        # Group by expiration timeframe
        expired = [r for r in self.results if r['is_expired']]
        week = [r for r in self.results if 0 <= r['days_until_expiry'] <= 7]
        month = [r for r in self.results if 7 < r['days_until_expiry'] <= 30]
        quarter = [r for r in self.results if 30 < r['days_until_expiry'] <= 90]
        
        if expired:
            print(f"\n🔴 Already Expired ({len(expired)}):")
            for r in expired:
                print(f"  • {r['hostname']}:{r['port']} - Expired {abs(r['days_until_expiry'])} days ago")
        
        if week:
            print(f"\n🔴 Expiring This Week ({len(week)}):")
            for r in sorted(week, key=lambda x: x['days_until_expiry']):
                print(f"  • {r['hostname']}:{r['port']} - {r['days_until_expiry']} days")
        
        if month:
            print(f"\n🟠 Expiring This Month ({len(month)}):")
            for r in sorted(month, key=lambda x: x['days_until_expiry']):
                print(f"  • {r['hostname']}:{r['port']} - {r['days_until_expiry']} days")
        
        if quarter:
            print(f"\n🟡 Expiring This Quarter ({len(quarter)}):")
            for r in sorted(quarter, key=lambda x: x['days_until_expiry']):
                print(f"  • {r['hostname']}:{r['port']} - {r['days_until_expiry']} days")
        
        # Security recommendations
        print(f"\n🔒 SECURITY RECOMMENDATIONS")
        print(f"{'─'*70}")
        
        recommendations = []
        
        if expired:
            recommendations.append("• CRITICAL: Renew expired certificates immediately")
        
        if expiring_soon:
            recommendations.append("• HIGH: Renew certificates expiring within 30 days")
        
        if weak_ciphers:
            recommendations.append("• HIGH: Upgrade to stronger cipher suites (AES-GCM recommended)")
        
        tls10_11 = [r for r in self.results if r['tls_version'] in ['TLSv1', 'TLSv1.1']]
        if tls10_11:
            recommendations.append("• HIGH: Disable TLS 1.0/1.1, use TLS 1.2+ only")
        
        recommendations.append("• Implement certificate monitoring and automated renewal")
        recommendations.append("• Set up alerts for certificates expiring within 30 days")
        recommendations.append("• Consider using automated certificate management (Let's Encrypt, ACME)")
        recommendations.append("• Regularly audit certificate chain validity")
        
        for rec in recommendations:
            print(rec)
        
        print(f"\n{'='*70}\n")
    
    def export_json(self, filename):
        """
        Export certificate report to JSON
        
        Args:
            filename: Output filename
        """
        report = {
            'report_info': {
                'timestamp': datetime.now().isoformat(),
                'total_certificates': len(self.results)
            },
            'summary': {
                'expired': len([r for r in self.results if r['is_expired']]),
                'expiring_30_days': len([r for r in self.results if 0 < r['days_until_expiry'] <= 30]),
                'weak_ciphers': len([r for r in self.results if r['is_weak_cipher']]),
                'by_severity': {
                    'critical': len([r for r in self.results if r['severity'] == 'CRITICAL']),
                    'high': len([r for r in self.results if r['severity'] == 'HIGH']),
                    'medium': len([r for r in self.results if r['severity'] == 'MEDIUM']),
                    'ok': len([r for r in self.results if r['severity'] == 'OK'])
                }
            },
            'certificates': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report exported to: {filename}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='SSL/TLS Certificate Monitor - Track certificate health across infrastructure',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check single website
  python3 ssl_monitor.py example.com
  
  # Check multiple sites
  python3 ssl_monitor.py example.com google.com github.com
  
  # Check specific port
  python3 ssl_monitor.py mail.example.com:587
  
  # Check with URL
  python3 ssl_monitor.py https://example.com
  
  # Read targets from file and export
  python3 ssl_monitor.py -f domains.txt --export cert_report.json
  
  # Check with custom timeout
  python3 ssl_monitor.py example.com --timeout 5
        """
    )
    
    parser.add_argument('targets', nargs='*', help='Target hostnames or URLs')
    parser.add_argument('-f', '--file', help='Read targets from file (one per line)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Connection timeout in seconds (default: 10)')
    parser.add_argument('--export', help='Export report to JSON file')
    
    args = parser.parse_args()
    
    # Gather targets
    targets = args.targets or []
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                targets.extend(file_targets)
        except FileNotFoundError:
            print(f"Error: File {args.file} not found")
            sys.exit(1)
    
    if not targets:
        parser.print_help()
        sys.exit(1)
    
    # Initialize monitor
    monitor = CertificateMonitor(timeout=args.timeout)
    
    # Check certificates
    monitor.check_multiple(targets)
    
    # Generate report
    monitor.generate_report()
    
    # Export if requested
    if args.export:
        monitor.export_json(args.export)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Monitoring interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)