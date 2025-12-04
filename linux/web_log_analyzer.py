#!/usr/bin/env python3
"""
Web Server Log Analyzer
Detect attacks in Apache/Nginx logs - SQL injection, XSS, directory traversal, brute force
Perfect for healthcare web applications and critical infrastructure protection
"""

import re
import sys
import argparse
import json
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path

class WebLogAnalyzer:
    """Professional web server log analyzer for security monitoring"""
    
    # Attack pattern signatures
    SQL_INJECTION_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL meta-characters
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # Equals with SQL chars
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",  # 'or'
        r"((\%27)|(\'))union",  # union attacks
        r"exec(\s|\+)+(s|x)p\w+",  # stored procedures
        r"UNION.*SELECT",  # UNION SELECT
        r"SELECT.*FROM.*WHERE",  # SELECT statements
        r"INSERT.*INTO.*VALUES",  # INSERT statements
        r"DROP.*TABLE",  # DROP TABLE
        r"UPDATE.*SET",  # UPDATE statements
        r"DELETE.*FROM",  # DELETE statements
        r"1=1",  # Boolean attacks
        r"' or '1'='1",  # Classic SQLi
        r"admin'--",  # Comment attacks
    ]
    
    # XSS attack patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",  # Script tags
        r"javascript:",  # JavaScript protocol
        r"onerror\s*=",  # onerror event
        r"onload\s*=",  # onload event
        r"onclick\s*=",  # onclick event
        r"<iframe",  # iframe injection
        r"<img[^>]+src",  # Image XSS
        r"document\.cookie",  # Cookie stealing
        r"document\.write",  # Document manipulation
        r"eval\s*\(",  # eval() usage
        r"fromCharCode",  # Character encoding
        r"<svg.*onload",  # SVG XSS
        r"alert\s*\(",  # Alert XSS
    ]
    
    # Directory traversal patterns
    DIR_TRAVERSAL_PATTERNS = [
        r"\.\./",  # Parent directory
        r"\.\.\\",  # Windows path traversal
        r"/etc/passwd",  # Common Linux target
        r"/etc/shadow",  # Password hashes
        r"c:\\windows",  # Windows system dir
        r"boot\.ini",  # Windows boot config
        r"\.\.%2f",  # URL encoded traversal
        r"%2e%2e/",  # URL encoded dots
    ]
    
    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r";\s*(ls|cat|wget|curl|nc|bash|sh)",  # Shell commands
        r"\|\s*(ls|cat|wget|curl|nc|bash|sh)",  # Piped commands
        r"`.*`",  # Backtick execution
        r"\$\(.*\)",  # Command substitution
        r"&&",  # Command chaining
    ]
    
    # Common attack user agents
    MALICIOUS_AGENTS = [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'nessus', 'acunetix',
        'burp', 'metasploit', 'w3af', 'havij', 'dirbuster', 'hydra',
        'netsparker', 'openvas', 'wpscan', 'skipfish', 'arachni'
    ]
    
    # Common authentication endpoints
    AUTH_ENDPOINTS = [
        '/login', '/admin', '/wp-login', '/administrator',
        '/auth', '/signin', '/user/login', '/account/login',
        '/wp-admin', '/phpmyadmin', '/cpanel'
    ]
    
    def __init__(self, log_file):
        """
        Initialize web log analyzer
        
        Args:
            log_file: Path to web server log file
        """
        self.log_file = log_file
        self.entries = []
        self.attacks = defaultdict(list)
        
        # Compile regex patterns for performance
        self.sql_patterns = [re.compile(p, re.IGNORECASE) for p in self.SQL_INJECTION_PATTERNS]
        self.xss_patterns = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]
        self.dir_patterns = [re.compile(p, re.IGNORECASE) for p in self.DIR_TRAVERSAL_PATTERNS]
        self.cmd_patterns = [re.compile(p, re.IGNORECASE) for p in self.COMMAND_INJECTION_PATTERNS]
        
        # Log format patterns
        self.apache_pattern = re.compile(
            r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
            r'(?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
        )
        
        self.nginx_pattern = re.compile(
            r'(?P<ip>\S+) - \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
            r'(?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
        )
    
    def parse_line(self, line):
        """
        Parse a log line
        
        Args:
            line: Log line string
            
        Returns:
            dict: Parsed log entry or None
        """
        # Try Apache format
        match = self.apache_pattern.match(line)
        if not match:
            # Try Nginx format
            match = self.nginx_pattern.match(line)
        
        if match:
            return match.groupdict()
        
        return None
    
    def detect_sql_injection(self, entry):
        """Detect SQL injection attempts"""
        path = entry.get('path', '')
        
        for pattern in self.sql_patterns:
            if pattern.search(path):
                return True
        
        return False
    
    def detect_xss(self, entry):
        """Detect XSS attempts"""
        path = entry.get('path', '')
        
        for pattern in self.xss_patterns:
            if pattern.search(path):
                return True
        
        return False
    
    def detect_directory_traversal(self, entry):
        """Detect directory traversal attempts"""
        path = entry.get('path', '')
        
        for pattern in self.dir_patterns:
            if pattern.search(path):
                return True
        
        return False
    
    def detect_command_injection(self, entry):
        """Detect command injection attempts"""
        path = entry.get('path', '')
        
        for pattern in self.cmd_patterns:
            if pattern.search(path):
                return True
        
        return False
    
    def detect_scanner(self, entry):
        """Detect security scanner/bot activity"""
        agent = entry.get('agent', '').lower()
        
        for mal_agent in self.MALICIOUS_AGENTS:
            if mal_agent in agent:
                return True
        
        return False
    
    def is_auth_endpoint(self, path):
        """Check if path is an authentication endpoint"""
        return any(auth in path.lower() for auth in self.AUTH_ENDPOINTS)
    
    def analyze_log(self):
        """Analyze web server log for attacks"""
        print(f"\n{'='*70}")
        print(f"Web Server Log Analyzer - Starting Analysis")
        print(f"{'='*70}")
        print(f"Log file: {self.log_file}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        if not Path(self.log_file).exists():
            print(f"Error: Log file {self.log_file} not found")
            return
        
        # Parse log file
        print("[*] Parsing log file...")
        
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                entry = self.parse_line(line)
                
                if entry:
                    self.entries.append(entry)
                    
                    # Detect attacks
                    if self.detect_sql_injection(entry):
                        self.attacks['sql_injection'].append({
                            'line': line_num,
                            'ip': entry['ip'],
                            'time': entry['time'],
                            'path': entry['path'],
                            'status': entry['status']
                        })
                    
                    if self.detect_xss(entry):
                        self.attacks['xss'].append({
                            'line': line_num,
                            'ip': entry['ip'],
                            'time': entry['time'],
                            'path': entry['path'],
                            'status': entry['status']
                        })
                    
                    if self.detect_directory_traversal(entry):
                        self.attacks['directory_traversal'].append({
                            'line': line_num,
                            'ip': entry['ip'],
                            'time': entry['time'],
                            'path': entry['path'],
                            'status': entry['status']
                        })
                    
                    if self.detect_command_injection(entry):
                        self.attacks['command_injection'].append({
                            'line': line_num,
                            'ip': entry['ip'],
                            'time': entry['time'],
                            'path': entry['path'],
                            'status': entry['status']
                        })
                    
                    if self.detect_scanner(entry):
                        self.attacks['scanner_detected'].append({
                            'line': line_num,
                            'ip': entry['ip'],
                            'time': entry['time'],
                            'agent': entry['agent'],
                            'path': entry['path']
                        })
        
        print(f"[+] Parsed {len(self.entries)} log entries")
        print(f"[+] Total attacks detected: {sum(len(v) for v in self.attacks.values())}\n")
    
    def detect_brute_force(self):
        """Detect brute force login attempts"""
        print("[*] Analyzing for brute force attacks...")
        
        auth_attempts = defaultdict(list)
        
        for entry in self.entries:
            path = entry.get('path', '')
            status = entry.get('status', '')
            ip = entry.get('ip', '')
            
            if self.is_auth_endpoint(path):
                auth_attempts[ip].append({
                    'time': entry['time'],
                    'path': path,
                    'status': status,
                    'method': entry.get('method', '')
                })
        
        # Identify IPs with excessive failed attempts
        brute_force_ips = {}
        
        for ip, attempts in auth_attempts.items():
            failed = [a for a in attempts if a['status'] in ['401', '403', '404']]
            
            if len(failed) > 5:  # Threshold for brute force
                brute_force_ips[ip] = {
                    'total_attempts': len(attempts),
                    'failed_attempts': len(failed),
                    'endpoints': Counter([a['path'] for a in attempts])
                }
        
        if brute_force_ips:
            self.attacks['brute_force'] = [
                {
                    'ip': ip,
                    'total_attempts': data['total_attempts'],
                    'failed_attempts': data['failed_attempts'],
                    'endpoints': dict(data['endpoints'])
                }
                for ip, data in brute_force_ips.items()
            ]
        
        print(f"[+] Found {len(brute_force_ips)} IPs with brute force behavior\n")
    
    def generate_report(self):
        """Generate comprehensive attack report"""
        print(f"\n{'='*70}")
        print(f"Security Analysis Report")
        print(f"{'='*70}\n")
        
        # Summary statistics
        total_attacks = sum(len(v) for v in self.attacks.values())
        
        print(f"📊 SUMMARY")
        print(f"{'─'*70}")
        print(f"Total log entries: {len(self.entries)}")
        print(f"Total attacks detected: {total_attacks}")
        print(f"Unique attack types: {len([k for k, v in self.attacks.items() if v])}\n")
        
        # Attack breakdown
        print(f"🚨 ATTACK TYPES DETECTED")
        print(f"{'─'*70}")
        
        attack_names = {
            'sql_injection': 'SQL Injection',
            'xss': 'Cross-Site Scripting (XSS)',
            'directory_traversal': 'Directory Traversal',
            'command_injection': 'Command Injection',
            'scanner_detected': 'Security Scanner/Bot',
            'brute_force': 'Brute Force Login'
        }
        
        for attack_type, attacks in self.attacks.items():
            if attacks:
                print(f"  {attack_names.get(attack_type, attack_type)}: {len(attacks)} attempt(s)")
        
        if not total_attacks:
            print("  ✓ No attacks detected")
        
        print()
        
        # Detailed attack information
        if self.attacks:
            print(f"🔍 DETAILED ATTACK INFORMATION")
            print(f"{'─'*70}\n")
            
            # SQL Injection
            if self.attacks['sql_injection']:
                print(f"💉 SQL Injection Attempts ({len(self.attacks['sql_injection'])})")
                print(f"{'─'*70}")
                
                # Top attacking IPs
                ip_counter = Counter([a['ip'] for a in self.attacks['sql_injection']])
                print(f"Top attacking IPs:")
                for ip, count in ip_counter.most_common(5):
                    print(f"  {ip}: {count} attempts")
                
                print(f"\nRecent attempts:")
                for attack in self.attacks['sql_injection'][-5:]:
                    print(f"  [{attack['time']}] {attack['ip']}")
                    print(f"    Path: {attack['path'][:80]}")
                    print(f"    Status: {attack['status']}\n")
            
            # XSS
            if self.attacks['xss']:
                print(f"🎯 Cross-Site Scripting (XSS) Attempts ({len(self.attacks['xss'])})")
                print(f"{'─'*70}")
                
                ip_counter = Counter([a['ip'] for a in self.attacks['xss']])
                print(f"Top attacking IPs:")
                for ip, count in ip_counter.most_common(5):
                    print(f"  {ip}: {count} attempts")
                
                print(f"\nRecent attempts:")
                for attack in self.attacks['xss'][-5:]:
                    print(f"  [{attack['time']}] {attack['ip']}")
                    print(f"    Path: {attack['path'][:80]}")
                    print(f"    Status: {attack['status']}\n")
            
            # Directory Traversal
            if self.attacks['directory_traversal']:
                print(f"📁 Directory Traversal Attempts ({len(self.attacks['directory_traversal'])})")
                print(f"{'─'*70}")
                
                ip_counter = Counter([a['ip'] for a in self.attacks['directory_traversal']])
                print(f"Top attacking IPs:")
                for ip, count in ip_counter.most_common(5):
                    print(f"  {ip}: {count} attempts")
                
                print(f"\nRecent attempts:")
                for attack in self.attacks['directory_traversal'][-5:]:
                    print(f"  [{attack['time']}] {attack['ip']}")
                    print(f"    Path: {attack['path'][:80]}")
                    print(f"    Status: {attack['status']}\n")
            
            # Command Injection
            if self.attacks['command_injection']:
                print(f"💻 Command Injection Attempts ({len(self.attacks['command_injection'])})")
                print(f"{'─'*70}")
                
                ip_counter = Counter([a['ip'] for a in self.attacks['command_injection']])
                print(f"Top attacking IPs:")
                for ip, count in ip_counter.most_common(5):
                    print(f"  {ip}: {count} attempts")
                
                print(f"\nRecent attempts:")
                for attack in self.attacks['command_injection'][-5:]:
                    print(f"  [{attack['time']}] {attack['ip']}")
                    print(f"    Path: {attack['path'][:80]}")
                    print(f"    Status: {attack['status']}\n")
            
            # Scanner Detection
            if self.attacks['scanner_detected']:
                print(f"🤖 Security Scanner/Bot Activity ({len(self.attacks['scanner_detected'])})")
                print(f"{'─'*70}")
                
                ip_counter = Counter([a['ip'] for a in self.attacks['scanner_detected']])
                agent_counter = Counter([a['agent'] for a in self.attacks['scanner_detected']])
                
                print(f"Scanning IPs:")
                for ip, count in ip_counter.most_common(5):
                    print(f"  {ip}: {count} requests")
                
                print(f"\nDetected scanners:")
                for agent, count in agent_counter.most_common(5):
                    print(f"  {agent}: {count} requests\n")
            
            # Brute Force
            if self.attacks['brute_force']:
                print(f"🔐 Brute Force Login Attempts ({len(self.attacks['brute_force'])})")
                print(f"{'─'*70}")
                
                for attack in sorted(self.attacks['brute_force'], 
                                   key=lambda x: x['failed_attempts'], reverse=True):
                    print(f"  IP: {attack['ip']}")
                    print(f"    Total attempts: {attack['total_attempts']}")
                    print(f"    Failed attempts: {attack['failed_attempts']}")
                    print(f"    Targeted endpoints: {', '.join(attack['endpoints'].keys())}\n")
        
        # Top attacking IPs overall
        print(f"🎯 TOP ATTACKING IPs")
        print(f"{'─'*70}")
        
        all_ips = []
        for attacks in self.attacks.values():
            for attack in attacks:
                if 'ip' in attack:
                    all_ips.append(attack['ip'])
        
        if all_ips:
            ip_counter = Counter(all_ips)
            for ip, count in ip_counter.most_common(10):
                print(f"  {ip}: {count} total attacks")
        else:
            print("  No attacks detected")
        
        # Recommendations
        print(f"\n🔒 SECURITY RECOMMENDATIONS")
        print(f"{'─'*70}")
        
        recommendations = []
        
        if self.attacks['sql_injection']:
            recommendations.append("• CRITICAL: Implement parameterized queries to prevent SQL injection")
            recommendations.append("• Use a Web Application Firewall (WAF) to filter SQL injection attempts")
        
        if self.attacks['xss']:
            recommendations.append("• HIGH: Implement output encoding to prevent XSS attacks")
            recommendations.append("• Deploy Content Security Policy (CSP) headers")
        
        if self.attacks['directory_traversal']:
            recommendations.append("• HIGH: Validate and sanitize file path inputs")
            recommendations.append("• Implement proper access controls and chroot jails")
        
        if self.attacks['command_injection']:
            recommendations.append("• CRITICAL: Avoid executing system commands with user input")
            recommendations.append("• Use allowlists for permitted commands/parameters")
        
        if self.attacks['brute_force']:
            recommendations.append("• MEDIUM: Implement rate limiting on authentication endpoints")
            recommendations.append("• Deploy CAPTCHA on login forms")
            recommendations.append("• Enable account lockout after failed attempts")
        
        if self.attacks['scanner_detected']:
            recommendations.append("• MEDIUM: Block known scanner IPs at firewall level")
            recommendations.append("• Implement bot detection and mitigation")
        
        if all_ips:
            recommendations.append("• Consider implementing IP-based rate limiting")
            recommendations.append("• Monitor and block repeat offender IPs")
        
        if recommendations:
            for rec in recommendations:
                print(rec)
        else:
            print("✓ Continue monitoring for security threats")
        
        print(f"\n{'='*70}\n")
    
    def export_json(self, filename):
        """
        Export attack report to JSON
        
        Args:
            filename: Output filename
        """
        report = {
            'analysis_info': {
                'log_file': self.log_file,
                'timestamp': datetime.now().isoformat(),
                'total_entries': len(self.entries),
                'total_attacks': sum(len(v) for v in self.attacks.values())
            },
            'attacks': self.attacks,
            'summary': {
                attack_type: len(attacks)
                for attack_type, attacks in self.attacks.items()
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report exported to: {filename}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Web Server Log Analyzer - Detect attacks in Apache/Nginx logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze Apache access log
  python3 web_log_analyzer.py /var/log/apache2/access.log
  
  # Analyze Nginx access log
  python3 web_log_analyzer.py /var/log/nginx/access.log
  
  # Export results to JSON
  python3 web_log_analyzer.py access.log --export attack_report.json
  
  # Analyze custom log file
  python3 web_log_analyzer.py /path/to/access.log
        """
    )
    
    parser.add_argument('log_file', help='Path to web server access log')
    parser.add_argument('--export', help='Export attack report to JSON file')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = WebLogAnalyzer(args.log_file)
    
    # Analyze log
    analyzer.analyze_log()
    
    # Detect brute force
    analyzer.detect_brute_force()
    
    # Generate report
    analyzer.generate_report()
    
    # Export if requested
    if args.export:
        analyzer.export_json(args.export)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Analysis interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
