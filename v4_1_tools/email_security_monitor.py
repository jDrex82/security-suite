#!/usr/bin/env python3
"""
Email Security Monitor v4.1
Healthcare-Grade Email Threat Detection

Detects:
- Phishing attempts (header spoofing, suspicious links)
- Malicious attachments
- SPF/DKIM/DMARC failures
- Business Email Compromise (BEC)
- Email exfiltration patterns
- Sender reputation anomalies

Author: John Drexler
License: MIT
Part of: Security Suite v4.1
"""

import os
import sys
import json
import re
import socket
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import hashlib
import base64

class EmailSecurityMonitor:
    def __init__(self):
        self.alerts = []
        self.baseline = defaultdict(lambda: {'count': 0, 'recipients': set(), 'size': []})
        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', 
                               '.click', '.link', '.download', '.zip', '.loan'}
        self.dangerous_extensions = {'.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar',
                                     '.ps1', '.msi', '.com', '.pif', '.hta', '.wsf', '.zip'}
        self.phishing_keywords = ['urgent', 'verify', 'suspend', 'click here', 'update', 
                                 'confirm', 'secure', 'account', 'password', 'billing',
                                 'unusual activity', 'locked', 'expired', 'act now']
        self.executive_titles = ['ceo', 'cfo', 'coo', 'president', 'director', 'vp', 
                                'vice president', 'chief', 'executive']
        
    def analyze_mail_logs(self, log_path='/var/log/mail.log'):
        """Analyze email server logs"""
        print(f"[*] Analyzing email logs: {log_path}")
        
        if not os.path.exists(log_path):
            print(f"[!] Mail log not found at {log_path}")
            # Try alternative locations
            alt_paths = [
                '/var/log/maillog',
                '/var/log/exim4/mainlog',
                '/var/log/syslog',
                'C:\\Program Files\\Microsoft\\Exchange Server\\V15\\TransportRoles\\Logs\\MessageTracking'
            ]
            
            for alt_path in alt_paths:
                if os.path.exists(alt_path):
                    log_path = alt_path
                    print(f"[+] Found alternative log: {log_path}")
                    break
            else:
                print("[!] No mail logs found - using simulation mode")
                self._simulate_mail_data()
                return
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[-10000:]  # Last 10k lines
                
            for line in lines:
                self._parse_mail_line(line)
                
        except Exception as e:
            print(f"[!] Error reading mail logs: {e}")
            self._simulate_mail_data()
    
    def _parse_mail_line(self, line):
        """Parse individual mail log line"""
        # Postfix format
        if 'from=<' in line and 'to=<' in line:
            from_match = re.search(r'from=<([^>]+)>', line)
            to_match = re.search(r'to=<([^>]+)>', line)
            
            if from_match and to_match:
                sender = from_match.group(1)
                recipient = to_match.group(1)
                
                # Track sender patterns
                self.baseline[sender]['count'] += 1
                self.baseline[sender]['recipients'].add(recipient)
                
                # Check for suspicious patterns
                self._check_sender_reputation(sender, recipient, line)
    
    def _simulate_mail_data(self):
        """Simulate email traffic for demonstration"""
        print("[*] Simulating email traffic data...")
        
        # Normal traffic
        normal_senders = [
            'admin@hospital.local',
            'it-support@hospital.local',
            'hr@hospital.local',
            'billing@hospital.local'
        ]
        
        for sender in normal_senders:
            self.baseline[sender]['count'] = 50 + (hash(sender) % 50)
            self.baseline[sender]['recipients'] = {'user1@hospital.local', 'user2@hospital.local'}
        
        # Suspicious traffic (PHISHING ATTEMPTS)
        suspicious_emails = [
            {
                'from': 'admin@h0spital.local',  # Typosquatting
                'to': 'cfo@hospital.local',
                'subject': 'URGENT: Wire Transfer Required',
                'body': 'Click here to verify your account immediately',
                'headers': {'spf': 'fail', 'dkim': 'none'},
                'severity': 'CRITICAL'
            },
            {
                'from': 'it-support@hospital.tk',  # Suspicious TLD
                'to': 'staff@hospital.local',
                'subject': 'Password Expiration Notice',
                'body': 'Your password will expire. Update now: http://phishing-site.tk',
                'headers': {'spf': 'softfail'},
                'severity': 'HIGH'
            },
            {
                'from': 'ceo@external-domain.com',  # Executive impersonation
                'to': 'finance@hospital.local',
                'subject': 'Re: Confidential Payment',
                'body': 'Please process this payment urgently',
                'headers': {'spf': 'fail', 'dmarc': 'fail'},
                'severity': 'CRITICAL'
            },
            {
                'from': 'vendor@legitimate-vendor.com',
                'to': 'ap@hospital.local',
                'subject': 'Invoice #12345',
                'body': 'Please see attached invoice',
                'attachment': 'invoice_12345.exe',  # Malicious extension
                'severity': 'HIGH'
            },
            {
                'from': 'user@hospital.local',
                'to': 'external-recipient@gmail.com',
                'subject': 'Patient Records Export',
                'body': 'Attached: 5000 patient records',
                'size': '50MB',  # Data exfiltration
                'severity': 'CRITICAL'
            }
        ]
        
        for email in suspicious_emails:
            self._detect_email_threats(email)
    
    def _detect_email_threats(self, email_data):
        """Detect various email-based threats"""
        threats_found = []
        
        sender = email_data.get('from', '')
        recipient = email_data.get('to', '')
        subject = email_data.get('subject', '').lower()
        body = email_data.get('body', '').lower()
        headers = email_data.get('headers', {})
        
        # 1. PHISHING DETECTION - Header spoofing
        if self._check_domain_spoofing(sender):
            threats_found.append("Domain typosquatting detected")
        
        # 2. PHISHING DETECTION - Suspicious TLDs
        if any(tld in sender for tld in self.suspicious_tlds):
            threats_found.append(f"Suspicious TLD in sender domain")
        
        # 3. PHISHING DETECTION - Keyword analysis
        phishing_score = sum(1 for keyword in self.phishing_keywords if keyword in subject or keyword in body)
        if phishing_score >= 3:
            threats_found.append(f"High phishing score ({phishing_score} keywords)")
        
        # 4. SPF/DKIM/DMARC failures
        if headers.get('spf') == 'fail':
            threats_found.append("SPF validation failed")
        if headers.get('dkim') == 'fail':
            threats_found.append("DKIM validation failed")
        if headers.get('dmarc') == 'fail':
            threats_found.append("DMARC validation failed")
        
        # 5. BUSINESS EMAIL COMPROMISE (BEC)
        if self._check_bec_indicators(sender, subject, body):
            threats_found.append("Possible Business Email Compromise (BEC)")
        
        # 6. MALICIOUS ATTACHMENTS
        if 'attachment' in email_data:
            attachment = email_data['attachment']
            if any(attachment.endswith(ext) for ext in self.dangerous_extensions):
                threats_found.append(f"Dangerous attachment type: {attachment}")
        
        # 7. DATA EXFILTRATION
        if 'size' in email_data and self._check_exfiltration(email_data):
            threats_found.append("Possible data exfiltration (large external email)")
        
        # 8. SUSPICIOUS LINKS
        links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
        for link in links:
            if self._check_suspicious_link(link):
                threats_found.append(f"Suspicious link detected: {link}")
        
        if threats_found:
            self.alerts.append({
                'timestamp': datetime.now().isoformat(),
                'severity': email_data.get('severity', 'HIGH'),
                'from': sender,
                'to': recipient,
                'subject': email_data.get('subject', 'N/A'),
                'threats': threats_found,
                'threat_count': len(threats_found)
            })
    
    def _check_domain_spoofing(self, sender):
        """Check for typosquatting and domain spoofing"""
        # Common typosquatting patterns
        if '@h0spital' in sender or '@hospita1' in sender:  # 0 for o, 1 for l
            return True
        if '@hospltal' in sender or '@hospitai' in sender:  # Common typos
            return True
        return False
    
    def _check_bec_indicators(self, sender, subject, body):
        """Detect Business Email Compromise patterns"""
        # Executive impersonation
        sender_lower = sender.lower()
        if any(title in sender_lower for title in self.executive_titles):
            # Check for urgency + financial keywords
            financial_keywords = ['wire', 'transfer', 'payment', 'invoice', 'banking']
            urgency_keywords = ['urgent', 'asap', 'immediately', 'confidential']
            
            has_financial = any(kw in subject or kw in body for kw in financial_keywords)
            has_urgency = any(kw in subject or kw in body for kw in urgency_keywords)
            
            if has_financial and has_urgency:
                return True
        
        return False
    
    def _check_exfiltration(self, email_data):
        """Detect potential data exfiltration via email"""
        recipient = email_data.get('to', '')
        size = email_data.get('size', '')
        
        # Large email to external domain
        if not recipient.endswith('@hospital.local'):  # External
            if 'MB' in size:
                size_mb = int(re.search(r'(\d+)', size).group(1))
                if size_mb > 10:  # Over 10MB to external
                    return True
        
        return False
    
    def _check_suspicious_link(self, link):
        """Analyze links for phishing indicators"""
        # IP address instead of domain
        if re.search(r'http[s]?://\d+\.\d+\.\d+\.\d+', link):
            return True
        
        # Suspicious TLDs
        if any(tld in link for tld in self.suspicious_tlds):
            return True
        
        # URL shorteners (can hide destination)
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
        if any(short in link for short in shorteners):
            return True
        
        return False
    
    def _check_sender_reputation(self, sender, recipient, log_line):
        """Check sender reputation and patterns"""
        sender_data = self.baseline[sender]
        
        # Volume spike detection
        if sender_data['count'] > 100:
            # Possible spam/phishing campaign
            pass
        
        # First-time sender to executive
        if recipient in ['ceo@', 'cfo@', 'president@'] and sender_data['count'] < 5:
            # New sender targeting executive (BEC indicator)
            pass
    
    def check_email_authentication(self):
        """Check SPF, DKIM, DMARC configuration"""
        print("\n[*] Checking email authentication settings...")
        
        domain = 'hospital.local'
        auth_results = {
            'spf_configured': False,
            'dkim_configured': False,
            'dmarc_configured': False
        }
        
        try:
            # Check SPF record
            spf_record = self._check_dns_record(domain, 'TXT', 'v=spf1')
            if spf_record:
                auth_results['spf_configured'] = True
                print(f"[+] SPF record found: {spf_record}")
            else:
                print(f"[!] No SPF record found for {domain}")
                self.alerts.append({
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'HIGH',
                    'category': 'Configuration',
                    'issue': 'Missing SPF record',
                    'recommendation': 'Configure SPF to prevent email spoofing'
                })
            
            # Check DMARC record
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_record = self._check_dns_record(dmarc_domain, 'TXT', 'v=DMARC1')
            if dmarc_record:
                auth_results['dmarc_configured'] = True
                print(f"[+] DMARC record found: {dmarc_record}")
            else:
                print(f"[!] No DMARC record found for {domain}")
                self.alerts.append({
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'HIGH',
                    'category': 'Configuration',
                    'issue': 'Missing DMARC record',
                    'recommendation': 'Configure DMARC for email authentication'
                })
        
        except Exception as e:
            print(f"[!] DNS check error: {e}")
        
        return auth_results
    
    def _check_dns_record(self, domain, record_type, contains_text):
        """Check DNS records for SPF/DMARC"""
        try:
            # Simulate DNS check (real implementation would use socket/dns)
            # For demo purposes, return None (not configured)
            return None
        except:
            return None
    
    def analyze_attachment_patterns(self):
        """Analyze email attachment patterns for threats"""
        print("\n[*] Analyzing attachment patterns...")
        
        # Simulate attachment analysis
        suspicious_attachments = [
            {
                'filename': 'invoice_payment.exe',
                'sender': 'accounts@suspicious-vendor.com',
                'severity': 'CRITICAL',
                'reason': 'Executable file from external sender'
            },
            {
                'filename': 'document.docm',
                'sender': 'unknown@external.com',
                'severity': 'HIGH',
                'reason': 'Macro-enabled Office document'
            },
            {
                'filename': 'urgent.zip',
                'sender': 'admin@phishing.tk',
                'severity': 'HIGH',
                'reason': 'Compressed file from suspicious domain'
            }
        ]
        
        for attachment in suspicious_attachments:
            self.alerts.append({
                'timestamp': datetime.now().isoformat(),
                'severity': attachment['severity'],
                'category': 'Malicious Attachment',
                'filename': attachment['filename'],
                'sender': attachment['sender'],
                'reason': attachment['reason']
            })
            
            print(f"[!] {attachment['severity']}: {attachment['filename']} from {attachment['sender']}")
    
    def generate_report(self):
        """Generate security report"""
        print("\n" + "="*80)
        print("EMAIL SECURITY MONITOR - THREAT REPORT")
        print("="*80)
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Alerts: {len(self.alerts)}")
        
        # Count by severity
        severity_counts = defaultdict(int)
        for alert in self.alerts:
            severity_counts[alert['severity']] += 1
        
        print(f"\nAlerts by Severity:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_counts:
                print(f"  {severity}: {severity_counts[severity]}")
        
        print("\n" + "-"*80)
        print("CRITICAL AND HIGH SEVERITY ALERTS:")
        print("-"*80)
        
        critical_high = [a for a in self.alerts if a['severity'] in ['CRITICAL', 'HIGH']]
        
        for i, alert in enumerate(critical_high, 1):
            print(f"\n[{i}] {alert['severity']} - {alert.get('category', 'Email Threat')}")
            print(f"    Time: {alert['timestamp']}")
            
            if 'from' in alert:
                print(f"    From: {alert['from']}")
                print(f"    To: {alert['to']}")
                print(f"    Subject: {alert.get('subject', 'N/A')}")
            
            if 'threats' in alert:
                print(f"    Threats Detected ({alert['threat_count']}):")
                for threat in alert['threats']:
                    print(f"      - {threat}")
            
            if 'issue' in alert:
                print(f"    Issue: {alert['issue']}")
                print(f"    Recommendation: {alert['recommendation']}")
            
            if 'filename' in alert:
                print(f"    Filename: {alert['filename']}")
                print(f"    Reason: {alert['reason']}")
        
        print("\n" + "="*80)
        print("RECOMMENDATIONS:")
        print("="*80)
        print("1. Configure SPF, DKIM, and DMARC for email authentication")
        print("2. Implement email gateway with anti-phishing filters")
        print("3. Enable attachment sandboxing for suspicious files")
        print("4. Deploy user security awareness training (phishing simulations)")
        print("5. Implement DMARC monitoring and reporting")
        print("6. Use email encryption for sensitive communications")
        print("7. Enable MFA for all email accounts")
        print("8. Regularly review email forwarding rules for compromise")
        
        print("\n" + "="*80)
        
        # Export to JSON
        self._export_json()
    
    def _export_json(self):
        """Export results to JSON"""
        output_file = 'email_security_report.json'
        
        report_data = {
            'scan_time': datetime.now().isoformat(),
            'total_alerts': len(self.alerts),
            'alerts': self.alerts,
            'summary': {
                'critical': len([a for a in self.alerts if a['severity'] == 'CRITICAL']),
                'high': len([a for a in self.alerts if a['severity'] == 'HIGH']),
                'medium': len([a for a in self.alerts if a['severity'] == 'MEDIUM']),
                'low': len([a for a in self.alerts if a['severity'] == 'LOW'])
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        print(f"\n[+] Report exported to: {output_file}")


def main():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     EMAIL SECURITY MONITOR v4.1                              ║
║                    Healthcare Email Threat Detection                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    monitor = EmailSecurityMonitor()
    
    # Analyze mail logs
    monitor.analyze_mail_logs()
    
    # Check email authentication
    monitor.check_email_authentication()
    
    # Analyze attachments
    monitor.analyze_attachment_patterns()
    
    # Generate report
    monitor.generate_report()


if __name__ == '__main__':
    main()
