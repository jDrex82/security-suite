#!/usr/bin/env python3
"""
Cloud Security Posture Monitor v4.1
AWS/Azure/GCP Security Configuration

Author: John Drexler
License: MIT
Part of: Security Suite v4.1
"""

import os
import sys
import json
from datetime import datetime
from collections import defaultdict

class CloudSecurityMonitor:
    def __init__(self):
        self.alerts = []
        
    def check_s3_buckets(self):
        """Check S3 bucket security"""
        print("[*] Checking S3 bucket configurations...")
        
        # Simulate S3 security issues
        s3_issues = [
            {
                'bucket': 'patient-records-backup',
                'public_access': True,
                'encryption': False,
                'versioning': False,
                'severity': 'CRITICAL',
                'risk': 'Public PHI data exposure - massive HIPAA violation'
            },
            {
                'bucket': 'medical-images-archive',
                'public_access': False,
                'encryption': False,
                'logging': False,
                'severity': 'HIGH',
                'risk': 'Unencrypted PHI storage'
            }
        ]
        
        for issue in s3_issues:
            if issue.get('public_access'):
                self.alerts.append({
                    'timestamp': datetime.now().isoformat(),
                    'severity': issue['severity'],
                    'category': 'Public S3 Bucket',
                    'bucket_name': issue['bucket'],
                    'risk': issue['risk'],
                    'hipaa_violation': True,
                    'action': 'Block public access immediately'
                })
    
    def check_iam_policies(self):
        """Check IAM security"""
        print("\n[*] Checking IAM policies...")
        
        iam_issues = [
            {
                'user': 'admin-user',
                'mfa_enabled': False,
                'severity': 'HIGH',
                'permissions': ['*:*'],  # Full admin
                'risk': 'Admin account without MFA'
            },
            {
                'user': 'backup-service',
                'overprivileged': True,
                'permissions': ['s3:*', 'ec2:*', 'rds:*'],
                'required': ['s3:GetObject', 's3:PutObject'],
                'severity': 'MEDIUM'
            }
        ]
        
        for issue in iam_issues:
            if not issue.get('mfa_enabled', True):
                self.alerts.append({
                    'timestamp': datetime.now().isoformat(),
                    'severity': issue['severity'],
                    'category': 'IAM Security',
                    **issue
                })
    
    def check_security_groups(self):
        """Check security group rules"""
        print("\n[*] Checking security groups...")
        
        sg_issues = [
            {
                'security_group': 'sg-web-servers',
                'rule': '0.0.0.0/0:22',  # SSH open to world
                'severity': 'CRITICAL',
                'risk': 'SSH open to internet'
            },
            {
                'security_group': 'sg-database',
                'rule': '0.0.0.0/0:3306',  # MySQL open to world
                'severity': 'CRITICAL',
                'risk': 'Database exposed to internet'
            }
        ]
        
        for issue in sg_issues:
            self.alerts.append({
                'timestamp': datetime.now().isoformat(),
                'severity': issue['severity'],
                'category': 'Insecure Security Group',
                **issue
            })
    
    def generate_report(self):
        """Generate report"""
        print("\n" + "="*80)
        print("CLOUD SECURITY POSTURE MONITOR - REPORT")
        print("="*80)
        print(f"Total Alerts: {len(self.alerts)}")
        
        for alert in self.alerts:
            print(f"\n{alert['severity']}: {alert['category']}")
            for k, v in alert.items():
                if k not in ['timestamp', 'severity', 'category']:
                    print(f"  {k}: {v}")
        
        with open('cloud_security_report.json', 'w') as f:
            json.dump({'alerts': self.alerts}, f, indent=2, default=str)
        
        print(f"\n[+] Report exported")

def main():
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║              CLOUD SECURITY POSTURE MONITOR v4.1                             ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝\n")
    
    monitor = CloudSecurityMonitor()
    monitor.check_s3_buckets()
    monitor.check_iam_policies()
    monitor.check_security_groups()
    monitor.generate_report()

if __name__ == '__main__':
    main()
