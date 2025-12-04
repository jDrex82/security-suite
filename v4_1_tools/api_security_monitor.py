#!/usr/bin/env python3
"""
API Security Monitor v4.1
Modern Application Security

Author: John Drexler
License: MIT
Part of: Security Suite v4.1
"""

import os
import json
from datetime import datetime
from collections import defaultdict

class APISecurityMonitor:
    def __init__(self):
        self.alerts = []
        
    def monitor_api_traffic(self):
        """Monitor API security"""
        print("[*] Monitoring API traffic...")
        
        # Simulate API security issues
        api_alerts = [
            {
                'api': '/api/v1/patients',
                'method': 'GET',
                'ip': '203.0.113.50',
                'requests_per_minute': 1000,
                'severity': 'HIGH',
                'issue': 'Rate limit exceeded - possible scraping'
            },
            {
                'api': '/api/v1/admin',
                'auth': 'None',
                'severity': 'CRITICAL',
                'issue': 'Admin API endpoint without authentication'
            },
            {
                'api': '/api/v1/records',
                'sql_injection_attempt': True,
                'payload': "' OR '1'='1",
                'severity': 'CRITICAL',
                'issue': 'SQL injection attempt detected'
            }
        ]
        
        for alert in api_alerts:
            self.alerts.append({
                'timestamp': datetime.now().isoformat(),
                'severity': alert['severity'],
                'category': 'API Security',
                **{k: v for k, v in alert.items() if k != 'severity'}
            })
    
    def generate_report(self):
        """Generate report"""
        print("\n" + "="*80)
        print("API SECURITY MONITOR - REPORT")
        print("="*80)
        print(f"Total Alerts: {len(self.alerts)}")
        
        for alert in self.alerts:
            print(f"\n{alert['severity']}: {alert['category']}")
            for k, v in alert.items():
                if k not in ['timestamp', 'severity', 'category']:
                    print(f"  {k}: {v}")
        
        with open('api_security_report.json', 'w') as f:
            json.dump({'alerts': self.alerts}, f, indent=2, default=str)
        
        print(f"\n[+] Report exported")

def main():
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                    API SECURITY MONITOR v4.1                                 ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝\n")
    
    monitor = APISecurityMonitor()
    monitor.monitor_api_traffic()
    monitor.generate_report()

if __name__ == '__main__':
    main()
