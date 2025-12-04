#!/usr/bin/env python3
"""
VPN/Remote Access Security Monitor v4.1
Remote Work Security Monitoring

Author: John Drexler
License: MIT
Part of: Security Suite v4.1
"""

import os
import json
from datetime import datetime
from collections import defaultdict

class VPNSecurityMonitor:
    def __init__(self):
        self.alerts = []
        
    def check_vpn_connections(self):
        """Monitor VPN connections"""
        print("[*] Monitoring VPN connections...")
        
        # Simulate VPN alerts
        vpn_alerts = [
            {
                'user': 'dr.smith@hospital.local',
                'ip': '185.220.101.50',  # Tor exit node
                'location': 'Russia',
                'severity': 'CRITICAL',
                'risk': 'VPN connection from Tor/suspicious location'
            },
            {
                'user': 'nurse.jones@hospital.local',
                'connections': 5,
                'locations': ['New York', 'London', 'Tokyo'],
                'timeframe': '30 minutes',
                'severity': 'CRITICAL',
                'risk': 'Impossible travel - account compromise'
            },
            {
                'user': 'admin@hospital.local',
                'rdp_enabled': True,
                'mfa': False,
                'severity': 'HIGH',
                'risk': 'Admin RDP without MFA'
            }
        ]
        
        for alert in vpn_alerts:
            self.alerts.append({
                'timestamp': datetime.now().isoformat(),
                'severity': alert['severity'],
                'category': 'VPN/Remote Access',
                **{k: v for k, v in alert.items() if k != 'severity'}
            })
    
    def generate_report(self):
        """Generate report"""
        print("\n" + "="*80)
        print("VPN/REMOTE ACCESS SECURITY MONITOR - REPORT")
        print("="*80)
        print(f"Total Alerts: {len(self.alerts)}")
        
        for alert in self.alerts:
            print(f"\n{alert['severity']}: {alert['category']}")
            for k, v in alert.items():
                if k not in ['timestamp', 'severity', 'category']:
                    print(f"  {k}: {v}")
        
        with open('vpn_security_report.json', 'w') as f:
            json.dump({'alerts': self.alerts}, f, indent=2, default=str)
        
        print(f"\n[+] Report exported")

def main():
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║             VPN/REMOTE ACCESS SECURITY MONITOR v4.1                          ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝\n")
    
    monitor = VPNSecurityMonitor()
    monitor.check_vpn_connections()
    monitor.generate_report()

if __name__ == '__main__':
    main()
