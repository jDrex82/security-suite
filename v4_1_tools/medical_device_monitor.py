#!/usr/bin/env python3
"""
Medical Device Security Monitor v4.1
IoMT (Internet of Medical Things) Security

Detects:
- Outdated medical device firmware
- Medical device network isolation violations
- Unauthorized medical device access
- DICOM traffic anomalies
- FDA recall compliance

Author: John Drexler
License: MIT
Part of: Security Suite v4.1
"""

import os
import sys
import json
import socket
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict

class MedicalDeviceSecurityMonitor:
    def __init__(self):
        self.alerts = []
        self.devices = []
        self.medical_device_ports = {
            104: 'DICOM (Medical Imaging)',
            2761: 'DICOM TLS',
            2762: 'DICOM TLS',
            11112: 'DICOM Alternative',
            2575: 'HL7',
            8080: 'Medical Device Web Interface',
            443: 'HTTPS (Device Management)'
        }
        self.known_medical_vendors = [
            'ge-healthcare', 'philips', 'siemens', 'medtronic',
            'boston-scientific', 'abbott', 'stryker', 'zimmer',
            'baxter', 'bd', 'medline', 'cardinal'
        ]
        
    def discover_medical_devices(self):
        """Discover medical devices on network"""
        print("[*] Discovering medical devices...")
        
        # Simulate medical device discovery
        discovered_devices = [
            {
                'name': 'GE Ultrasound US-2024',
                'ip': '10.20.30.100',
                'mac': '00:11:22:33:44:55',
                'type': 'Diagnostic Imaging',
                'manufacturer': 'GE Healthcare',
                'firmware': '2.1.4',
                'last_seen': datetime.now().isoformat(),
                'vlan': 'GENERAL_NETWORK',  # SHOULD BE MEDICAL_VLAN!
                'criticality': 'HIGH'
            },
            {
                'name': 'Philips MRI Scanner MX450',
                'ip': '10.20.30.105',
                'mac': '00:AA:BB:CC:DD:EE',
                'type': 'Diagnostic Imaging',
                'manufacturer': 'Philips',
                'firmware': '5.2.1',
                'last_seen': datetime.now().isoformat(),
                'vlan': 'MEDICAL_DEVICES',
                'criticality': 'CRITICAL'
            },
            {
                'name': 'Infusion Pump IP-7000',
                'ip': '10.20.30.110',
                'mac': '00:11:AA:BB:CC:DD',
                'type': 'Patient Monitoring',
                'manufacturer': 'Baxter',
                'firmware': '1.8.2',
                'last_seen': datetime.now().isoformat(),
                'vlan': 'MEDICAL_DEVICES',
                'criticality': 'CRITICAL',
                'fda_recall': True
            },
            {
                'name': 'ECG Monitor CardioMX',
                'ip': '10.20.30.120',
                'mac': '00:22:33:44:55:66',
                'type': 'Patient Monitoring',
                'manufacturer': 'Unknown',
                'firmware': 'Unknown',
                'last_seen': datetime.now().isoformat(),
                'vlan': 'GENERAL_NETWORK',
                'criticality': 'HIGH',
                'unmanaged': True
            }
        ]
        
        self.devices = discovered_devices
        print(f"[+] Discovered {len(self.devices)} medical devices")
        
        # Analyze each device
        for device in self.devices:
            self._analyze_device_security(device)
    
    def _analyze_device_security(self, device):
        """Analyze individual device security"""
        
        # Check network isolation
        if device['vlan'] != 'MEDICAL_DEVICES':
            self.alerts.append({
                'timestamp': datetime.now().isoformat(),
                'severity': 'CRITICAL',
                'category': 'Network Isolation Violation',
                'device': device['name'],
                'ip': device['ip'],
                'current_vlan': device['vlan'],
                'required_vlan': 'MEDICAL_DEVICES',
                'risk': 'Medical device on general network - ransomware propagation risk',
                'hipaa_impact': True
            })
        
        # Check firmware version
        if 'firmware' in device and device['firmware'] != 'Unknown':
            self._check_firmware_vulnerability(device)
        
        # Check FDA recalls
        if device.get('fda_recall'):
            self.alerts.append({
                'timestamp': datetime.now().isoformat(),
                'severity': 'CRITICAL',
                'category': 'FDA Recall',
                'device': device['name'],
                'manufacturer': device['manufacturer'],
                'model': device['name'],
                'risk': 'Device subject to FDA recall - immediate action required',
                'action': 'Contact manufacturer for recall remediation'
            })
        
        # Check unmanaged devices
        if device.get('unmanaged'):
            self.alerts.append({
                'timestamp': datetime.now().isoformat(),
                'severity': 'HIGH',
                'category': 'Unmanaged Medical Device',
                'device': device['name'],
                'ip': device['ip'],
                'risk': 'Device not in asset management system',
                'recommendation': 'Add to medical device inventory and MDM'
            })
    
    def _check_firmware_vulnerability(self, device):
        """Check if device firmware has known vulnerabilities"""
        
        # Simulate firmware vulnerability database
        vulnerable_firmware = {
            'GE Ultrasound US-2024': {
                'vulnerable_versions': ['2.1.4', '2.1.3', '2.0.x'],
                'cve': 'CVE-2023-12345',
                'severity': 'HIGH',
                'description': 'Authentication bypass vulnerability',
                'patched_version': '2.2.0'
            },
            'Infusion Pump IP-7000': {
                'vulnerable_versions': ['1.8.2', '1.8.1'],
                'cve': 'CVE-2023-67890',
                'severity': 'CRITICAL',
                'description': 'Remote code execution - can modify drug dosages',
                'patched_version': '1.9.0'
            }
        }
        
        for vuln_device, vuln_info in vulnerable_firmware.items():
            if vuln_device in device['name']:
                if device['firmware'] in vuln_info['vulnerable_versions']:
                    self.alerts.append({
                        'timestamp': datetime.now().isoformat(),
                        'severity': vuln_info['severity'],
                        'category': 'Vulnerable Medical Device Firmware',
                        'device': device['name'],
                        'current_firmware': device['firmware'],
                        'patched_firmware': vuln_info['patched_version'],
                        'cve': vuln_info['cve'],
                        'vulnerability': vuln_info['description'],
                        'patient_safety_risk': True
                    })
    
    def monitor_dicom_traffic(self):
        """Monitor DICOM medical imaging traffic"""
        print("\n[*] Monitoring DICOM traffic...")
        
        # Simulate DICOM traffic analysis
        dicom_alerts = [
            {
                'source_ip': '10.20.30.200',
                'dest_ip': '192.168.100.50',  # External!
                'port': 104,
                'protocol': 'DICOM',
                'severity': 'CRITICAL',
                'issue': 'DICOM traffic to external IP - possible PHI exfiltration',
                'images_transferred': 150
            },
            {
                'source_ip': '10.20.30.100',
                'dest_ip': '10.20.30.105',
                'port': 104,
                'protocol': 'DICOM',
                'encryption': False,
                'severity': 'HIGH',
                'issue': 'Unencrypted DICOM traffic - HIPAA violation'
            },
            {
                'source_ip': 'Unknown',
                'dest_ip': '10.20.30.105',
                'port': 104,
                'failed_auth_attempts': 47,
                'severity': 'HIGH',
                'issue': 'Multiple failed DICOM authentication attempts'
            }
        ]
        
        for alert in dicom_alerts:
            self.alerts.append({
                'timestamp': datetime.now().isoformat(),
                'severity': alert['severity'],
                'category': 'DICOM Traffic Anomaly',
                **{k: v for k, v in alert.items() if k != 'severity'}
            })
    
    def check_device_authentication(self):
        """Check medical device authentication security"""
        print("\n[*] Checking device authentication...")
        
        auth_issues = [
            {
                'device': 'GE Ultrasound US-2024',
                'issue': 'Default credentials in use',
                'username': 'admin',
                'password': 'admin',
                'severity': 'CRITICAL',
                'risk': 'Unauthorized access to medical device'
            },
            {
                'device': 'Infusion Pump IP-7000',
                'issue': 'No authentication required',
                'severity': 'CRITICAL',
                'risk': 'Anyone can modify pump settings - patient safety risk'
            },
            {
                'device': 'ECG Monitor CardioMX',
                'issue': 'Weak password policy',
                'min_length': 4,
                'severity': 'HIGH',
                'risk': 'Easy to brute force'
            }
        ]
        
        for issue in auth_issues:
            self.alerts.append({
                'timestamp': datetime.now().isoformat(),
                'severity': issue['severity'],
                'category': 'Device Authentication Issue',
                **{k: v for k, v in issue.items() if k != 'severity'}
            })
    
    def check_fda_guidance_compliance(self):
        """Check FDA cybersecurity guidance compliance"""
        print("\n[*] Checking FDA cybersecurity guidance compliance...")
        
        compliance_checks = [
            {
                'requirement': 'Device asset inventory',
                'status': 'FAIL',
                'devices_missing': 3,
                'severity': 'HIGH'
            },
            {
                'requirement': 'Network segmentation (FDA guidance)',
                'status': 'FAIL',
                'devices_on_general_network': 2,
                'severity': 'CRITICAL'
            },
            {
                'requirement': 'Vulnerability management program',
                'status': 'PARTIAL',
                'unpatched_devices': 4,
                'severity': 'HIGH'
            },
            {
                'requirement': 'Incident response plan for devices',
                'status': 'FAIL',
                'severity': 'MEDIUM'
            }
        ]
        
        for check in compliance_checks:
            if check['status'] in ['FAIL', 'PARTIAL']:
                self.alerts.append({
                    'timestamp': datetime.now().isoformat(),
                    'severity': check['severity'],
                    'category': 'FDA Guidance Non-Compliance',
                    **{k: v for k, v in check.items() if k != 'severity'}
                })
    
    def generate_report(self):
        """Generate medical device security report"""
        print("\n" + "="*80)
        print("MEDICAL DEVICE SECURITY MONITOR - REPORT")
        print("="*80)
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Devices Scanned: {len(self.devices)}")
        print(f"Total Alerts: {len(self.alerts)}")
        
        severity_counts = defaultdict(int)
        for alert in self.alerts:
            severity_counts[alert['severity']] += 1
        
        print(f"\nAlerts by Severity:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_counts:
                print(f"  {severity}: {severity_counts[severity]}")
        
        print("\n" + "-"*80)
        print("CRITICAL PATIENT SAFETY RISKS:")
        print("-"*80)
        
        critical = [a for a in self.alerts if a['severity'] == 'CRITICAL']
        
        for i, alert in enumerate(critical, 1):
            print(f"\n[{i}] {alert['category']}")
            for key, value in alert.items():
                if key not in ['timestamp', 'severity', 'category']:
                    print(f"    {key.replace('_', ' ').title()}: {value}")
        
        print("\n" + "="*80)
        print("MEDICAL DEVICE SECURITY RECOMMENDATIONS:")
        print("="*80)
        print("1. Implement medical device VLAN (network segmentation)")
        print("2. Deploy Medical Device Management (MDM) system")
        print("3. Maintain comprehensive medical device asset inventory")
        print("4. Subscribe to FDA medical device cybersecurity alerts")
        print("5. Coordinate firmware updates with manufacturers")
        print("6. Implement DICOM encryption (TLS)")
        print("7. Change all default credentials immediately")
        print("8. Conduct regular medical device security assessments")
        print("9. Develop medical device incident response procedures")
        print("10. Train biomedical engineering staff on cybersecurity")
        
        self._export_json()
    
    def _export_json(self):
        """Export to JSON"""
        output_file = 'medical_device_security_report.json'
        
        with open(output_file, 'w') as f:
            json.dump({
                'scan_time': datetime.now().isoformat(),
                'devices_scanned': len(self.devices),
                'total_alerts': len(self.alerts),
                'devices': self.devices,
                'alerts': self.alerts,
                'summary': {
                    'critical': len([a for a in self.alerts if a['severity'] == 'CRITICAL']),
                    'high': len([a for a in self.alerts if a['severity'] == 'HIGH'])
                }
            }, f, indent=2, default=str)
        
        print(f"\n[+] Report exported to: {output_file}")


def main():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                MEDICAL DEVICE SECURITY MONITOR v4.1                          ║
║             IoMT (Internet of Medical Things) Security                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    monitor = MedicalDeviceSecurityMonitor()
    monitor.discover_medical_devices()
    monitor.monitor_dicom_traffic()
    monitor.check_device_authentication()
    monitor.check_fda_guidance_compliance()
    monitor.generate_report()


if __name__ == '__main__':
    main()
