#!/usr/bin/env python3
"""
USB Device Monitor (USB)
Monitors USB device connections, detects unauthorized devices, and prevents data exfiltration
Critical for preventing USB-based attacks and data theft - HIPAA/PCI-DSS requirement
"""

import os
import sys
import re
import json
import time
import argparse
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path

class USBDeviceMonitor:
    def __init__(self, baseline_file='usb_baseline.json'):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.alerts = defaultdict(list)
        self.severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        # USB device tracking
        self.devices = {
            'current': {},
            'historical': [],
            'whitelisted': set(),
            'blacklisted': set()
        }
        
        # Thresholds
        self.thresholds = {
            'max_file_copy_mb': 500,  # MB
            'max_devices_per_hour': 5,
            'suspicious_mount_count': 10,
            'large_transfer_mb': 100
        }
        
        # Log paths
        self.log_paths = {
            'syslog': '/var/log/syslog',
            'messages': '/var/log/messages',
            'kern': '/var/log/kern.log',
            'dmesg': None  # Will use dmesg command
        }
        
        # Suspicious device types
        self.suspicious_devices = [
            'Rubber Ducky',
            'Bash Bunny',
            'USB Armory',
            'LAN Turtle',
            'Teensy',
            'BadUSB'
        ]
        
    def get_current_usb_devices(self):
        """Get currently connected USB devices"""
        devices = {}
        
        try:
            # Use lsusb to get USB devices
            result = subprocess.run(
                ['lsusb'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        # Parse lsusb output: Bus 001 Device 002: ID 1234:5678 Vendor Device
                        match = re.match(r'Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+([0-9a-f:]+)\s+(.*)', line)
                        if match:
                            bus, device, device_id, description = match.groups()
                            
                            devices[f"{bus}:{device}"] = {
                                'bus': bus,
                                'device': device,
                                'id': device_id,
                                'description': description,
                                'timestamp': datetime.now().isoformat()
                            }
        
        except FileNotFoundError:
            # lsusb not available, try alternative method
            print("[!] lsusb not found, using /sys/bus/usb/devices")
            
            try:
                usb_path = Path('/sys/bus/usb/devices')
                if usb_path.exists():
                    for device_path in usb_path.iterdir():
                        if device_path.is_dir():
                            try:
                                # Read idVendor and idProduct
                                vendor_file = device_path / 'idVendor'
                                product_file = device_path / 'idProduct'
                                
                                if vendor_file.exists() and product_file.exists():
                                    vendor = vendor_file.read_text().strip()
                                    product = product_file.read_text().strip()
                                    
                                    device_id = f"{vendor}:{product}"
                                    devices[str(device_path.name)] = {
                                        'id': device_id,
                                        'path': str(device_path),
                                        'timestamp': datetime.now().isoformat()
                                    }
                            except Exception:
                                continue
            
            except Exception as e:
                print(f"Warning: Error reading /sys/bus/usb/devices: {e}")
        
        except Exception as e:
            print(f"Warning: Error getting USB devices: {e}")
        
        return devices
    
    def parse_usb_logs(self, log_file, lines_limit=5000):
        """Parse system logs for USB events"""
        events = []
        
        if not os.path.exists(log_file):
            return events
        
        usb_patterns = [
            (r'usb.*new.*device', 'device_connected'),
            (r'usb.*disconnect', 'device_disconnected'),
            (r'usb.*Mass Storage', 'storage_device'),
            (r'usb.*mounted', 'device_mounted'),
            (r'usb.*unmounted', 'device_unmounted'),
        ]
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                # Only read last N lines for performance
                lines = lines[-lines_limit:] if len(lines) > lines_limit else lines
                
                for line in lines:
                    for pattern, event_type in usb_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            timestamp = self._extract_timestamp(line)
                            
                            # Extract device info if available
                            device_match = re.search(r'usb (\d+-\d+)', line)
                            device_id = device_match.group(1) if device_match else 'unknown'
                            
                            events.append({
                                'type': event_type,
                                'device': device_id,
                                'timestamp': timestamp,
                                'raw_log': line.strip()
                            })
                            break
        
        except Exception as e:
            print(f"Warning: Error parsing {log_file}: {e}")
        
        return events
    
    def _extract_timestamp(self, log_line):
        """Extract timestamp from log line"""
        match = re.match(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', log_line)
        if match:
            timestamp_str = match.group(1)
            try:
                year = datetime.now().year
                dt = datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                return dt.isoformat()
            except:
                pass
        
        return datetime.now().isoformat()
    
    def check_dmesg_events(self):
        """Check dmesg for recent USB events"""
        events = []
        
        try:
            result = subprocess.run(
                ['dmesg'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'usb' in line.lower():
                        if any(keyword in line.lower() for keyword in ['new', 'disconnect', 'storage']):
                            events.append({
                                'type': 'dmesg_event',
                                'timestamp': datetime.now().isoformat(),
                                'message': line.strip()
                            })
        
        except Exception as e:
            print(f"Warning: Error reading dmesg: {e}")
        
        return events
    
    def detect_suspicious_devices(self):
        """Detect known malicious USB devices"""
        print("[*] Checking for suspicious USB devices...")
        
        current_devices = self.get_current_usb_devices()
        
        for device_key, device_info in current_devices.items():
            description = device_info.get('description', '').lower()
            device_id = device_info.get('id', '')
            
            # Check against known bad devices
            for suspicious in self.suspicious_devices:
                if suspicious.lower() in description:
                    self.alerts['suspicious_device'].append({
                        'severity': 'CRITICAL',
                        'description': 'Known malicious USB device detected',
                        'device': device_key,
                        'device_id': device_id,
                        'type': suspicious,
                        'full_description': device_info.get('description', 'unknown')
                    })
                    self.severity_counts['CRITICAL'] += 1
        
        print(f"    • Current devices: {len(current_devices)}")
    
    def detect_unauthorized_devices(self):
        """Detect devices not in whitelist"""
        if not self.baseline or 'whitelisted_devices' not in self.baseline:
            return
        
        print("[*] Checking for unauthorized devices...")
        
        whitelist = set(self.baseline['whitelisted_devices'])
        current_devices = self.get_current_usb_devices()
        
        for device_key, device_info in current_devices.items():
            device_id = device_info.get('id', '')
            
            if device_id not in whitelist:
                self.alerts['unauthorized_device'].append({
                    'severity': 'HIGH',
                    'description': 'Unauthorized USB device connected',
                    'device': device_key,
                    'device_id': device_id,
                    'description_text': device_info.get('description', 'unknown')
                })
                self.severity_counts['HIGH'] += 1
    
    def detect_mass_file_operations(self):
        """Detect large file transfers to USB"""
        print("[*] Checking for mass file operations...")
        
        # Check mounted USB devices
        try:
            result = subprocess.run(
                ['df', '-h'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                usb_mounts = []
                for line in result.stdout.split('\n')[1:]:
                    if '/media/' in line or '/mnt/' in line:
                        parts = line.split()
                        if len(parts) >= 6:
                            mount_point = parts[5]
                            used = parts[2]
                            usb_mounts.append({
                                'mount_point': mount_point,
                                'used_space': used
                            })
                
                if usb_mounts:
                    print(f"    • Found {len(usb_mounts)} mounted USB devices")
                    
                    for mount in usb_mounts:
                        # Try to count files
                        try:
                            file_count = 0
                            for root, dirs, files in os.walk(mount['mount_point']):
                                file_count += len(files)
                                if file_count > 10000:  # Limit for performance
                                    break
                            
                            if file_count > 5000:
                                self.alerts['mass_file_copy'].append({
                                    'severity': 'HIGH',
                                    'description': 'Large number of files on USB device',
                                    'mount_point': mount['mount_point'],
                                    'file_count': file_count,
                                    'used_space': mount['used_space']
                                })
                                self.severity_counts['HIGH'] += 1
                        
                        except Exception:
                            pass
        
        except Exception as e:
            print(f"Warning: Error checking file operations: {e}")
    
    def analyze_connection_frequency(self, events):
        """Analyze USB connection frequency"""
        print("[*] Analyzing connection frequency...")
        
        # Count device connections per hour
        connections_per_hour = defaultdict(int)
        
        for event in events:
            if event['type'] in ['device_connected', 'device_mounted']:
                try:
                    dt = datetime.fromisoformat(event['timestamp'])
                    hour_key = dt.strftime('%Y-%m-%d %H:00')
                    connections_per_hour[hour_key] += 1
                except:
                    pass
        
        # Check for suspicious connection rate
        for hour, count in connections_per_hour.items():
            if count > self.thresholds['max_devices_per_hour']:
                self.alerts['high_connection_rate'].append({
                    'severity': 'MEDIUM',
                    'description': 'High USB connection rate detected',
                    'hour': hour,
                    'connections': count,
                    'threshold': self.thresholds['max_devices_per_hour']
                })
                self.severity_counts['MEDIUM'] += 1
    
    def scan(self):
        """Scan for USB device threats"""
        print(f"\n{'='*70}")
        print("USB DEVICE MONITOR - Scan Started")
        print(f"{'='*70}\n")
        
        # Get current devices
        self.devices['current'] = self.get_current_usb_devices()
        
        # Check for suspicious devices
        self.detect_suspicious_devices()
        
        # Check against whitelist
        self.detect_unauthorized_devices()
        
        # Check for mass file operations
        self.detect_mass_file_operations()
        
        # Parse logs for events
        all_events = []
        print("\n[*] Parsing system logs for USB events...")
        
        for log_name, log_path in self.log_paths.items():
            if log_path and os.path.exists(log_path):
                print(f"[*] Parsing {log_name}: {log_path}")
                events = self.parse_usb_logs(log_path)
                all_events.extend(events)
                print(f"    • Found {len(events)} USB events")
        
        # Check dmesg
        print("[*] Checking dmesg for USB events...")
        dmesg_events = self.check_dmesg_events()
        all_events.extend(dmesg_events)
        print(f"    • Found {len(dmesg_events)} dmesg events")
        
        # Analyze connection frequency
        if all_events:
            self.analyze_connection_frequency(all_events)
        
        return self.alerts
    
    def create_baseline(self):
        """Create baseline of authorized USB devices"""
        print(f"\n{'='*70}")
        print("USB DEVICE MONITOR - Creating Baseline")
        print(f"{'='*70}\n")
        
        current_devices = self.get_current_usb_devices()
        
        baseline_data = {
            'timestamp': datetime.now().isoformat(),
            'whitelisted_devices': [dev['id'] for dev in current_devices.values()],
            'device_descriptions': {
                dev['id']: dev.get('description', 'unknown')
                for dev in current_devices.values()
            }
        }
        
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)
        
        print(f"[+] Baseline created: {self.baseline_file}")
        print(f"[+] Whitelisted {len(baseline_data['whitelisted_devices'])} devices")
        
        if baseline_data['whitelisted_devices']:
            print("\nWhitelisted Devices:")
            for device_id, description in baseline_data['device_descriptions'].items():
                print(f"  • {device_id}: {description}")
        
        return True
    
    def load_baseline(self):
        """Load baseline data"""
        if os.path.exists(self.baseline_file):
            try:
                with open(self.baseline_file, 'r') as f:
                    self.baseline = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load baseline: {e}")
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{'='*70}")
        print("SCAN SUMMARY")
        print(f"{'='*70}\n")
        
        total_alerts = sum(self.severity_counts.values())
        
        print(f"Total Alerts: {total_alerts}")
        print(f"  CRITICAL: {self.severity_counts['CRITICAL']}")
        print(f"  HIGH:     {self.severity_counts['HIGH']}")
        print(f"  MEDIUM:   {self.severity_counts['MEDIUM']}")
        print(f"  LOW:      {self.severity_counts['LOW']}")
        
        if self.devices['current']:
            print(f"\nCurrent USB Devices: {len(self.devices['current'])}")
            for device_key, device_info in self.devices['current'].items():
                description = device_info.get('description', device_info.get('id', 'unknown'))
                print(f"  • {device_key}: {description}")
        
        if total_alerts == 0:
            print("\n✓ No suspicious USB activity detected")
        else:
            print(f"\n⚠ {total_alerts} USB security issues detected")
            
            if self.alerts:
                print("\nAlert Breakdown:")
                for alert_type, alerts in self.alerts.items():
                    if alerts:
                        print(f"  • {alert_type.replace('_', ' ').title()}: {len(alerts)}")
    
    def export_results(self, output_file):
        """Export results to JSON"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_alerts': sum(self.severity_counts.values()),
                'severity_counts': self.severity_counts,
                'current_devices': len(self.devices['current'])
            },
            'devices': {
                'current': self.devices['current'],
            },
            'alerts': dict(self.alerts)
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Results exported to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='USB Device Monitor - Prevent USB-based attacks and data exfiltration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create baseline (whitelist current devices)
  python3 usb_device_monitor.py --baseline
  
  # Run scan
  python3 usb_device_monitor.py --scan
  
  # Run scan and export results
  python3 usb_device_monitor.py --scan --export usb_results.json
  
  # Continuous monitoring (24 hours, check every 5 minutes)
  python3 usb_device_monitor.py --monitor --duration 86400 --interval 300
        """
    )
    
    parser.add_argument('--baseline', action='store_true',
                       help='Create baseline of authorized USB devices')
    parser.add_argument('--scan', action='store_true',
                       help='Scan once for USB threats')
    parser.add_argument('--monitor', action='store_true',
                       help='Continuous monitoring mode')
    parser.add_argument('--duration', type=int, default=3600,
                       help='Monitoring duration in seconds (default: 3600)')
    parser.add_argument('--interval', type=int, default=60,
                       help='Monitoring interval in seconds (default: 60)')
    parser.add_argument('--export', type=str,
                       help='Export results to JSON file')
    parser.add_argument('--baseline-file', type=str, default='usb_baseline.json',
                       help='Baseline file path (default: usb_baseline.json)')
    
    args = parser.parse_args()
    
    if not any([args.baseline, args.scan, args.monitor]):
        parser.print_help()
        sys.exit(1)
    
    monitor = USBDeviceMonitor(baseline_file=args.baseline_file)
    monitor.load_baseline()
    
    if args.baseline:
        monitor.create_baseline()
    
    elif args.scan:
        monitor.scan()
        monitor.print_summary()
        
        if args.export:
            monitor.export_results(args.export)
    
    elif args.monitor:
        print(f"\n{'='*70}")
        print("USB DEVICE MONITOR - Continuous Monitoring")
        print(f"{'='*70}\n")
        print(f"Duration: {args.duration} seconds")
        print(f"Interval: {args.interval} seconds")
        print(f"Press Ctrl+C to stop\n")
        
        start_time = time.time()
        iteration = 0
        
        try:
            while time.time() - start_time < args.duration:
                iteration += 1
                print(f"\n[*] Scan iteration {iteration} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                
                monitor.scan()
                monitor.print_summary()
                
                if args.export:
                    export_file = args.export.replace('.json', f'_{iteration}.json')
                    monitor.export_results(export_file)
                
                # Reset for next iteration
                monitor.alerts = defaultdict(list)
                monitor.severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                
                print(f"\n[*] Sleeping {args.interval} seconds...")
                time.sleep(args.interval)
        
        except KeyboardInterrupt:
            print("\n\n[!] Monitoring stopped by user")
            print(f"[*] Total iterations: {iteration}")

if __name__ == '__main__':
    main()
