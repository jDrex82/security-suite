#!/usr/bin/env python3
"""
Ransomware Behavior Detector (RBD)
Real-time detection of ransomware behavior patterns
Catches mass file encryption, shadow copy deletion, backup tampering

This tool detects BEHAVIORS, not signatures - works against zero-day ransomware
"""

import os
import sys
import re
import json
import time
import hashlib
import argparse
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
import threading

class RansomwareBehaviorDetector:
    def __init__(self, monitored_paths=None, baseline_file='rbd_baseline.json'):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.alerts = defaultdict(list)
        self.severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        self.is_windows = sys.platform.startswith('win')
        
        # Paths to monitor (default to user directories)
        if monitored_paths is None:
            self.monitored_paths = self._get_default_paths()
        else:
            self.monitored_paths = monitored_paths
        
        # File modification tracking
        self.file_changes = defaultdict(lambda: {
            'modifications': 0,
            'first_seen': None,
            'last_seen': None,
            'extensions': set(),
            'entropy_changes': []
        })
        
        # Ransomware indicators
        self.suspicious_extensions = [
            '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.lock',
            '.cerber', '.locky', '.wcry', '.wncry', '.wannacry',
            '.zepto', '.odin', '.aesir', '.thor', '.zzzzz',
            '.vvv', '.exx', '.ezz', '.ecc', '.xyz', '.zzz',
            '.aaa', '.abc', '.dharma', '.wallet', '.payransom',
            '.paytounlock', '.cryptolocker', '.cryptowall',
            '.keybtc@inbox_com', '.crjoker', '.EnCiPhErEd'
        ]
        
        # Shadow copy deletion commands (Windows)
        self.shadow_copy_commands = [
            r'vssadmin.*delete.*shadows',
            r'wmic.*shadowcopy.*delete',
            r'bcdedit.*recoveryenabled.*no',
            r'wbadmin.*delete.*catalog',
            r'wbadmin.*delete.*backup',
            r'vssadmin.*resize.*maxsize'
        ]
        
        # Backup service tampering (Windows services)
        self.backup_services = [
            'VSS', 'wbengine', 'BackupExecAgentBrowser',
            'ShadowProtectSvc', 'VeeamDeploymentService',
            'SQLWriter', 'swi_service'
        ]
        
        # Ransomware behavior patterns
        self.behavior_thresholds = {
            'rapid_file_changes': 50,  # Files modified per minute
            'extension_changes': 10,   # Different new extensions
            'entropy_threshold': 7.5,  # High entropy (encrypted files)
            'delete_rate': 20,         # Files deleted per minute
        }
        
        # Known ransomware note filenames
        self.ransom_note_patterns = [
            r'(?i).*decrypt.*\.txt',
            r'(?i).*readme.*\.txt',
            r'(?i).*ransom.*\.txt',
            r'(?i).*help.*decrypt.*',
            r'(?i).*recover.*files.*',
            r'(?i).*restore.*files.*',
            r'(?i).*how.*to.*decrypt.*',
            r'(?i).*your.*files.*encrypted.*'
        ]
        
        # Process monitoring
        self.suspicious_processes = [
            'vssadmin', 'wmic', 'bcdedit', 'wbadmin',
            'powershell', 'cmd', 'cscript', 'wscript'
        ]
        
    def _get_default_paths(self):
        """Get default paths to monitor based on OS"""
        paths = []
        
        if self.is_windows:
            # Windows user directories
            user_profile = os.environ.get('USERPROFILE', 'C:\\Users\\')
            paths = [
                os.path.join(user_profile, 'Documents'),
                os.path.join(user_profile, 'Desktop'),
                os.path.join(user_profile, 'Pictures'),
                os.path.join(user_profile, 'Downloads'),
                'C:\\Users\\Public\\Documents',
            ]
        else:
            # Linux user directories
            home = os.path.expanduser('~')
            paths = [
                os.path.join(home, 'Documents'),
                os.path.join(home, 'Desktop'),
                os.path.join(home, 'Pictures'),
                os.path.join(home, 'Downloads'),
                '/home',
            ]
        
        # Filter to existing paths
        return [p for p in paths if os.path.exists(p)]
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data (higher = more random/encrypted)"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x and (p_x * 8) or 0)
        
        return entropy
    
    def check_file_entropy(self, filepath, sample_size=4096):
        """Check if file has high entropy (possibly encrypted)"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(sample_size)
                if data:
                    entropy = self.calculate_entropy(data)
                    return entropy
        except:
            pass
        return 0
    
    def detect_mass_file_changes(self, scan_duration=60):
        """Detect rapid file modifications (ransomware encryption pattern)"""
        print(f"\n[*] Monitoring for mass file changes ({scan_duration}s)...")
        
        # Track file modifications
        start_time = datetime.now()
        end_time = start_time + timedelta(seconds=scan_duration)
        
        file_snapshots = {}
        alerts = []
        
        # Initial snapshot
        for path in self.monitored_paths:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        try:
                            stat = os.stat(filepath)
                            file_snapshots[filepath] = {
                                'mtime': stat.st_mtime,
                                'size': stat.st_size,
                                'extension': Path(filepath).suffix.lower()
                            }
                        except:
                            pass
        
        print(f"  Initial snapshot: {len(file_snapshots)} files")
        time.sleep(scan_duration)
        
        # Check for changes
        modified_files = []
        new_extensions = set()
        deleted_files = 0
        
        for path in self.monitored_paths:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        try:
                            stat = os.stat(filepath)
                            current_ext = Path(filepath).suffix.lower()
                            
                            # Check if file was modified
                            if filepath in file_snapshots:
                                old_mtime = file_snapshots[filepath]['mtime']
                                old_ext = file_snapshots[filepath]['extension']
                                
                                if stat.st_mtime > old_mtime:
                                    modified_files.append(filepath)
                                    
                                    # Check for extension change
                                    if current_ext != old_ext and current_ext in self.suspicious_extensions:
                                        new_extensions.add(current_ext)
                                        
                                        alerts.append({
                                            'severity': 'CRITICAL',
                                            'type': 'SUSPICIOUS_EXTENSION_CHANGE',
                                            'file': filepath,
                                            'old_extension': old_ext,
                                            'new_extension': current_ext,
                                            'message': f'File extension changed to ransomware indicator: {filepath}'
                                        })
                                    
                                    # Check entropy for possible encryption
                                    entropy = self.check_file_entropy(filepath)
                                    if entropy > self.behavior_thresholds['entropy_threshold']:
                                        alerts.append({
                                            'severity': 'HIGH',
                                            'type': 'HIGH_ENTROPY_FILE',
                                            'file': filepath,
                                            'entropy': round(entropy, 2),
                                            'message': f'File shows high entropy (possibly encrypted): {filepath}'
                                        })
                            else:
                                # New file created
                                if current_ext in self.suspicious_extensions:
                                    alerts.append({
                                        'severity': 'CRITICAL',
                                        'type': 'SUSPICIOUS_NEW_FILE',
                                        'file': filepath,
                                        'extension': current_ext,
                                        'message': f'New file with ransomware extension: {filepath}'
                                    })
                        except:
                            pass
        
        # Check for deleted files
        current_files = set()
        for path in self.monitored_paths:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for filename in files:
                        current_files.add(os.path.join(root, filename))
        
        deleted_files = len(set(file_snapshots.keys()) - current_files)
        
        # Calculate modification rate
        time_elapsed = (datetime.now() - start_time).total_seconds() / 60  # minutes
        modification_rate = len(modified_files) / time_elapsed if time_elapsed > 0 else 0
        delete_rate = deleted_files / time_elapsed if time_elapsed > 0 else 0
        
        # Check for mass modification pattern
        if modification_rate > self.behavior_thresholds['rapid_file_changes']:
            alerts.append({
                'severity': 'CRITICAL',
                'type': 'MASS_FILE_MODIFICATION',
                'files_modified': len(modified_files),
                'rate_per_minute': round(modification_rate, 2),
                'message': f'RANSOMWARE BEHAVIOR: Mass file modification detected - {len(modified_files)} files modified at {round(modification_rate, 2)}/min'
            })
        
        if delete_rate > self.behavior_thresholds['delete_rate']:
            alerts.append({
                'severity': 'HIGH',
                'type': 'MASS_FILE_DELETION',
                'files_deleted': deleted_files,
                'rate_per_minute': round(delete_rate, 2),
                'message': f'Mass file deletion detected: {deleted_files} files at {round(delete_rate, 2)}/min'
            })
        
        if len(new_extensions) > self.behavior_thresholds['extension_changes']:
            alerts.append({
                'severity': 'CRITICAL',
                'type': 'MULTIPLE_SUSPICIOUS_EXTENSIONS',
                'extensions': list(new_extensions),
                'count': len(new_extensions),
                'message': f'Multiple suspicious extensions detected: {", ".join(new_extensions)}'
            })
        
        print(f"  Files modified: {len(modified_files)}")
        print(f"  Files deleted: {deleted_files}")
        print(f"  Modification rate: {round(modification_rate, 2)}/min")
        print(f"  Suspicious extensions: {len(new_extensions)}")
        
        return alerts
    
    def detect_shadow_copy_deletion(self):
        """Detect shadow copy deletion attempts (Windows)"""
        alerts = []
        
        if not self.is_windows:
            return alerts
        
        print("\n[*] Checking for shadow copy tampering...")
        
        try:
            # Check shadow copies
            result = subprocess.run(
                ['vssadmin', 'list', 'shadows'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                shadow_count = result.stdout.count('Shadow Copy Volume')
                print(f"  Current shadow copies: {shadow_count}")
                
                if shadow_count == 0:
                    alerts.append({
                        'severity': 'CRITICAL',
                        'type': 'NO_SHADOW_COPIES',
                        'message': 'RANSOMWARE INDICATOR: No shadow copies found - may have been deleted'
                    })
            
            # Check for suspicious processes
            result = subprocess.run(
                ['tasklist', '/FO', 'CSV', '/NH'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for process in self.suspicious_processes:
                    if process.lower() in result.stdout.lower():
                        # Get command line for process
                        cmd_result = subprocess.run(
                            ['wmic', 'process', 'where', f'name="{process}.exe"', 'get', 'commandline', '/format:list'],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        
                        if cmd_result.returncode == 0:
                            cmdline = cmd_result.stdout
                            
                            # Check for shadow copy deletion commands
                            for pattern in self.shadow_copy_commands:
                                if re.search(pattern, cmdline, re.IGNORECASE):
                                    alerts.append({
                                        'severity': 'CRITICAL',
                                        'type': 'SHADOW_COPY_DELETION_ATTEMPT',
                                        'process': process,
                                        'command': cmdline.strip(),
                                        'message': f'RANSOMWARE BEHAVIOR: Shadow copy deletion command detected - {process}'
                                    })
        
        except Exception as e:
            print(f"  Error checking shadow copies: {e}")
        
        return alerts
    
    def detect_backup_tampering(self):
        """Detect backup service tampering"""
        alerts = []
        
        if not self.is_windows:
            # Linux: Check for backup directory deletion
            backup_dirs = ['/var/backups', '/backup', '/home/backup']
            for backup_dir in backup_dirs:
                if not os.path.exists(backup_dir):
                    # Check if it existed recently
                    alerts.append({
                        'severity': 'HIGH',
                        'type': 'BACKUP_DIRECTORY_MISSING',
                        'directory': backup_dir,
                        'message': f'Backup directory not found: {backup_dir}'
                    })
            return alerts
        
        print("\n[*] Checking backup services...")
        
        try:
            # Check Windows backup services
            result = subprocess.run(
                ['sc', 'query'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                services_output = result.stdout
                
                for service in self.backup_services:
                    if service.lower() in services_output.lower():
                        # Check service status
                        status_result = subprocess.run(
                            ['sc', 'query', service],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        
                        if status_result.returncode == 0:
                            if 'STOPPED' in status_result.stdout:
                                alerts.append({
                                    'severity': 'HIGH',
                                    'type': 'BACKUP_SERVICE_STOPPED',
                                    'service': service,
                                    'message': f'RANSOMWARE INDICATOR: Backup service stopped - {service}'
                                })
                        else:
                            alerts.append({
                                'severity': 'MEDIUM',
                                'type': 'BACKUP_SERVICE_MISSING',
                                'service': service,
                                'message': f'Backup service not found: {service}'
                            })
        
        except Exception as e:
            print(f"  Error checking backup services: {e}")
        
        return alerts
    
    def detect_ransom_notes(self):
        """Detect ransomware note files"""
        alerts = []
        
        print("\n[*] Scanning for ransom notes...")
        
        note_files = []
        
        for path in self.monitored_paths:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for filename in files:
                        for pattern in self.ransom_note_patterns:
                            if re.search(pattern, filename):
                                filepath = os.path.join(root, filename)
                                note_files.append(filepath)
                                
                                alerts.append({
                                    'severity': 'CRITICAL',
                                    'type': 'RANSOM_NOTE_DETECTED',
                                    'file': filepath,
                                    'message': f'RANSOMWARE CONFIRMED: Ransom note detected - {filename}'
                                })
                                
                                # Try to read content
                                try:
                                    with open(filepath, 'r', errors='ignore') as f:
                                        content = f.read(500)  # First 500 chars
                                        if any(word in content.lower() for word in ['bitcoin', 'decrypt', 'ransom', 'payment']):
                                            alerts[-1]['content_preview'] = content[:200]
                                except:
                                    pass
        
        print(f"  Ransom notes found: {len(note_files)}")
        
        return alerts
    
    def monitor(self, duration=300, interval=60):
        """Continuous monitoring mode"""
        print(f"\n{'='*70}")
        print("Ransomware Behavior Detector - Active Monitoring")
        print(f"{'='*70}")
        print(f"Duration: {duration} seconds | Check interval: {interval} seconds")
        print(f"Monitored paths: {len(self.monitored_paths)}")
        for path in self.monitored_paths:
            print(f"  - {path}")
        print(f"{'='*70}\n")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(seconds=duration)
        iteration = 0
        
        while datetime.now() < end_time:
            iteration += 1
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Check #{iteration}")
            print("-" * 70)
            
            # Run all detection methods
            all_alerts = []
            all_alerts.extend(self.detect_mass_file_changes(scan_duration=interval))
            all_alerts.extend(self.detect_shadow_copy_deletion())
            all_alerts.extend(self.detect_backup_tampering())
            all_alerts.extend(self.detect_ransom_notes())
            
            # Process alerts
            if all_alerts:
                print(f"\n⚠️  {len(all_alerts)} RANSOMWARE INDICATORS DETECTED!")
                print("=" * 70)
                
                for alert in all_alerts:
                    severity = alert['severity']
                    self.severity_counts[severity] += 1
                    self.alerts[severity].append(alert)
                    
                    print(f"\n[{severity}] {alert['type']}")
                    print(f"  {alert['message']}")
                    
                    if severity == 'CRITICAL':
                        print("  ⚠️  IMMEDIATE ACTION REQUIRED ⚠️")
            else:
                print("\n✓ No ransomware behavior detected")
            
            # Wait before next check
            if datetime.now() < end_time:
                remaining = int((end_time - datetime.now()).total_seconds())
                print(f"\nNext check in {min(interval, remaining)} seconds...")
                time.sleep(min(interval, remaining))
        
        self.print_summary()
    
    def scan(self):
        """One-time comprehensive scan"""
        print(f"\n{'='*70}")
        print("Ransomware Behavior Detector - One-Time Scan")
        print(f"{'='*70}\n")
        
        all_alerts = []
        all_alerts.extend(self.detect_mass_file_changes(scan_duration=30))
        all_alerts.extend(self.detect_shadow_copy_deletion())
        all_alerts.extend(self.detect_backup_tampering())
        all_alerts.extend(self.detect_ransom_notes())
        
        # Process results
        for alert in all_alerts:
            severity = alert['severity']
            self.severity_counts[severity] += 1
            self.alerts[severity].append(alert)
        
        self.print_summary()
    
    def print_summary(self):
        """Print detection summary"""
        print(f"\n{'='*70}")
        print("RANSOMWARE DETECTION SUMMARY")
        print(f"{'='*70}")
        
        total_alerts = sum(self.severity_counts.values())
        print(f"\nTotal Indicators: {total_alerts}")
        print(f"  CRITICAL: {self.severity_counts['CRITICAL']}")
        print(f"  HIGH: {self.severity_counts['HIGH']}")
        print(f"  MEDIUM: {self.severity_counts['MEDIUM']}")
        print(f"  LOW: {self.severity_counts['LOW']}")
        
        if self.severity_counts['CRITICAL'] > 0:
            print(f"\n{'!'*70}")
            print("⚠️  CRITICAL RANSOMWARE INDICATORS DETECTED ⚠️")
            print("IMMEDIATE ACTIONS:")
            print("  1. DISCONNECT from network immediately")
            print("  2. DO NOT restart the system")
            print("  3. Contact security team / incident response")
            print("  4. Preserve evidence (disk image if possible)")
            print("  5. Check backups for integrity")
            print(f"{'!'*70}")
        
        if total_alerts > 0:
            print(f"\n{'='*70}")
            print("DETAILED FINDINGS")
            print(f"{'='*70}")
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if self.alerts[severity]:
                    print(f"\n{severity} Alerts ({len(self.alerts[severity])}):")
                    for i, alert in enumerate(self.alerts[severity][:10], 1):
                        print(f"\n  {i}. {alert['type']}")
                        print(f"     {alert['message']}")
                        if 'file' in alert:
                            print(f"     File: {alert['file']}")
                    
                    if len(self.alerts[severity]) > 10:
                        print(f"\n  ... and {len(self.alerts[severity]) - 10} more {severity} alerts")
    
    def export_results(self, output_file='rbd_results.json'):
        """Export results to JSON"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'platform': 'Windows' if self.is_windows else 'Linux',
            'monitored_paths': self.monitored_paths,
            'summary': {
                'total_indicators': sum(self.severity_counts.values()),
                'severity_counts': self.severity_counts,
                'critical_detected': self.severity_counts['CRITICAL'] > 0
            },
            'alerts': dict(self.alerts)
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n✓ Results exported to: {output_file}")
        return output_file


def main():
    parser = argparse.ArgumentParser(
        description='Ransomware Behavior Detector - Behavioral analysis for ransomware detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # One-time scan
  python ransomware_detector.py --scan
  
  # Continuous monitoring (5 minutes, check every 60 seconds)
  python ransomware_detector.py --monitor --duration 300 --interval 60
  
  # Monitor specific paths
  python ransomware_detector.py --monitor --paths "C:\\Users" "D:\\Data"
  
  # Export results
  python ransomware_detector.py --scan --export results.json

Detection Methods:
  - Mass file modification patterns
  - Suspicious file extension changes
  - High entropy files (encrypted)
  - Shadow copy deletion attempts (Windows)
  - Backup service tampering
  - Ransom note detection

Note: Requires appropriate permissions to access monitored directories.
      Windows features require Administrator privileges.
        """
    )
    
    parser.add_argument('--scan', action='store_true',
                       help='One-time scan')
    parser.add_argument('--monitor', action='store_true',
                       help='Continuous monitoring mode')
    parser.add_argument('--duration', type=int, default=300,
                       help='Monitoring duration in seconds (default: 300)')
    parser.add_argument('--interval', type=int, default=60,
                       help='Check interval in seconds (default: 60)')
    parser.add_argument('--paths', nargs='+',
                       help='Specific paths to monitor (space-separated)')
    parser.add_argument('--export', metavar='FILE',
                       help='Export results to JSON file')
    
    args = parser.parse_args()
    
    # Check for admin privileges on Windows
    if sys.platform.startswith('win'):
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("⚠️  Warning: Not running as Administrator. Some features may be limited.")
                print("   For full functionality, run as Administrator.\n")
        except:
            pass
    
    detector = RansomwareBehaviorDetector(monitored_paths=args.paths)
    
    try:
        if args.monitor:
            detector.monitor(duration=args.duration, interval=args.interval)
            if args.export:
                detector.export_results(args.export)
        elif args.scan:
            detector.scan()
            if args.export:
                detector.export_results(args.export)
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        print("\n\nMonitoring interrupted by user.")
        if args.export:
            detector.export_results(args.export)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
