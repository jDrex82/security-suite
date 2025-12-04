#!/usr/bin/env python3
"""
Rootkit and Memory Forensics Detector (RMD)
Detects hidden processes, kernel modules, rootkits, and memory-resident malware
Critical for detecting advanced persistent threats that evade traditional monitoring
"""

import os
import sys
import re
import json
import time
import argparse
import subprocess
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path

class RootkitMemoryDetector:
    def __init__(self, baseline_file='rmd_baseline.json'):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.alerts = defaultdict(list)
        self.severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        # Suspicious kernel modules
        self.suspicious_modules = [
            'diamorphine',  # Famous LKM rootkit
            'reptile',  # LKM rootkit
            'suterusu',  # LKM rootkit
            'kovid',  # LKM rootkit
            'rootkit',  # Generic
            'backdoor',  # Generic
            'hide',  # Process hiding
            'reverse_tcp',  # Reverse shells
        ]
        
        # Suspicious system call hooks
        self.critical_syscalls = [
            'sys_read', 'sys_write', 'sys_open', 'sys_close',
            'sys_execve', 'sys_fork', 'sys_kill', 'sys_getdents',
            'sys_getdents64', 'sys_recvmsg', 'sys_sendmsg'
        ]
        
        # Known rootkit artifacts
        self.rootkit_artifacts = [
            '/dev/shm/.ice',
            '/tmp/.X11-unix/.ICE',
            '/proc/knark',
            '/proc/rtk',
            '/proc/sysdev',
            '/dev/ptyxx',
        ]
        
        # Process tracking
        self.ps_processes = set()
        self.proc_processes = set()
        
    def get_processes_from_ps(self):
        """Get process list using ps command"""
        processes = set()
        
        try:
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split(None, 10)
                        if len(parts) >= 2:
                            pid = parts[1]
                            processes.add(pid)
        
        except Exception as e:
            print(f"Warning: Error getting ps output: {e}")
        
        return processes
    
    def get_processes_from_proc(self):
        """Get process list directly from /proc"""
        processes = set()
        
        try:
            for entry in os.listdir('/proc'):
                if entry.isdigit():  # PIDs are numeric
                    processes.add(entry)
        
        except Exception as e:
            print(f"Warning: Error reading /proc: {e}")
        
        return processes
    
    def detect_hidden_processes(self):
        """Detect processes hidden from ps but visible in /proc"""
        print("[*] Checking for hidden processes...")
        
        self.ps_processes = self.get_processes_from_ps()
        self.proc_processes = self.get_processes_from_proc()
        
        print(f"    • ps shows: {len(self.ps_processes)} processes")
        print(f"    • /proc shows: {len(self.proc_processes)} processes")
        
        # Find processes in /proc but not in ps (potentially hidden)
        hidden = self.proc_processes - self.ps_processes
        
        if hidden:
            for pid in hidden:
                try:
                    # Try to get process info
                    cmdline_path = f'/proc/{pid}/cmdline'
                    comm_path = f'/proc/{pid}/comm'
                    
                    cmdline = 'unknown'
                    if os.path.exists(cmdline_path):
                        with open(cmdline_path, 'r') as f:
                            cmdline = f.read().replace('\x00', ' ').strip()
                    
                    comm = 'unknown'
                    if os.path.exists(comm_path):
                        with open(comm_path, 'r') as f:
                            comm = f.read().strip()
                    
                    self.alerts['hidden_process'].append({
                        'severity': 'CRITICAL',
                        'description': 'Process hidden from ps command',
                        'pid': pid,
                        'cmdline': cmdline if cmdline else 'unknown',
                        'comm': comm if comm else 'unknown'
                    })
                    self.severity_counts['CRITICAL'] += 1
                
                except Exception:
                    pass
    
    def check_kernel_modules(self):
        """Check for suspicious kernel modules"""
        print("[*] Checking loaded kernel modules...")
        
        try:
            result = subprocess.run(
                ['lsmod'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                modules = []
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if parts:
                            module_name = parts[0]
                            modules.append(module_name)
                            
                            # Check against suspicious list
                            for suspicious in self.suspicious_modules:
                                if suspicious.lower() in module_name.lower():
                                    self.alerts['suspicious_module'].append({
                                        'severity': 'CRITICAL',
                                        'description': 'Suspicious kernel module loaded',
                                        'module': module_name,
                                        'pattern': suspicious
                                    })
                                    self.severity_counts['CRITICAL'] += 1
                
                print(f"    • Found {len(modules)} loaded modules")
                
                # Also check /proc/modules directly
                if os.path.exists('/proc/modules'):
                    with open('/proc/modules', 'r') as f:
                        proc_modules = len(f.readlines())
                        
                        # Discrepancy check
                        if abs(len(modules) - proc_modules) > 5:
                            self.alerts['module_discrepancy'].append({
                                'severity': 'HIGH',
                                'description': 'Module count discrepancy detected',
                                'lsmod_count': len(modules),
                                'proc_modules_count': proc_modules,
                                'difference': abs(len(modules) - proc_modules)
                            })
                            self.severity_counts['HIGH'] += 1
        
        except Exception as e:
            print(f"Warning: Error checking kernel modules: {e}")
    
    def check_rootkit_artifacts(self):
        """Check for known rootkit artifacts"""
        print("[*] Checking for rootkit artifacts...")
        
        found = 0
        for artifact in self.rootkit_artifacts:
            if os.path.exists(artifact):
                self.alerts['rootkit_artifact'].append({
                    'severity': 'CRITICAL',
                    'description': 'Known rootkit artifact detected',
                    'path': artifact,
                    'type': 'file' if os.path.isfile(artifact) else 'directory'
                })
                self.severity_counts['CRITICAL'] += 1
                found += 1
        
        print(f"    • Found {found} known rootkit artifacts")
    
    def check_network_hiding(self):
        """Check for hidden network connections"""
        print("[*] Checking for hidden network connections...")
        
        # Get connections from ss/netstat
        netstat_connections = set()
        try:
            result = subprocess.run(
                ['ss', '-tupan'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:
                    if line.strip():
                        # Parse connection
                        parts = line.split()
                        if len(parts) >= 5:
                            local = parts[4]
                            remote = parts[5] if len(parts) > 5 else ''
                            netstat_connections.add(f"{local}-{remote}")
        
        except Exception:
            pass
        
        # Get connections from /proc/net/tcp
        proc_connections = set()
        try:
            for proto in ['tcp', 'tcp6', 'udp', 'udp6']:
                path = f'/proc/net/{proto}'
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        for line in f.readlines()[1:]:  # Skip header
                            parts = line.split()
                            if len(parts) >= 3:
                                local = parts[1]
                                remote = parts[2]
                                proc_connections.add(f"{local}-{remote}")
        
        except Exception:
            pass
        
        print(f"    • netstat/ss: {len(netstat_connections)} connections")
        print(f"    • /proc/net: {len(proc_connections)} connections")
        
        # Large discrepancy might indicate hiding
        if abs(len(netstat_connections) - len(proc_connections)) > 10:
            self.alerts['connection_hiding'].append({
                'severity': 'HIGH',
                'description': 'Network connection hiding suspected',
                'netstat_count': len(netstat_connections),
                'proc_count': len(proc_connections),
                'difference': abs(len(netstat_connections) - len(proc_connections))
            })
            self.severity_counts['HIGH'] += 1
    
    def check_ld_preload(self):
        """Check for LD_PRELOAD hijacking"""
        print("[*] Checking for LD_PRELOAD hijacking...")
        
        ld_preload = os.environ.get('LD_PRELOAD', '')
        if ld_preload:
            self.alerts['ld_preload'].append({
                'severity': 'HIGH',
                'description': 'LD_PRELOAD environment variable set',
                'value': ld_preload,
                'risk': 'Could be used for function hooking'
            })
            self.severity_counts['HIGH'] += 1
        
        # Check /etc/ld.so.preload
        if os.path.exists('/etc/ld.so.preload'):
            try:
                with open('/etc/ld.so.preload', 'r') as f:
                    content = f.read().strip()
                    if content:
                        self.alerts['ld_preload_file'].append({
                            'severity': 'CRITICAL',
                            'description': '/etc/ld.so.preload contains entries',
                            'content': content,
                            'risk': 'System-wide library preloading (rootkit technique)'
                        })
                        self.severity_counts['CRITICAL'] += 1
            except Exception:
                pass
    
    def check_suspicious_binaries(self):
        """Check for suspicious system binaries"""
        print("[*] Checking system binaries for tampering...")
        
        critical_binaries = [
            '/bin/ps', '/bin/ls', '/bin/netstat', '/bin/lsof',
            '/usr/bin/ssh', '/usr/bin/sudo', '/usr/bin/top',
            '/sbin/init', '/sbin/insmod', '/sbin/lsmod'
        ]
        
        for binary in critical_binaries:
            if not os.path.exists(binary):
                continue
            
            try:
                # Check if binary is suspiciously small (could be replaced)
                size = os.path.getsize(binary)
                if size < 1000:  # Less than 1KB is suspicious
                    self.alerts['suspicious_binary'].append({
                        'severity': 'HIGH',
                        'description': 'System binary unusually small',
                        'binary': binary,
                        'size': size,
                        'risk': 'Possible binary replacement'
                    })
                    self.severity_counts['HIGH'] += 1
                
                # Check for unusual permissions
                stat_info = os.stat(binary)
                mode = stat_info.st_mode
                
                # Check if world-writable
                if mode & 0o002:
                    self.alerts['binary_permissions'].append({
                        'severity': 'CRITICAL',
                        'description': 'System binary is world-writable',
                        'binary': binary,
                        'permissions': oct(mode),
                        'risk': 'Could be modified by any user'
                    })
                    self.severity_counts['CRITICAL'] += 1
            
            except Exception:
                pass
    
    def check_cron_backdoors(self):
        """Check for cron-based persistence"""
        print("[*] Checking for cron backdoors...")
        
        cron_dirs = [
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.monthly',
            '/etc/cron.weekly',
            '/var/spool/cron/crontabs'
        ]
        
        suspicious_patterns = [
            r'nc\s+-e',  # Netcat reverse shell
            r'/dev/tcp/',  # Bash reverse shell
            r'curl.*\|.*sh',  # Download and execute
            r'wget.*\|.*bash',  # Download and execute
            r'python.*socket',  # Python backdoor
            r'perl.*socket',  # Perl backdoor
        ]
        
        for cron_dir in cron_dirs:
            if not os.path.exists(cron_dir):
                continue
            
            try:
                for root, dirs, files in os.walk(cron_dir):
                    for file in files:
                        filepath = os.path.join(root, file)
                        
                        try:
                            with open(filepath, 'r', errors='ignore') as f:
                                content = f.read()
                                
                                for pattern in suspicious_patterns:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        self.alerts['cron_backdoor'].append({
                                            'severity': 'CRITICAL',
                                            'description': 'Suspicious cron job detected',
                                            'file': filepath,
                                            'pattern': pattern,
                                            'risk': 'Persistent backdoor'
                                        })
                                        self.severity_counts['CRITICAL'] += 1
                                        break
                        except Exception:
                            pass
            
            except Exception:
                pass
    
    def check_init_system(self):
        """Check init system for persistence"""
        print("[*] Checking init system for backdoors...")
        
        systemd_paths = [
            '/etc/systemd/system',
            '/usr/lib/systemd/system',
            '/lib/systemd/system'
        ]
        
        for path in systemd_paths:
            if not os.path.exists(path):
                continue
            
            try:
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if file.endswith('.service'):
                            filepath = os.path.join(root, file)
                            
                            # Check for unusual service files
                            try:
                                with open(filepath, 'r', errors='ignore') as f:
                                    content = f.read()
                                    
                                    # Look for suspicious commands
                                    if any(pattern in content.lower() for pattern in ['nc -e', '/dev/tcp/', 'reverse_tcp', 'backdoor']):
                                        self.alerts['systemd_backdoor'].append({
                                            'severity': 'CRITICAL',
                                            'description': 'Suspicious systemd service detected',
                                            'file': filepath,
                                            'risk': 'Persistent backdoor via systemd'
                                        })
                                        self.severity_counts['CRITICAL'] += 1
                            except Exception:
                                pass
            
            except Exception:
                pass
    
    def scan(self):
        """Run comprehensive rootkit and memory forensics scan"""
        print(f"\n{'='*70}")
        print("ROOTKIT & MEMORY FORENSICS DETECTOR - Scan Started")
        print(f"{'='*70}\n")
        
        # Check for hidden processes
        self.detect_hidden_processes()
        
        # Check kernel modules
        self.check_kernel_modules()
        
        # Check for rootkit artifacts
        self.check_rootkit_artifacts()
        
        # Check for hidden network connections
        self.check_network_hiding()
        
        # Check for LD_PRELOAD hijacking
        self.check_ld_preload()
        
        # Check system binaries
        self.check_suspicious_binaries()
        
        # Check cron for backdoors
        self.check_cron_backdoors()
        
        # Check init system
        self.check_init_system()
        
        return self.alerts
    
    def create_baseline(self):
        """Create baseline of normal system state"""
        print(f"\n{'='*70}")
        print("ROOTKIT & MEMORY FORENSICS - Creating Baseline")
        print(f"{'='*70}\n")
        
        baseline_data = {
            'timestamp': datetime.now().isoformat(),
            'ps_process_count': len(self.get_processes_from_ps()),
            'proc_process_count': len(self.get_processes_from_proc()),
            'loaded_modules': [],
            'system_binaries': {}
        }
        
        # Get loaded modules
        try:
            result = subprocess.run(['lsmod'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:
                    if line.strip():
                        module = line.split()[0]
                        baseline_data['loaded_modules'].append(module)
        except Exception:
            pass
        
        # Record binary sizes
        critical_binaries = ['/bin/ps', '/bin/ls', '/bin/netstat', '/usr/bin/ssh']
        for binary in critical_binaries:
            if os.path.exists(binary):
                try:
                    size = os.path.getsize(binary)
                    baseline_data['system_binaries'][binary] = size
                except Exception:
                    pass
        
        # Save baseline
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)
        
        print(f"[+] Baseline created: {self.baseline_file}")
        print(f"[+] Process count: {baseline_data['proc_process_count']}")
        print(f"[+] Loaded modules: {len(baseline_data['loaded_modules'])}")
        
        return True
    
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
        
        if total_alerts == 0:
            print("\n✓ No rootkits or memory-resident threats detected")
        else:
            print(f"\n⚠ {total_alerts} potential rootkit/malware indicators detected")
            
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
                'ps_processes': len(self.ps_processes),
                'proc_processes': len(self.proc_processes),
                'hidden_processes': len(self.proc_processes - self.ps_processes)
            },
            'alerts': dict(self.alerts)
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Results exported to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Rootkit & Memory Forensics Detector - Detect kernel-level malware and hidden threats',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create baseline
  sudo python3 rootkit_memory_detector.py --baseline
  
  # Run scan
  sudo python3 rootkit_memory_detector.py --scan
  
  # Run scan and export results
  sudo python3 rootkit_memory_detector.py --scan --export rmd_results.json
  
  # Continuous monitoring (24 hours, check every 1 hour)
  sudo python3 rootkit_memory_detector.py --monitor --duration 86400 --interval 3600
  
Note: Root/sudo privileges recommended for full functionality
        """
    )
    
    parser.add_argument('--baseline', action='store_true',
                       help='Create baseline of normal system state')
    parser.add_argument('--scan', action='store_true',
                       help='Scan once for rootkits and malware')
    parser.add_argument('--monitor', action='store_true',
                       help='Continuous monitoring mode')
    parser.add_argument('--duration', type=int, default=3600,
                       help='Monitoring duration in seconds (default: 3600)')
    parser.add_argument('--interval', type=int, default=600,
                       help='Monitoring interval in seconds (default: 600)')
    parser.add_argument('--export', type=str,
                       help='Export results to JSON file')
    parser.add_argument('--baseline-file', type=str, default='rmd_baseline.json',
                       help='Baseline file path (default: rmd_baseline.json)')
    
    args = parser.parse_args()
    
    if not any([args.baseline, args.scan, args.monitor]):
        parser.print_help()
        sys.exit(1)
    
    # Check if running as root/administrator (platform-specific)
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("[!] Warning: Not running as Administrator. Some checks may be limited.")
            print("[!] Run PowerShell as Administrator for full functionality\n")
    except (AttributeError, ImportError):
        # Unix/Linux system - check if root
        try:
            if os.geteuid() != 0:
                print("[!] Warning: Not running as root. Some checks may be limited.")
                print("[!] Run with sudo for full functionality\n")
        except AttributeError:
            # Neither Windows nor Unix - skip check
            pass
    
    detector = RootkitMemoryDetector(baseline_file=args.baseline_file)
    
    if args.baseline:
        detector.create_baseline()
    
    elif args.scan:
        detector.scan()
        detector.print_summary()
        
        if args.export:
            detector.export_results(args.export)
    
    elif args.monitor:
        print(f"\n{'='*70}")
        print("ROOTKIT & MEMORY FORENSICS - Continuous Monitoring")
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
                
                detector.scan()
                detector.print_summary()
                
                if args.export:
                    export_file = args.export.replace('.json', f'_{iteration}.json')
                    detector.export_results(export_file)
                
                # Reset for next iteration
                detector.alerts = defaultdict(list)
                detector.severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                
                print(f"\n[*] Sleeping {args.interval} seconds...")
                time.sleep(args.interval)
        
        except KeyboardInterrupt:
            print("\n\n[!] Monitoring stopped by user")
            print(f"[*] Total iterations: {iteration}")

if __name__ == '__main__':
    main()
