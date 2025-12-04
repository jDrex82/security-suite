#!/usr/bin/env python3
"""
Windows File Integrity Monitor (FIM)
Detects unauthorized changes to critical Windows system files and directories
Windows equivalent of FIM for Linux
"""

import os
import sys
import json
import hashlib
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import stat

class WindowsFileIntegrityMonitor:
    def __init__(self, baseline_file='fim_baseline_windows.json', config_file=None):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.config_file = config_file
        self.changes = defaultdict(list)
        
        # Critical Windows system files and directories to monitor
        self.default_paths = self._get_windows_paths()
    
    def _get_windows_paths(self):
        """Get Windows-specific paths to monitor"""
        system_root = os.environ.get('SystemRoot', 'C:\\Windows')
        program_files = os.environ.get('ProgramFiles', 'C:\\Program Files')
        
        paths = [
            # System configuration
            os.path.join(system_root, 'System32', 'config', 'SAM'),
            os.path.join(system_root, 'System32', 'config', 'SYSTEM'),
            os.path.join(system_root, 'System32', 'config', 'SECURITY'),
            os.path.join(system_root, 'System32', 'config', 'SOFTWARE'),
            
            # Boot configuration
            'C:\\Boot.ini',
            os.path.join(system_root, 'System32', 'drivers', 'etc', 'hosts'),
            
            # Critical system directories
            os.path.join(system_root, 'System32', 'drivers'),
            os.path.join(system_root, 'System32', 'WindowsPowerShell'),
            os.path.join(system_root, 'Tasks'),  # Scheduled tasks
            
            # Startup locations
            'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
            os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            
            # Registry-based startup (we'll note these for manual checking)
            # HKLM\Software\Microsoft\Windows\CurrentVersion\Run
            # HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
        ]
        
        # Filter out paths that don't exist
        return [p for p in paths if os.path.exists(p)]
    
    def calculate_hash(self, filepath, algorithm='sha256'):
        """Calculate cryptographic hash of a file"""
        try:
            hash_obj = hashlib.new(algorithm)
            with open(filepath, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except (PermissionError, FileNotFoundError, OSError) as e:
            return f"ERROR: {str(e)}"
    
    def get_file_metadata(self, filepath):
        """Get comprehensive file metadata for Windows"""
        try:
            stats = os.stat(filepath)
            
            metadata = {
                'path': str(filepath),
                'size': stats.st_size,
                'mtime': stats.st_mtime,
                'mtime_human': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'ctime': stats.st_ctime,
                'ctime_human': datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                'hash': self.calculate_hash(filepath)
            }
            
            # Get Windows-specific attributes if available
            try:
                import win32api
                import win32con
                
                attrs = win32api.GetFileAttributes(filepath)
                metadata['attributes'] = {
                    'hidden': bool(attrs & win32con.FILE_ATTRIBUTE_HIDDEN),
                    'system': bool(attrs & win32con.FILE_ATTRIBUTE_SYSTEM),
                    'readonly': bool(attrs & win32con.FILE_ATTRIBUTE_READONLY),
                    'archive': bool(attrs & win32con.FILE_ATTRIBUTE_ARCHIVE),
                    'compressed': bool(attrs & win32con.FILE_ATTRIBUTE_COMPRESSED),
                    'encrypted': bool(attrs & win32con.FILE_ATTRIBUTE_ENCRYPTED),
                }
            except ImportError:
                # pywin32 not available, skip Windows-specific attributes
                pass
            except Exception:
                # Error getting attributes, skip
                pass
            
            return metadata
            
        except (PermissionError, FileNotFoundError, OSError) as e:
            return {
                'path': str(filepath),
                'error': str(e)
            }
    
    def scan_directory(self, directory, recursive=True, max_depth=3, current_depth=0):
        """Recursively scan directory for files"""
        files = []
        
        try:
            path = Path(directory)
            if not path.exists():
                print(f"Warning: {directory} does not exist")
                return files
            
            if path.is_file():
                return [str(path)]
            
            # Scan directory
            for item in path.iterdir():
                try:
                    if item.is_file():
                        files.append(str(item))
                    elif item.is_dir() and recursive and current_depth < max_depth:
                        # Skip certain directories
                        skip_dirs = ['$RECYCLE.BIN', 'System Volume Information', 
                                   'Windows.old', 'WinSxS']
                        if item.name not in skip_dirs:
                            files.extend(self.scan_directory(
                                str(item), recursive, max_depth, current_depth + 1
                            ))
                except (PermissionError, OSError):
                    continue
            
        except (PermissionError, OSError) as e:
            print(f"Warning: Cannot access {directory}: {e}")
        
        return files
    
    def create_baseline(self, paths=None, recursive=True):
        """Create baseline of file hashes"""
        if paths is None:
            paths = self.default_paths
        elif isinstance(paths, str):
            paths = [paths]
        
        print("Creating baseline...")
        print(f"Monitoring {len(paths)} paths")
        
        all_files = []
        for path in paths:
            print(f"Scanning: {path}")
            files = self.scan_directory(path, recursive=recursive)
            all_files.extend(files)
        
        print(f"\nProcessing {len(all_files)} files...")
        
        for i, filepath in enumerate(all_files, 1):
            if i % 100 == 0:
                print(f"Progress: {i}/{len(all_files)}", end='\r')
            
            metadata = self.get_file_metadata(filepath)
            if 'error' not in metadata:
                self.baseline[filepath] = metadata
        
        print(f"\nBaseline created with {len(self.baseline)} files")
        
        # Save baseline
        self.save_baseline()
        
        return self.baseline
    
    def save_baseline(self):
        """Save baseline to JSON file"""
        output = {
            'created': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'baseline': self.baseline
        }
        
        with open(self.baseline_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"Baseline saved to {self.baseline_file}")
    
    def load_baseline(self):
        """Load baseline from JSON file"""
        try:
            with open(self.baseline_file, 'r') as f:
                data = json.load(f)
                self.baseline = data.get('baseline', {})
                created = data.get('created', 'Unknown')
                print(f"Loaded baseline from {self.baseline_file}")
                print(f"Created: {created}")
                print(f"Files: {len(self.baseline)}")
                return True
        except FileNotFoundError:
            print(f"Error: Baseline file {self.baseline_file} not found")
            print("Run with --create-baseline first")
            return False
        except json.JSONDecodeError:
            print(f"Error: Baseline file {self.baseline_file} is corrupted")
            return False
    
    def check_integrity(self, paths=None):
        """Check current state against baseline"""
        if not self.baseline:
            if not self.load_baseline():
                return
        
        if paths is None:
            # Check all paths in baseline
            paths_to_check = list(set([os.path.dirname(p) for p in self.baseline.keys()]))
        elif isinstance(paths, str):
            paths_to_check = [paths]
        else:
            paths_to_check = paths
        
        print("\nChecking integrity...")
        
        # Get current state
        current_files = []
        for path in paths_to_check:
            current_files.extend(self.scan_directory(path, recursive=True))
        
        current_files = set(current_files)
        baseline_files = set(self.baseline.keys())
        
        # Find changes
        new_files = current_files - baseline_files
        deleted_files = baseline_files - current_files
        common_files = current_files & baseline_files
        
        print(f"Checking {len(common_files)} existing files...")
        
        modified_files = []
        for filepath in common_files:
            current_metadata = self.get_file_metadata(filepath)
            
            if 'error' in current_metadata:
                continue
            
            baseline_metadata = self.baseline[filepath]
            
            # Check for changes
            if current_metadata['hash'] != baseline_metadata['hash']:
                change = {
                    'file': filepath,
                    'type': 'modified',
                    'baseline_hash': baseline_metadata['hash'],
                    'current_hash': current_metadata['hash'],
                    'baseline_mtime': baseline_metadata['mtime_human'],
                    'current_mtime': current_metadata['mtime_human'],
                    'size_change': current_metadata['size'] - baseline_metadata['size']
                }
                modified_files.append(change)
                self.changes['modified'].append(change)
        
        # Record new and deleted files
        for filepath in new_files:
            metadata = self.get_file_metadata(filepath)
            change = {
                'file': filepath,
                'type': 'new',
                'created': metadata.get('mtime_human', 'Unknown'),
                'size': metadata.get('size', 0)
            }
            self.changes['new'].append(change)
        
        for filepath in deleted_files:
            change = {
                'file': filepath,
                'type': 'deleted',
                'baseline_hash': self.baseline[filepath]['hash']
            }
            self.changes['deleted'].append(change)
        
        # Print report
        self.print_report(new_files, deleted_files, modified_files)
        
        return len(new_files) + len(deleted_files) + len(modified_files) > 0
    
    def print_report(self, new_files, deleted_files, modified_files):
        """Print integrity check report"""
        print("\n" + "="*70)
        print(" FILE INTEGRITY CHECK REPORT")
        print("="*70)
        
        if modified_files:
            print(f"\n[MODIFIED FILES: {len(modified_files)}]")
            print("-" * 70)
            for change in modified_files[:50]:  # Limit output
                print(f"\n  File: {change['file']}")
                print(f"  Modified: {change['current_mtime']}")
                print(f"  Hash changed: {change['baseline_hash'][:16]}... -> {change['current_hash'][:16]}...")
                print(f"  Size change: {change['size_change']:+d} bytes")
            if len(modified_files) > 50:
                print(f"\n  ... and {len(modified_files) - 50} more modified files")
        
        if new_files:
            print(f"\n[NEW FILES: {len(new_files)}]")
            print("-" * 70)
            for filepath in list(new_files)[:30]:
                print(f"  + {filepath}")
            if len(new_files) > 30:
                print(f"  ... and {len(new_files) - 30} more new files")
        
        if deleted_files:
            print(f"\n[DELETED FILES: {len(deleted_files)}]")
            print("-" * 70)
            for filepath in list(deleted_files)[:30]:
                print(f"  - {filepath}")
            if len(deleted_files) > 30:
                print(f"  ... and {len(deleted_files) - 30} more deleted files")
        
        if not modified_files and not new_files and not deleted_files:
            print("\n✓ No changes detected - System integrity verified")
        else:
            print("\n⚠ WARNING: Changes detected!")
            print(f"\nSummary:")
            print(f"  Modified: {len(modified_files)}")
            print(f"  New:      {len(new_files)}")
            print(f"  Deleted:  {len(deleted_files)}")
        
        print("\n" + "="*70)
    
    def export_changes(self, filename='fim_changes_windows.json'):
        """Export detected changes to JSON"""
        output = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'changes': dict(self.changes)
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\nChanges exported to {filename}")
    
    def monitor_continuous(self, interval=60):
        """Continuously monitor for changes"""
        import time
        
        print(f"Starting continuous monitoring (checking every {interval} seconds)")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Checking integrity...")
                
                changes_detected = self.check_integrity()
                
                if changes_detected:
                    # Export changes
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    self.export_changes(f'fim_changes_{timestamp}.json')
                
                print(f"\nNext check in {interval} seconds...")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user")

def main():
    parser = argparse.ArgumentParser(
        description='Windows File Integrity Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create initial baseline
  python fim_windows.py --create-baseline
  
  # Check for changes
  python fim_windows.py --check
  
  # Monitor specific directory
  python fim_windows.py --create-baseline --path "C:\\Important Files"
  python fim_windows.py --check --path "C:\\Important Files"
  
  # Continuous monitoring
  python fim_windows.py --monitor --interval 60
  
  # Export changes
  python fim_windows.py --check --export changes.json

Note: Run as Administrator for full system access.
        """
    )
    
    parser.add_argument('--create-baseline', action='store_true',
                       help='Create new baseline')
    parser.add_argument('--check', action='store_true',
                       help='Check integrity against baseline')
    parser.add_argument('--monitor', action='store_true',
                       help='Continuous monitoring mode')
    parser.add_argument('--path', type=str,
                       help='Specific path to monitor (default: system paths)')
    parser.add_argument('--baseline-file', type=str, default='fim_baseline_windows.json',
                       help='Baseline file path')
    parser.add_argument('--export', type=str, metavar='FILE',
                       help='Export changes to JSON file')
    parser.add_argument('--interval', type=int, default=60,
                       help='Check interval in seconds for monitoring mode')
    parser.add_argument('--no-recursive', action='store_true',
                       help='Do not scan directories recursively')
    
    args = parser.parse_args()
    
    # Check if running on Windows
    if sys.platform != 'win32':
        print("Error: This script is designed for Windows systems only.")
        print("For Linux systems, use fim.py instead.")
        sys.exit(1)
    
    fim = WindowsFileIntegrityMonitor(baseline_file=args.baseline_file)
    
    paths = None
    if args.path:
        paths = [args.path]
    
    if args.create_baseline:
        fim.create_baseline(paths=paths, recursive=not args.no_recursive)
    elif args.check:
        changes_detected = fim.check_integrity(paths=paths)
        if args.export:
            fim.export_changes(args.export)
        sys.exit(0 if not changes_detected else 1)
    elif args.monitor:
        if not fim.load_baseline():
            print("\nCreating initial baseline for monitoring...")
            fim.create_baseline(paths=paths, recursive=not args.no_recursive)
        fim.monitor_continuous(interval=args.interval)
    else:
        parser.print_help()
        print("\nPlease specify --create-baseline, --check, or --monitor")
        sys.exit(1)

if __name__ == '__main__':
    main()
