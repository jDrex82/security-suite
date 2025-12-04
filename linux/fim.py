#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
Detects unauthorized changes to critical system files and directories
Perfect for security monitoring, compliance, and intrusion detection
"""

import os
import sys
import json
import hashlib
import argparse
import stat
from pathlib import Path
from datetime import datetime
from collections import defaultdict

class FileIntegrityMonitor:
    def __init__(self, baseline_file='fim_baseline.json', config_file=None):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.config_file = config_file
        self.changes = defaultdict(list)
        
        # Critical system files and directories to monitor by default
        self.default_paths = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/sudoers',
            '/etc/ssh/sshd_config',
            '/etc/hosts',
            '/etc/crontab',
            '/etc/systemd/system',
            '/root/.ssh/authorized_keys',
        ]
    
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
        """Get comprehensive file metadata"""
        try:
            stats = os.stat(filepath)
            return {
                'path': str(filepath),
                'size': stats.st_size,
                'mode': oct(stats.st_mode),
                'permissions': stat.filemode(stats.st_mode),
                'uid': stats.st_uid,
                'gid': stats.st_gid,
                'mtime': stats.st_mtime,
                'mtime_human': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'is_suid': bool(stats.st_mode & stat.S_ISUID),
                'is_sgid': bool(stats.st_mode & stat.S_ISGID),
                'is_sticky': bool(stats.st_mode & stat.S_ISVTX),
                'hash': self.calculate_hash(filepath)
            }
        except (PermissionError, FileNotFoundError, OSError) as e:
            return {
                'path': str(filepath),
                'error': str(e)
            }
    
    def scan_directory(self, directory, recursive=True, max_depth=3):
        """Recursively scan directory for files"""
        files = []
        try:
            path = Path(directory)
            if not path.exists():
                print(f"Warning: {directory} does not exist")
                return files
            
            if path.is_file():
                files.append(str(path))
                return files
            
            if recursive:
                for item in path.rglob('*'):
                    if item.is_file():
                        # Check depth
                        depth = len(item.relative_to(path).parts)
                        if depth <= max_depth:
                            files.append(str(item))
            else:
                for item in path.iterdir():
                    if item.is_file():
                        files.append(str(item))
        
        except PermissionError:
            print(f"Warning: Permission denied accessing {directory}")
        except Exception as e:
            print(f"Warning: Error scanning {directory}: {e}")
        
        return files
    
    def create_baseline(self, paths=None, recursive=True):
        """Create a baseline snapshot of file integrity"""
        if paths is None:
            paths = self.default_paths
        
        print(f"\n{'='*70}")
        print("Creating File Integrity Baseline")
        print(f"{'='*70}\n")
        
        all_files = []
        for path in paths:
            if os.path.isdir(path):
                print(f"📁 Scanning directory: {path}")
                files = self.scan_directory(path, recursive=recursive)
                all_files.extend(files)
            elif os.path.isfile(path):
                print(f"📄 Adding file: {path}")
                all_files.append(path)
            else:
                print(f"⚠️  Path not found: {path}")
        
        print(f"\nProcessing {len(all_files)} files...")
        
        baseline = {
            'created': datetime.now().isoformat(),
            'paths_monitored': paths,
            'files': {}
        }
        
        for filepath in all_files:
            metadata = self.get_file_metadata(filepath)
            if 'error' not in metadata:
                baseline['files'][filepath] = metadata
                if metadata.get('is_suid') or metadata.get('is_sgid'):
                    print(f"🔐 SUID/SGID detected: {filepath}")
        
        # Save baseline
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(baseline, f, indent=2)
            print(f"\n✅ Baseline created successfully!")
            print(f"📊 Files monitored: {len(baseline['files'])}")
            print(f"💾 Baseline saved to: {self.baseline_file}")
        except Exception as e:
            print(f"\n❌ Error saving baseline: {e}")
            return False
        
        return True
    
    def load_baseline(self):
        """Load baseline from file"""
        try:
            with open(self.baseline_file, 'r') as f:
                self.baseline = json.load(f)
            return True
        except FileNotFoundError:
            print(f"❌ Baseline file not found: {self.baseline_file}")
            print("   Run with --create-baseline first")
            return False
        except json.JSONDecodeError:
            print(f"❌ Invalid baseline file format")
            return False
    
    def check_integrity(self, verbose=False):
        """Check current state against baseline"""
        if not self.baseline:
            if not self.load_baseline():
                return False
        
        print(f"\n{'='*70}")
        print("File Integrity Check")
        print(f"{'='*70}")
        print(f"Baseline created: {self.baseline.get('created', 'Unknown')}")
        print(f"Files in baseline: {len(self.baseline.get('files', {}))}")
        print(f"{'='*70}\n")
        
        baseline_files = self.baseline.get('files', {})
        current_files = set()
        
        changes_detected = False
        
        # Check each file in baseline
        for filepath, baseline_data in baseline_files.items():
            current_files.add(filepath)
            current_data = self.get_file_metadata(filepath)
            
            if 'error' in current_data:
                if 'No such file' in current_data['error']:
                    print(f"🗑️  DELETED: {filepath}")
                    self.changes['deleted'].append({
                        'path': filepath,
                        'baseline': baseline_data
                    })
                    changes_detected = True
                elif verbose:
                    print(f"⚠️  Cannot access: {filepath} - {current_data['error']}")
                continue
            
            # Check hash
            if current_data['hash'] != baseline_data['hash']:
                print(f"⚠️  MODIFIED: {filepath}")
                print(f"   Old hash: {baseline_data['hash'][:16]}...")
                print(f"   New hash: {current_data['hash'][:16]}...")
                print(f"   Modified: {current_data['mtime_human']}")
                self.changes['modified'].append({
                    'path': filepath,
                    'baseline': baseline_data,
                    'current': current_data
                })
                changes_detected = True
            
            # Check permissions
            if current_data['permissions'] != baseline_data['permissions']:
                print(f"🔑 PERMISSIONS CHANGED: {filepath}")
                print(f"   Old: {baseline_data['permissions']}")
                print(f"   New: {current_data['permissions']}")
                self.changes['permissions'].append({
                    'path': filepath,
                    'old': baseline_data['permissions'],
                    'new': current_data['permissions']
                })
                changes_detected = True
            
            # Check ownership
            if current_data['uid'] != baseline_data['uid'] or current_data['gid'] != baseline_data['gid']:
                print(f"👤 OWNERSHIP CHANGED: {filepath}")
                print(f"   Old UID/GID: {baseline_data['uid']}/{baseline_data['gid']}")
                print(f"   New UID/GID: {current_data['uid']}/{current_data['gid']}")
                self.changes['ownership'].append({
                    'path': filepath,
                    'old_uid': baseline_data['uid'],
                    'old_gid': baseline_data['gid'],
                    'new_uid': current_data['uid'],
                    'new_gid': current_data['gid']
                })
                changes_detected = True
            
            # Check SUID/SGID changes
            if current_data['is_suid'] != baseline_data['is_suid']:
                print(f"🚨 SUID BIT CHANGED: {filepath}")
                print(f"   Old: {baseline_data['is_suid']} → New: {current_data['is_suid']}")
                self.changes['suid'].append({
                    'path': filepath,
                    'enabled': current_data['is_suid']
                })
                changes_detected = True
            
            if current_data['is_sgid'] != baseline_data['is_sgid']:
                print(f"🚨 SGID BIT CHANGED: {filepath}")
                print(f"   Old: {baseline_data['is_sgid']} → New: {current_data['is_sgid']}")
                self.changes['sgid'].append({
                    'path': filepath,
                    'enabled': current_data['is_sgid']
                })
                changes_detected = True
        
        # Check for new files in monitored directories
        for path in self.baseline.get('paths_monitored', []):
            if os.path.isdir(path):
                current_scan = self.scan_directory(path, recursive=True)
                for filepath in current_scan:
                    if filepath not in baseline_files:
                        print(f"➕ NEW FILE: {filepath}")
                        metadata = self.get_file_metadata(filepath)
                        self.changes['new'].append({
                            'path': filepath,
                            'metadata': metadata
                        })
                        if metadata.get('is_suid') or metadata.get('is_sgid'):
                            print(f"   ⚠️  WARNING: New file has SUID/SGID bit set!")
                        changes_detected = True
        
        # Summary
        print(f"\n{'='*70}")
        print("SUMMARY")
        print(f"{'='*70}")
        
        if not changes_detected:
            print("✅ No changes detected - System integrity maintained!")
        else:
            print("⚠️  CHANGES DETECTED:")
            if self.changes['modified']:
                print(f"   Modified files: {len(self.changes['modified'])}")
            if self.changes['deleted']:
                print(f"   Deleted files: {len(self.changes['deleted'])}")
            if self.changes['new']:
                print(f"   New files: {len(self.changes['new'])}")
            if self.changes['permissions']:
                print(f"   Permission changes: {len(self.changes['permissions'])}")
            if self.changes['ownership']:
                print(f"   Ownership changes: {len(self.changes['ownership'])}")
            if self.changes['suid'] or self.changes['sgid']:
                print(f"   SUID/SGID changes: {len(self.changes['suid']) + len(self.changes['sgid'])}")
        
        return not changes_detected
    
    def find_suid_sgid(self, paths=None):
        """Find all SUID/SGID files in system"""
        if paths is None:
            paths = ['/usr', '/bin', '/sbin', '/opt']
        
        print(f"\n{'='*70}")
        print("SUID/SGID File Scanner")
        print(f"{'='*70}\n")
        print("Searching for files with SUID/SGID bits set...")
        print("These files run with elevated privileges and are common attack vectors.\n")
        
        suid_files = []
        sgid_files = []
        
        for path in paths:
            if not os.path.exists(path):
                continue
            
            print(f"📁 Scanning: {path}")
            files = self.scan_directory(path, recursive=True, max_depth=5)
            
            for filepath in files:
                metadata = self.get_file_metadata(filepath)
                if 'error' not in metadata:
                    if metadata['is_suid']:
                        suid_files.append(metadata)
                    if metadata['is_sgid']:
                        sgid_files.append(metadata)
        
        print(f"\n{'='*70}")
        print("RESULTS")
        print(f"{'='*70}\n")
        
        if suid_files:
            print(f"🔐 SUID Files Found ({len(suid_files)}):")
            for f in suid_files:
                print(f"   {f['path']}")
                print(f"      Permissions: {f['permissions']}")
                print(f"      Owner UID: {f['uid']}")
        
        if sgid_files:
            print(f"\n🔐 SGID Files Found ({len(sgid_files)}):")
            for f in sgid_files:
                print(f"   {f['path']}")
                print(f"      Permissions: {f['permissions']}")
                print(f"      Group GID: {f['gid']}")
        
        if not suid_files and not sgid_files:
            print("✅ No SUID/SGID files found in scanned paths")
        
        return suid_files, sgid_files
    
    def export_report(self, output_file='fim_report.json'):
        """Export changes to JSON report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'baseline_file': self.baseline_file,
            'baseline_created': self.baseline.get('created', 'Unknown'),
            'changes': dict(self.changes)
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n📄 Report exported to: {output_file}")
            return True
        except Exception as e:
            print(f"\n❌ Error exporting report: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(
        description='File Integrity Monitor - Detect unauthorized system changes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --create-baseline                    # Create initial baseline
  %(prog)s --check                              # Check for changes
  %(prog)s --check --verbose                    # Detailed check
  %(prog)s --find-suid                          # Find SUID/SGID files
  %(prog)s --create-baseline --paths /etc /usr/local  # Custom paths
  %(prog)s --check --export report.json         # Export changes
  
Security Use Cases:
  - Detect rootkit installations
  - Monitor configuration file tampering
  - Track unauthorized privilege escalation
  - Compliance auditing (HIPAA, PCI-DSS)
  - Incident response and forensics
        """
    )
    
    parser.add_argument('-b', '--baseline',
                       default='fim_baseline.json',
                       help='Baseline file path (default: fim_baseline.json)')
    
    parser.add_argument('--create-baseline',
                       action='store_true',
                       help='Create new baseline snapshot')
    
    parser.add_argument('--check',
                       action='store_true',
                       help='Check current state against baseline')
    
    parser.add_argument('--find-suid',
                       action='store_true',
                       help='Find all SUID/SGID files')
    
    parser.add_argument('-p', '--paths',
                       nargs='+',
                       help='Custom paths to monitor')
    
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Verbose output')
    
    parser.add_argument('-e', '--export',
                       help='Export changes to JSON file')
    
    parser.add_argument('--no-recursive',
                       action='store_true',
                       help='Disable recursive directory scanning')
    
    args = parser.parse_args()
    
    # Create monitor instance
    fim = FileIntegrityMonitor(baseline_file=args.baseline)
    
    # Execute requested operation
    if args.create_baseline:
        paths = args.paths if args.paths else None
        fim.create_baseline(paths=paths, recursive=not args.no_recursive)
    
    elif args.check:
        success = fim.check_integrity(verbose=args.verbose)
        if args.export:
            fim.export_report(args.export)
        sys.exit(0 if success else 1)
    
    elif args.find_suid:
        paths = args.paths if args.paths else None
        fim.find_suid_sgid(paths=paths)
    
    else:
        parser.print_help()
        print("\n💡 Tip: Start with --create-baseline to create an initial snapshot")

if __name__ == '__main__':
    main()
