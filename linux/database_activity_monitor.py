#!/usr/bin/env python3
"""
Database Activity Monitor (DAM)
Monitors database logs for suspicious queries, SQL injection attempts, and unauthorized access
Critical for protecting PHI, PII, and financial data - HIPAA/PCI-DSS compliance
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

class DatabaseActivityMonitor:
    def __init__(self, baseline_file='dam_baseline.json'):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.alerts = defaultdict(list)
        self.severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        # Dangerous SQL patterns
        self.dangerous_patterns = [
            # DDL operations
            (r'\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX|USER)\b', 'DROP command', 'CRITICAL'),
            (r'\bTRUNCATE\s+TABLE\b', 'TRUNCATE command', 'CRITICAL'),
            (r'\bALTER\s+TABLE\b', 'ALTER TABLE command', 'HIGH'),
            (r'\bCREATE\s+USER\b', 'User creation', 'HIGH'),
            (r'\bGRANT\s+ALL\b', 'Grant all privileges', 'HIGH'),
            
            # SQL Injection patterns
            (r"('\s*OR\s*'1'\s*=\s*'1|'\s*OR\s*1\s*=\s*1)", 'SQL injection attempt', 'CRITICAL'),
            (r'\bUNION\s+SELECT\b', 'UNION SELECT (potential SQLi)', 'CRITICAL'),
            (r';\s*DROP\s+TABLE', 'Chained DROP command', 'CRITICAL'),
            (r'--\s*$', 'SQL comment injection', 'HIGH'),
            (r'/\*.*\*/', 'SQL comment bypass', 'HIGH'),
            (r'\bEXEC\s*\(', 'Dynamic SQL execution', 'HIGH'),
            (r'xp_cmdshell', 'Command execution attempt', 'CRITICAL'),
            
            # Data exfiltration
            (r'SELECT\s+\*\s+FROM\s+\w+\s+LIMIT\s+\d{4,}', 'Large SELECT query', 'HIGH'),
            (r'SELECT.*INTO\s+OUTFILE', 'Data export attempt', 'CRITICAL'),
            (r'LOAD_FILE\s*\(', 'File read attempt', 'HIGH'),
            
            # Authentication attacks
            (r'SELECT.*FROM.*users.*WHERE.*password', 'Password query', 'HIGH'),
            (r'SELECT.*FROM.*user.*WHERE.*passwd', 'Password query variant', 'HIGH'),
            
            # Privilege escalation
            (r'\bUPDATE\s+mysql\.user\b', 'MySQL user table modification', 'CRITICAL'),
            (r'\bSET\s+PASSWORD\b', 'Password change', 'MEDIUM'),
            
            # Time-based blind SQLi
            (r'\bSLEEP\s*\(\d+\)', 'Time delay (blind SQLi)', 'HIGH'),
            (r'\bBENCHMARK\s*\(', 'Benchmark function (blind SQLi)', 'HIGH'),
        ]
        
        # Database log paths
        self.log_paths = {
            'mysql': [
                '/var/log/mysql/mysql.log',
                '/var/log/mysql/error.log',
                '/var/log/mysql/mysql-slow.log',
                '/var/lib/mysql/*.log',
            ],
            'postgresql': [
                '/var/log/postgresql/postgresql-*.log',
                '/var/lib/postgresql/data/log/*.log',
            ],
            'mssql': [
                '/var/opt/mssql/log/errorlog',
                'C:\\Program Files\\Microsoft SQL Server\\*\\MSSQL\\Log\\ERRORLOG',
            ],
            'mariadb': [
                '/var/log/mysql/error.log',
                '/var/log/mariadb/mariadb.log',
            ]
        }
        
        # Suspicious query thresholds
        self.thresholds = {
            'max_query_length': 5000,  # Characters
            'max_rows_selected': 10000,  # Rows
            'max_queries_per_minute': 100,  # Per user
            'max_failed_auth': 5,  # Per user per hour
            'max_schema_changes': 3,  # Per hour
        }
        
        # Track query statistics
        self.query_stats = defaultdict(lambda: {
            'count': 0,
            'users': set(),
            'databases': set(),
            'tables': set(),
            'last_seen': None
        })
        
    def find_database_logs(self):
        """Find all available database log files"""
        found_logs = []
        
        for db_type, paths in self.log_paths.items():
            for pattern in paths:
                # Handle glob patterns
                if '*' in pattern:
                    try:
                        from glob import glob
                        matches = glob(pattern)
                        for match in matches:
                            if os.path.exists(match) and os.path.isfile(match):
                                found_logs.append({
                                    'type': db_type,
                                    'path': match,
                                    'size': os.path.getsize(match)
                                })
                    except Exception as e:
                        continue
                else:
                    if os.path.exists(pattern) and os.path.isfile(pattern):
                        found_logs.append({
                            'type': db_type,
                            'path': pattern,
                            'size': os.path.getsize(pattern)
                        })
        
        return found_logs
    
    def parse_mysql_log(self, log_file):
        """Parse MySQL/MariaDB log files"""
        entries = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # MySQL query log format: timestamp thread_id command query
                    # Example: 2024-12-04T10:15:30.123456Z 5 Query SELECT * FROM users
                    
                    # Match query lines
                    if 'Query' in line or 'Execute' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            timestamp = parts[0] if parts[0].count(':') >= 2 else None
                            query = ' '.join(parts[3:]) if len(parts) > 3 else ''
                            
                            if query:
                                entries.append({
                                    'timestamp': timestamp or datetime.now().isoformat(),
                                    'database': 'mysql',
                                    'user': 'unknown',
                                    'query': query,
                                    'source': log_file
                                })
                    
                    # Match authentication failures
                    if 'Access denied' in line or 'Failed login' in line:
                        entries.append({
                            'timestamp': datetime.now().isoformat(),
                            'database': 'mysql',
                            'user': 'unknown',
                            'query': line.strip(),
                            'source': log_file,
                            'type': 'auth_failure'
                        })
        
        except Exception as e:
            print(f"Warning: Error parsing MySQL log {log_file}: {e}")
        
        return entries
    
    def parse_postgresql_log(self, log_file):
        """Parse PostgreSQL log files"""
        entries = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # PostgreSQL log format varies, but typically:
                    # timestamp [pid] user@database LOG: statement: query
                    
                    if 'statement:' in line.lower() or 'query:' in line.lower():
                        # Extract query
                        if 'statement:' in line.lower():
                            query = line.split('statement:', 1)[1].strip()
                        else:
                            query = line.split('query:', 1)[1].strip()
                        
                        # Extract user and database if possible
                        user_match = re.search(r'user=(\w+)', line)
                        db_match = re.search(r'database=(\w+)', line)
                        
                        entries.append({
                            'timestamp': datetime.now().isoformat(),
                            'database': 'postgresql',
                            'user': user_match.group(1) if user_match else 'unknown',
                            'db_name': db_match.group(1) if db_match else 'unknown',
                            'query': query,
                            'source': log_file
                        })
                    
                    # Authentication failures
                    if 'FATAL' in line and 'authentication' in line.lower():
                        entries.append({
                            'timestamp': datetime.now().isoformat(),
                            'database': 'postgresql',
                            'user': 'unknown',
                            'query': line.strip(),
                            'source': log_file,
                            'type': 'auth_failure'
                        })
        
        except Exception as e:
            print(f"Warning: Error parsing PostgreSQL log {log_file}: {e}")
        
        return entries
    
    def analyze_query(self, entry):
        """Analyze a database query for threats"""
        query = entry.get('query', '')
        alerts = []
        
        # Check for dangerous patterns
        for pattern, description, severity in self.dangerous_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                alerts.append({
                    'severity': severity,
                    'description': description,
                    'query': query[:200],  # Truncate long queries
                    'user': entry.get('user', 'unknown'),
                    'database': entry.get('database', 'unknown'),
                    'timestamp': entry.get('timestamp', datetime.now().isoformat()),
                    'source': entry.get('source', 'unknown')
                })
                self.severity_counts[severity] += 1
        
        # Check query length
        if len(query) > self.thresholds['max_query_length']:
            alerts.append({
                'severity': 'MEDIUM',
                'description': f'Extremely long query ({len(query)} chars)',
                'query': query[:200],
                'user': entry.get('user', 'unknown'),
                'database': entry.get('database', 'unknown'),
                'timestamp': entry.get('timestamp', datetime.now().isoformat())
            })
            self.severity_counts['MEDIUM'] += 1
        
        # Track query statistics
        query_type = query.split()[0].upper() if query.split() else 'UNKNOWN'
        self.query_stats[query_type]['count'] += 1
        self.query_stats[query_type]['users'].add(entry.get('user', 'unknown'))
        self.query_stats[query_type]['last_seen'] = entry.get('timestamp')
        
        return alerts
    
    def detect_auth_failures(self, entries):
        """Detect authentication brute force attempts"""
        auth_failures = defaultdict(list)
        
        for entry in entries:
            if entry.get('type') == 'auth_failure':
                user = entry.get('user', 'unknown')
                timestamp = entry.get('timestamp', datetime.now().isoformat())
                auth_failures[user].append(timestamp)
        
        # Check for brute force
        for user, timestamps in auth_failures.items():
            if len(timestamps) >= self.thresholds['max_failed_auth']:
                self.alerts['auth_brute_force'].append({
                    'severity': 'HIGH',
                    'description': f'Multiple failed authentication attempts',
                    'user': user,
                    'count': len(timestamps),
                    'first_seen': timestamps[0] if timestamps else 'unknown',
                    'last_seen': timestamps[-1] if timestamps else 'unknown'
                })
                self.severity_counts['HIGH'] += 1
    
    def detect_after_hours_access(self, entries):
        """Detect after-hours database access"""
        after_hours_threshold = 22  # 10 PM
        before_hours_threshold = 6  # 6 AM
        
        for entry in entries:
            try:
                timestamp = datetime.fromisoformat(entry.get('timestamp', '').replace('Z', '+00:00'))
                hour = timestamp.hour
                
                if hour >= after_hours_threshold or hour < before_hours_threshold:
                    self.alerts['after_hours'].append({
                        'severity': 'MEDIUM',
                        'description': 'After-hours database access',
                        'user': entry.get('user', 'unknown'),
                        'time': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                        'query': entry.get('query', '')[:100]
                    })
                    self.severity_counts['MEDIUM'] += 1
            except Exception:
                continue
    
    def scan(self, log_limit_mb=50):
        """Scan database logs for suspicious activity"""
        print(f"\n{'='*70}")
        print("DATABASE ACTIVITY MONITOR - Scan Started")
        print(f"{'='*70}\n")
        
        # Find database logs
        print("[*] Discovering database log files...")
        found_logs = self.find_database_logs()
        
        if not found_logs:
            print("[!] No database log files found")
            print("[!] Ensure database logging is enabled and check permissions")
            return
        
        print(f"[+] Found {len(found_logs)} database log file(s)")
        for log in found_logs:
            size_mb = log['size'] / (1024 * 1024)
            print(f"    • {log['type']}: {log['path']} ({size_mb:.2f} MB)")
        
        # Parse log files
        all_entries = []
        print("\n[*] Parsing database logs...")
        
        for log in found_logs:
            if log['size'] > log_limit_mb * 1024 * 1024:
                print(f"[!] Skipping {log['path']} (exceeds {log_limit_mb}MB limit)")
                continue
            
            print(f"[*] Parsing {log['type']} log: {log['path']}")
            
            if log['type'] in ['mysql', 'mariadb']:
                entries = self.parse_mysql_log(log['path'])
            elif log['type'] == 'postgresql':
                entries = self.parse_postgresql_log(log['path'])
            else:
                continue
            
            all_entries.extend(entries)
            print(f"    • Found {len(entries)} database operations")
        
        print(f"\n[+] Total database operations: {len(all_entries)}")
        
        # Analyze queries
        print("\n[*] Analyzing queries for threats...")
        for entry in all_entries:
            query_alerts = self.analyze_query(entry)
            for alert in query_alerts:
                self.alerts['dangerous_queries'].append(alert)
        
        # Detect authentication failures
        print("[*] Checking for authentication brute force...")
        self.detect_auth_failures(all_entries)
        
        # Detect after-hours access
        print("[*] Checking for after-hours access...")
        self.detect_after_hours_access(all_entries)
        
        return self.alerts
    
    def create_baseline(self):
        """Create baseline of normal database activity"""
        print(f"\n{'='*70}")
        print("DATABASE ACTIVITY MONITOR - Creating Baseline")
        print(f"{'='*70}\n")
        
        logs = self.find_database_logs()
        if not logs:
            print("[!] No database logs found to create baseline")
            return False
        
        baseline_data = {
            'timestamp': datetime.now().isoformat(),
            'databases_monitored': [log['type'] for log in logs],
            'log_files': [log['path'] for log in logs],
            'query_types': {},
            'users': set(),
            'peak_hours': {}
        }
        
        # Parse recent logs for baseline
        all_entries = []
        for log in logs[:3]:  # Limit to first 3 logs
            if log['type'] in ['mysql', 'mariadb']:
                entries = self.parse_mysql_log(log['path'])
            elif log['type'] == 'postgresql':
                entries = self.parse_postgresql_log(log['path'])
            else:
                continue
            all_entries.extend(entries)
        
        # Build baseline statistics
        query_types = Counter()
        users = set()
        
        for entry in all_entries:
            query = entry.get('query', '')
            query_type = query.split()[0].upper() if query.split() else 'UNKNOWN'
            query_types[query_type] += 1
            users.add(entry.get('user', 'unknown'))
        
        baseline_data['query_types'] = dict(query_types)
        baseline_data['users'] = list(users)
        
        # Save baseline
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)
        
        print(f"[+] Baseline created: {self.baseline_file}")
        print(f"[+] Monitored {len(logs)} database log files")
        print(f"[+] Tracked {len(all_entries)} operations")
        print(f"[+] Query types: {dict(query_types)}")
        print(f"[+] Users: {list(users)}")
        
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
        
        if self.query_stats:
            print(f"\nQuery Statistics:")
            for query_type, stats in sorted(self.query_stats.items()):
                print(f"  {query_type}: {stats['count']} queries by {len(stats['users'])} user(s)")
        
        if total_alerts == 0:
            print("\n✓ No suspicious database activity detected")
        else:
            print(f"\n⚠ {total_alerts} potential threats detected")
            
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
            },
            'alerts': dict(self.alerts),
            'query_statistics': {k: {
                'count': v['count'],
                'users': list(v['users']),
                'databases': list(v['databases']),
                'last_seen': v['last_seen']
            } for k, v in self.query_stats.items()}
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Results exported to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Database Activity Monitor - Detect SQL injection, data exfiltration, and unauthorized access',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create baseline
  python3 database_activity_monitor.py --baseline
  
  # Run scan
  python3 database_activity_monitor.py --scan
  
  # Run scan and export results
  python3 database_activity_monitor.py --scan --export dam_results.json
  
  # Continuous monitoring (24 hours, check every 10 minutes)
  python3 database_activity_monitor.py --monitor --duration 86400 --interval 600
        """
    )
    
    parser.add_argument('--baseline', action='store_true',
                       help='Create baseline of normal database activity')
    parser.add_argument('--scan', action='store_true',
                       help='Scan database logs once')
    parser.add_argument('--monitor', action='store_true',
                       help='Continuous monitoring mode')
    parser.add_argument('--duration', type=int, default=3600,
                       help='Monitoring duration in seconds (default: 3600)')
    parser.add_argument('--interval', type=int, default=300,
                       help='Monitoring interval in seconds (default: 300)')
    parser.add_argument('--export', type=str,
                       help='Export results to JSON file')
    parser.add_argument('--baseline-file', type=str, default='dam_baseline.json',
                       help='Baseline file path (default: dam_baseline.json)')
    
    args = parser.parse_args()
    
    if not any([args.baseline, args.scan, args.monitor]):
        parser.print_help()
        sys.exit(1)
    
    monitor = DatabaseActivityMonitor(baseline_file=args.baseline_file)
    
    if args.baseline:
        monitor.create_baseline()
    
    elif args.scan:
        monitor.scan()
        monitor.print_summary()
        
        if args.export:
            monitor.export_results(args.export)
    
    elif args.monitor:
        print(f"\n{'='*70}")
        print("DATABASE ACTIVITY MONITOR - Continuous Monitoring")
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
                monitor.query_stats = defaultdict(lambda: {
                    'count': 0,
                    'users': set(),
                    'databases': set(),
                    'tables': set(),
                    'last_seen': None
                })
                
                print(f"\n[*] Sleeping {args.interval} seconds...")
                time.sleep(args.interval)
        
        except KeyboardInterrupt:
            print("\n\n[!] Monitoring stopped by user")
            print(f"[*] Total iterations: {iteration}")

if __name__ == '__main__':
    main()
