#!/usr/bin/env python3
"""
Real-Time Login Anomaly Detection - PCAP Integration
Processes PCAP files and detects anomalies using ML

This bridges PCAP reader → ML detector
Author: John Drexler
"""

import json
import sys
import os
from datetime import datetime

# Import PCAP reader
from pcap_reader import PCAPReader

# Import enhanced ML detector
try:
    from enhanced_detector import EnhancedLoginDetector as LoginAnomalyDetector
except ImportError:
    # Fallback to base detector
    sys.path.insert(0, '/mnt/user-data/uploads')
    try:
        from login_anomaly_detector_ml import LoginAnomalyDetector
        print("[WARNING] Using base detector. For better PCAP detection, use enhanced_detector.py")
    except ImportError:
        print("[ERROR] Could not import ML detector")
        sys.exit(1)


def process_pcap_for_anomalies(pcap_file, baseline_days=7):
    """
    Complete pipeline: PCAP → Events → ML Detection → Alerts
    
    Args:
        pcap_file: Path to PCAP file
        baseline_days: Days of baseline training data
    
    Returns:
        alerts: List of detected anomalies
    """
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║              REAL-TIME LOGIN ANOMALY DETECTION - PCAP MODE                   ║
║                    PCAP Reader + ML Detector Integration                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Step 1: Read PCAP and extract login events
    print("[STEP 1: PCAP INGESTION]")
    print(f"[*] Reading PCAP file: {pcap_file}")
    
    reader = PCAPReader(pcap_file)
    packet_count = reader.read_pcap()
    print(f"[+] Parsed {packet_count} total packets")
    print(f"[+] Found {len(reader.packets)} login-related packets")
    
    print("\n[*] Extracting login events from packets...")
    events = reader.extract_login_events()
    print(f"[+] Extracted {len(events)} login events")
    
    if not events:
        print("[!] No login events found in PCAP. Nothing to analyze.")
        return []
    
    # Display protocol breakdown
    from collections import defaultdict
    protocols = defaultdict(int)
    for e in events:
        protocols[e['protocol']] += 1
    
    print("\nProtocol Breakdown:")
    for proto, count in protocols.items():
        print(f"  {proto}: {count} events")
    
    # Step 2: Split data into baseline (training) and test sets
    print("\n[STEP 2: BASELINE TRAINING]")
    
    # Sort events by time
    events.sort(key=lambda x: x['timestamp'])
    
    # Use first 70% as baseline, rest as test
    split_point = int(len(events) * 0.7)
    baseline_events = events[:split_point]
    test_events = events[split_point:]
    
    print(f"[*] Baseline events (training): {len(baseline_events)}")
    print(f"[*] Test events (detection): {len(test_events)}")
    
    if len(baseline_events) < 10:
        print("[!] Insufficient baseline data. Need at least 10 events.")
        print("[*] Using all events as test data instead...")
        baseline_events = reader.generate_synthetic_baseline(num_users=5, days=7)
        test_events = events
    
    # Step 3: Train ML model on baseline
    detector = LoginAnomalyDetector()
    detector.train_baseline(baseline_events)
    
    # Step 4: Run anomaly detection on test events
    print("\n[STEP 3: ANOMALY DETECTION]")
    print("[*] Analyzing login events for anomalies...\n")
    
    alerts = []
    for i, event in enumerate(test_events):
        is_anomaly, score, reasons = detector.detect_anomaly(event)
        
        if is_anomaly:
            severity = "CRITICAL" if score > 0.75 else "HIGH" if score > 0.60 else "MEDIUM"
            
            alert = {
                'timestamp': event['timestamp'].isoformat() if hasattr(event['timestamp'], 'isoformat') else str(event['timestamp']),
                'severity': severity,
                'user': event['user'],
                'source_ip': event['src_ip'],
                'destination_ip': event['dst_ip'],
                'location': event['location'],
                'protocol': event['protocol'],
                'anomaly_score': round(score, 3),
                'ml_confidence': f"{score * 100:.1f}%",
                'behavioral_anomalies': reasons,
                'failed_attempts': event['failed_attempts'],
                'recommended_action': 'Investigate immediately - possible account compromise'
            }
            alerts.append(alert)
            
            # Display alert
            print(f"[{severity}] ANOMALY DETECTED #{len(alerts)}")
            print(f"  User: {event['user']}")
            print(f"  Time: {event['timestamp']}")
            print(f"  Source: {event['src_ip']} ({event['location']})")
            print(f"  Protocol: {event['protocol']}")
            print(f"  ML Score: {score:.3f} ({score * 100:.1f}% confidence)")
            print(f"  Failed Attempts: {event['failed_attempts']}")
            print(f"  Reasons:")
            for reason in reasons:
                print(f"    • {reason}")
            print()
    
    # Step 5: Generate report
    print("=" * 80)
    print("DETECTION SUMMARY")
    print("=" * 80)
    print(f"PCAP File: {pcap_file}")
    print(f"Total Login Events: {len(events)}")
    print(f"Baseline Events: {len(baseline_events)}")
    print(f"Test Events: {len(test_events)}")
    print(f"Anomalies Detected: {len(alerts)}")
    if test_events:
        print(f"Detection Rate: {len(alerts)}/{len(test_events)} ({len(alerts)/len(test_events)*100:.1f}%)")
    print()
    
    if alerts:
        print("Severity Breakdown:")
        severity_counts = defaultdict(int)
        for alert in alerts:
            severity_counts[alert['severity']] += 1
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity}: {count}")
        print()
        
        print("Top 5 Anomalies:")
        sorted_alerts = sorted(alerts, key=lambda x: x['anomaly_score'], reverse=True)
        for i, alert in enumerate(sorted_alerts[:5], 1):
            print(f"  {i}. {alert['user']} - Score: {alert['anomaly_score']} - {alert['location']}")
    
    return alerts


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 pcap_ml_integration.py <pcap_file>")
        print("\nExample: python3 pcap_ml_integration.py sample_traffic.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    if not os.path.exists(pcap_file):
        print(f"[ERROR] PCAP file not found: {pcap_file}")
        sys.exit(1)
    
    # Process PCAP and detect anomalies
    alerts = process_pcap_for_anomalies(pcap_file)
    
    # Export alerts to JSON
    if alerts:
        output_file = pcap_file.replace('.pcap', '_anomalies.json')
        report = {
            'tool': 'Login Anomaly Detector - PCAP Mode',
            'version': '5.0',
            'pcap_source': pcap_file,
            'scan_time': datetime.now().isoformat(),
            'total_alerts': len(alerts),
            'alerts': alerts
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Anomaly report exported to: {output_file}")
    
    print("\n" + "=" * 80)
    print("🚨 REAL-TIME DETECTION COMPLETE")
    print("=" * 80)
    
    return 0 if len(alerts) == 0 else len(alerts)


if __name__ == '__main__':
    sys.exit(main())
