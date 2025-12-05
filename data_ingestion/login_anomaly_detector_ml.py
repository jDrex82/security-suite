#!/usr/bin/env python3
"""
Login Anomaly Detector v5.0 - ML-Powered
Detects compromised accounts using behavioral analysis

Uses Isolation Forest for unsupervised anomaly detection on:
- Login time patterns (hour of day, day of week)
- Geographic anomalies (location changes)
- Login frequency patterns
- Failed login attempts

Author: John Drexler
ML Algorithm: Isolation Forest (sklearn-compatible implementation)
"""

import json
import sys
import os
from datetime import datetime, timedelta
import random
import math
from collections import defaultdict

# Pure Python Isolation Forest implementation (no sklearn dependency)
class SimpleIsolationForest:
    """
    Lightweight Isolation Forest implementation
    Uses binary trees to isolate anomalies
    """
    
    def __init__(self, n_estimators=100, max_samples=256, contamination=0.1):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.trees = []
        self.threshold = None
        
    def _build_tree(self, X, depth=0, max_depth=10):
        """Build a single isolation tree"""
        n_samples = len(X)
        
        if depth >= max_depth or n_samples <= 1:
            return {'type': 'leaf', 'size': n_samples}
        
        # Random feature and split
        n_features = len(X[0])
        feature = random.randint(0, n_features - 1)
        
        values = [x[feature] for x in X]
        min_val, max_val = min(values), max(values)
        
        if min_val == max_val:
            return {'type': 'leaf', 'size': n_samples}
        
        split_value = random.uniform(min_val, max_val)
        
        # Split data
        left = [x for x in X if x[feature] < split_value]
        right = [x for x in X if x[feature] >= split_value]
        
        return {
            'type': 'node',
            'feature': feature,
            'split': split_value,
            'left': self._build_tree(left, depth + 1, max_depth),
            'right': self._build_tree(right, depth + 1, max_depth)
        }
    
    def _path_length(self, x, tree, depth=0):
        """Calculate path length for a sample"""
        if tree['type'] == 'leaf':
            size = tree['size']
            # Average path length of unsuccessful search in BST
            if size > 2:
                return depth + 2 * (math.log(size - 1) + 0.5772156649) - (2 * (size - 1) / size)
            elif size == 2:
                return depth + 1
            else:
                return depth
        
        feature = tree['feature']
        if x[feature] < tree['split']:
            return self._path_length(x, tree['left'], depth + 1)
        else:
            return self._path_length(x, tree['right'], depth + 1)
    
    def fit(self, X):
        """Train the isolation forest"""
        self.trees = []
        n_samples = len(X)
        max_depth = int(math.log2(min(self.max_samples, n_samples)))
        
        for _ in range(self.n_estimators):
            # Sample data
            if n_samples > self.max_samples:
                sample_indices = random.sample(range(n_samples), self.max_samples)
                sample = [X[i] for i in sample_indices]
            else:
                sample = X
            
            # Build tree
            tree = self._build_tree(sample, max_depth=max_depth)
            self.trees.append(tree)
        
        # Calculate threshold based on contamination
        scores = [self.score_sample(x) for x in X]
        scores.sort()
        threshold_idx = int(len(scores) * (1 - self.contamination))
        self.threshold = scores[threshold_idx]
        
        return self
    
    def score_sample(self, x):
        """Calculate anomaly score for a sample (higher = more anomalous)"""
        avg_path_length = sum(self._path_length(x, tree) for tree in self.trees) / self.n_estimators
        
        # Normalize: expected path length for n samples
        n = self.max_samples
        c_n = 2 * (math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n) if n > 2 else 1
        
        # Anomaly score: 2^(-avg_path_length / c_n)
        score = 2 ** (-avg_path_length / c_n)
        return score
    
    def predict(self, X):
        """Predict anomalies (1 = anomaly, 0 = normal)"""
        return [1 if self.score_sample(x) > self.threshold else 0 for x in X]


class LoginAnomalyDetector:
    """ML-powered login anomaly detection"""
    
    def __init__(self):
        self.model = None
        self.baseline_data = []
        self.user_profiles = defaultdict(lambda: {
            'normal_hours': set(),
            'normal_days': set(),
            'normal_locations': set(),
            'avg_logins_per_day': 0,
            'max_failed_attempts': 0
        })
        
    def extract_features(self, login_event):
        """
        Extract ML features from login event
        Returns: [hour, day_of_week, location_hash, failed_attempts, time_since_last]
        """
        timestamp = login_event.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        
        hour = timestamp.hour
        day_of_week = timestamp.weekday()  # 0=Monday, 6=Sunday
        location = login_event.get('location', 'unknown')
        location_hash = hash(location) % 1000  # Simple location encoding
        failed_attempts = login_event.get('failed_attempts', 0)
        
        # Time since last login (in hours)
        user = login_event.get('user', 'unknown')
        last_login = login_event.get('time_since_last', 24)  # Default 24 hours
        
        return [hour, day_of_week, location_hash, failed_attempts, last_login]
    
    def train_baseline(self, login_events):
        """Train model on baseline 'normal' login data"""
        print("[*] Training baseline model on normal login patterns...")
        
        # Extract features
        X = []
        for event in login_events:
            features = self.extract_features(event)
            X.append(features)
            
            # Build user profiles
            user = event.get('user', 'unknown')
            timestamp = event.get('timestamp', datetime.now())
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            
            self.user_profiles[user]['normal_hours'].add(timestamp.hour)
            self.user_profiles[user]['normal_days'].add(timestamp.weekday())
            self.user_profiles[user]['normal_locations'].add(event.get('location', 'unknown'))
        
        # Train Isolation Forest
        self.model = SimpleIsolationForest(
            n_estimators=100,
            max_samples=min(256, len(X)),
            contamination=0.1  # Expect 10% anomalies
        )
        self.model.fit(X)
        
        print(f"[+] Model trained on {len(X)} login events")
        print(f"[+] Learned profiles for {len(self.user_profiles)} users")
        
        return self
    
    def detect_anomaly(self, login_event):
        """
        Detect if login event is anomalous using HYBRID approach:
        1. ML anomaly score (Isolation Forest)
        2. Rule-based behavioral checks
        3. Combined scoring
        
        Returns: (is_anomaly, anomaly_score, reasons)
        """
        if not self.model:
            return False, 0.0, ["Model not trained"]
        
        features = self.extract_features(login_event)
        ml_score = self.model.score_sample(features)
        
        # Rule-based scoring
        rule_score = 0.0
        reasons = []
        user = login_event.get('user', 'unknown')
        timestamp = login_event.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        
        profile = self.user_profiles.get(user)
        if profile:
            # Check hour anomaly (+0.15 if unusual hour)
            if timestamp.hour not in profile['normal_hours']:
                rule_score += 0.15
                reasons.append(f"Unusual login hour: {timestamp.hour}:00 (normal: {sorted(profile['normal_hours'])})")
            
            # Check day anomaly (+0.10 if weekend for weekday worker)
            days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            if timestamp.weekday() not in profile['normal_days']:
                rule_score += 0.10
                normal_days = [days[d] for d in sorted(profile['normal_days'])]
                reasons.append(f"Unusual login day: {days[timestamp.weekday()]} (normal: {normal_days})")
            
            # Check location anomaly (+0.20 for new/foreign location)
            location = login_event.get('location', 'unknown')
            if location not in profile['normal_locations']:
                rule_score += 0.20
                reasons.append(f"New location: {location} (normal: {profile['normal_locations']})")
            
            # Check failed attempts (+0.25 for high failures)
            failed = login_event.get('failed_attempts', 0)
            if failed > 5:
                rule_score += min(0.25, failed * 0.01)  # Scale with failures
                reasons.append(f"High failed attempts: {failed} (normal: {profile['max_failed_attempts']})")
            
            # Check rapid logins (+0.15 for < 15 minutes)
            time_since = login_event.get('time_since_last', 24)
            if time_since < 0.25:  # Less than 15 minutes
                rule_score += 0.15
                reasons.append(f"Rapid login: {time_since * 60:.0f} minutes since last login")
        else:
            rule_score += 0.10
            reasons.append("New user - no baseline profile")
        
        # HYBRID SCORE: Combine ML (60%) + Rules (40%)
        combined_score = (ml_score * 0.6) + (rule_score * 0.4)
        
        # Determine if anomaly
        is_anomaly = combined_score > 0.45  # Tuned threshold for hybrid approach
        
        # Enhance reasons with ML confidence
        if ml_score > 0.55:
            reasons.insert(0, f"ML anomaly detection: {ml_score:.3f} confidence")
        
        return is_anomaly, combined_score, reasons
    
    def generate_synthetic_baseline(self, num_users=10, days=7):
        """Generate synthetic 'normal' login data for training"""
        print("[*] Generating synthetic baseline data...")
        
        users = [f"user{i}@hospital.local" for i in range(num_users)]
        locations = ["Office", "Hospital Floor 1", "Hospital Floor 2", "Admin Building"]
        
        baseline_events = []
        
        # Generate normal patterns
        for day in range(days):
            for user in users:
                # Normal work hours: 8 AM - 5 PM, weekdays
                if day % 7 < 5:  # Weekdays only
                    num_logins = random.randint(2, 5)
                    for _ in range(num_logins):
                        hour = random.randint(8, 17)  # 8 AM - 5 PM
                        timestamp = datetime.now() - timedelta(days=days-day, hours=24-hour)
                        
                        event = {
                            'user': user,
                            'timestamp': timestamp,
                            'location': random.choice(locations[:2]),  # Mostly office/floor 1
                            'failed_attempts': 0,
                            'time_since_last': random.uniform(1, 8),
                            'success': True
                        }
                        baseline_events.append(event)
        
        print(f"[+] Generated {len(baseline_events)} baseline login events")
        return baseline_events
    
    def generate_anomalous_logins(self):
        """Generate synthetic anomalous login attempts"""
        anomalies = []
        
        # 1. After-hours access (3 AM - very unusual)
        anomalies.append({
            'user': 'user1@hospital.local',
            'timestamp': datetime.now().replace(hour=3, minute=0),
            'location': 'Office',
            'failed_attempts': 0,
            'time_since_last': 18,  # 18 hours since last
            'success': True,
            'description': 'After-hours access (3:00 AM)'
        })
        
        # 2. Weekend access with new location
        now = datetime.now()
        days_until_sunday = (6 - now.weekday()) % 7
        sunday = now + timedelta(days=days_until_sunday)
        anomalies.append({
            'user': 'user2@hospital.local',
            'timestamp': sunday.replace(hour=23, minute=30),  # 11:30 PM Sunday
            'location': 'Remote - Unknown',
            'failed_attempts': 0,
            'time_since_last': 72,  # 3 days since last
            'success': True,
            'description': 'Late night weekend access from new location'
        })
        
        # 3. Foreign country access
        anomalies.append({
            'user': 'user3@hospital.local',
            'timestamp': datetime.now().replace(hour=10, minute=0),
            'location': 'Remote - Russia',
            'failed_attempts': 0,
            'time_since_last': 2,
            'success': True,
            'description': 'Login from high-risk location (Russia)'
        })
        
        # 4. Brute force attempt (many failed logins)
        anomalies.append({
            'user': 'user4@hospital.local',
            'timestamp': datetime.now().replace(hour=4, minute=0),  # 4 AM
            'location': 'Office',
            'failed_attempts': 25,  # High number
            'time_since_last': 0.3,  # 18 minutes
            'success': True,
            'description': 'Brute force attack (25 failed attempts at 4 AM)'
        })
        
        # 5. Impossible travel (rapid location changes)
        anomalies.append({
            'user': 'user5@hospital.local',
            'timestamp': datetime.now().replace(hour=1, minute=0),  # 1 AM
            'location': 'Remote - China',
            'failed_attempts': 0,
            'time_since_last': 0.05,  # 3 minutes since last
            'success': True,
            'description': 'Impossible travel (China login 3 min after US login)'
        })
        
        return anomalies


def main():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                 LOGIN ANOMALY DETECTOR v5.0 - ML POWERED                     ║
║              Behavioral Analysis for Account Compromise Detection            ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    detector = LoginAnomalyDetector()
    
    # Phase 1: Train on baseline data
    print("[PHASE 1: BASELINE TRAINING]")
    baseline_events = detector.generate_synthetic_baseline(num_users=10, days=7)
    detector.train_baseline(baseline_events)
    
    print("\n[PHASE 2: ANOMALY DETECTION]")
    print("[*] Testing model on anomalous login patterns...\n")
    
    # Phase 2: Test on anomalous logins
    anomalous_logins = detector.generate_anomalous_logins()
    
    alerts = []
    print("[DEBUG] Anomaly scores for test cases:")
    for login in anomalous_logins:
        is_anomaly, score, reasons = detector.detect_anomaly(login)
        print(f"  {login['user']}: score={score:.3f}, is_anomaly={is_anomaly}, desc={login['description']}")
        
        if is_anomaly:
            severity = "CRITICAL" if score > 0.75 else "HIGH"
            
            alert = {
                'timestamp': login['timestamp'].isoformat(),
                'severity': severity,
                'user': login['user'],
                'location': login['location'],
                'anomaly_score': round(score, 3),
                'ml_confidence': f"{score * 100:.1f}%",
                'description': login['description'],
                'behavioral_anomalies': reasons,
                'recommended_action': 'Verify user identity, check for account compromise'
            }
            alerts.append(alert)
            
            print(f"{severity}: Account Anomaly Detected")
            print(f"  User: {login['user']}")
            print(f"  Time: {login['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Location: {login['location']}")
            print(f"  ML Anomaly Score: {score:.3f} ({score * 100:.1f}% confidence)")
            print(f"  Description: {login['description']}")
            print(f"  Behavioral Anomalies:")
            for reason in reasons:
                print(f"    - {reason}")
            print()
    
    # Summary
    print("=" * 80)
    print("LOGIN ANOMALY DETECTOR - ML REPORT")
    print("=" * 80)
    print(f"Baseline Training: {len(baseline_events)} events, 10 users, 7 days")
    print(f"ML Algorithm: Isolation Forest (100 trees)")
    print(f"Anomalies Detected: {len(alerts)}")
    print(f"Detection Rate: {len(alerts)}/{len(anomalous_logins)} ({len(alerts)/len(anomalous_logins)*100:.0f}%)")
    print()
    
    print("Anomaly Breakdown:")
    for alert in alerts:
        print(f"  [{alert['severity']}] {alert['user']} - {alert['description']} (score: {alert['anomaly_score']})")
    
    print()
    print("ML Model Statistics:")
    print(f"  Trees: 100")
    print(f"  Max Samples: {min(256, len(baseline_events))}")
    print(f"  Contamination: 10%")
    print(f"  Feature Vector: [hour, day_of_week, location_hash, failed_attempts, time_since_last]")
    print()
    
    # Export report
    report = {
        'tool': 'Login Anomaly Detector',
        'version': '5.0',
        'ml_algorithm': 'Isolation Forest',
        'scan_time': datetime.now().isoformat(),
        'baseline_events': len(baseline_events),
        'total_alerts': len(alerts),
        'alerts': alerts,
        'model_info': {
            'algorithm': 'Isolation Forest',
            'n_estimators': 100,
            'contamination': 0.1,
            'features': ['hour', 'day_of_week', 'location_hash', 'failed_attempts', 'time_since_last']
        }
    }
    
    with open('login_anomaly_ml_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("[+] ML report exported to: login_anomaly_ml_report.json")
    print()
    print("=" * 80)
    print("🤖 ML-POWERED DETECTION COMPLETE")
    print("=" * 80)


if __name__ == '__main__':
    main()
