#!/usr/bin/env python3
"""
Enhanced Login Anomaly Detector for PCAP Data
Optimized for real network traffic with improved rule-based detection

Key improvements:
- Better handling of unknown users (external IPs)
- More aggressive failed attempt detection
- External IP geo-scoring
- Rapid-fire brute force detection

Author: John Drexler
"""

import sys
sys.path.insert(0, '/mnt/user-data/uploads')
from login_anomaly_detector_ml import LoginAnomalyDetector as BaseDetector
from datetime import datetime


class EnhancedLoginDetector(BaseDetector):
    """Enhanced detector with better rules for real PCAP data"""
    
    def detect_anomaly(self, login_event):
        """
        Enhanced anomaly detection with better real-world rules
        """
        if not self.model:
            return False, 0.0, ["Model not trained"]
        
        features = self.extract_features(login_event)
        ml_score = self.model.score_sample(features)
        
        # Rule-based scoring - ENHANCED
        rule_score = 0.0
        reasons = []
        user = login_event.get('user', 'unknown')
        timestamp = login_event.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        
        # Check if external IP (high risk)
        location = login_event.get('location', 'unknown')
        is_external = 'External' in location
        if is_external:
            rule_score += 0.30  # External = suspicious
            reasons.append(f"External IP detected: {location}")
        
        # Failed attempts - MORE AGGRESSIVE
        failed = login_event.get('failed_attempts', 0)
        if failed > 10:
            rule_score += 0.50  # Definite brute force
            reasons.append(f"BRUTE FORCE: {failed} failed attempts")
        elif failed > 5:
            rule_score += 0.35  # Likely attack
            reasons.append(f"Multiple failed attempts: {failed}")
        elif failed > 2:
            rule_score += 0.20  # Suspicious
            reasons.append(f"Failed attempts: {failed}")
        
        # Rapid logins - BRUTE FORCE INDICATOR
        time_since = login_event.get('time_since_last', 24)
        if time_since < 0.05:  # Less than 3 minutes
            rule_score += 0.35  # Very rapid = automated
            reasons.append(f"Automated attack pattern: {time_since * 60:.1f} minutes between attempts")
        elif time_since < 0.25:  # Less than 15 minutes
            rule_score += 0.20
            reasons.append(f"Rapid login: {time_since * 60:.0f} minutes since last")
        
        # Check user profile (if exists)
        profile = self.user_profiles.get(user)
        if profile:
            # Check hour anomaly
            if timestamp.hour not in profile['normal_hours']:
                rule_score += 0.15
                reasons.append(f"Unusual hour: {timestamp.hour}:00")
            
            # Check day anomaly
            days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            if timestamp.weekday() not in profile['normal_days']:
                rule_score += 0.12
                reasons.append(f"Unusual day: {days[timestamp.weekday()]}")
            
            # Check location anomaly
            if location not in profile['normal_locations'] and not is_external:
                rule_score += 0.18
                reasons.append(f"New location: {location}")
        else:
            # Unknown user + external = high risk
            if is_external:
                rule_score += 0.25
                reasons.append("Unknown user from external IP")
            else:
                rule_score += 0.10
                reasons.append("New user - no baseline")
        
        # HYBRID SCORE: Combine ML (50%) + Rules (50%) 
        # More weight on rules for PCAP data
        combined_score = (ml_score * 0.5) + (rule_score * 0.5)
        
        # LOWER threshold for PCAP mode (more sensitive)
        is_anomaly = combined_score > 0.40  # Was 0.45
        
        # Add ML confidence if high
        if ml_score > 0.55:
            reasons.insert(0, f"ML anomaly: {ml_score:.3f} confidence")
        
        return is_anomaly, combined_score, reasons


def main():
    """Test enhanced detector"""
    print("Enhanced Login Detector - Optimized for PCAP Data")
    print("=" * 80)
    
    detector = EnhancedLoginDetector()
    
    # Generate baseline
    baseline = detector.generate_synthetic_baseline(num_users=5, days=7)
    detector.train_baseline(baseline)
    
    # Test with brute force
    brute_force_event = {
        'user': 'attacker_198_51_100_25',
        'timestamp': datetime.now(),
        'location': 'External (198.51.100.25)',
        'failed_attempts': 15,
        'time_since_last': 0.03,  # 1.8 minutes
        'success': True,
        'protocol': 'SSH',
        'src_ip': '198.51.100.25',
        'dst_ip': '192.168.1.10'
    }
    
    is_anomaly, score, reasons = detector.detect_anomaly(brute_force_event)
    print(f"\nTest Event: Brute Force Attack")
    print(f"  Detected: {is_anomaly}")
    print(f"  Score: {score:.3f}")
    print(f"  Reasons: {reasons}")
    
    assert is_anomaly, "Enhanced detector should catch brute force!"
    print("\n✓ Enhanced detector working correctly")


if __name__ == '__main__':
    main()
