#!/usr/bin/env python3
"""
SSH Log Simulator
Generates realistic SSH log entries for testing ssh_monitor.py
"""

import time
import random
from datetime import datetime

# Sample IPs and usernames for realistic simulation
ATTACKER_IPS = [
    '192.168.1.100',
    '203.0.113.45',
    '198.51.100.22',
    '185.220.101.5',
    '45.142.212.33'
]

LEGITIMATE_IPS = [
    '10.0.0.5',
    '10.0.0.8',
    '10.0.0.10',
    '10.0.0.15',
    '10.0.0.20'
]

COMMON_USERNAMES = [
    'root', 'admin', 'user', 'test', 'guest',
    'oracle', 'postgres', 'mysql', 'tomcat', 'jenkins'
]

VALID_USERS = [
    'jdoe', 'jsmith', 'ubuntu', 'deploy', 'admin', 'developer'
]

def get_timestamp():
    """Get current timestamp in syslog format"""
    now = datetime.now()
    return now.strftime("%b %d %H:%M:%S")

def generate_failed_attempt():
    """Generate a failed login attempt"""
    ip = random.choice(ATTACKER_IPS)
    user = random.choice(COMMON_USERNAMES)
    port = random.randint(40000, 60000)
    timestamp = get_timestamp()
    pid = random.randint(10000, 99999)
    
    return f"{timestamp} server sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2\n"

def generate_invalid_user():
    """Generate an invalid user attempt"""
    ip = random.choice(ATTACKER_IPS)
    user = random.choice(COMMON_USERNAMES)
    port = random.randint(40000, 60000)
    timestamp = get_timestamp()
    pid = random.randint(10000, 99999)
    
    return f"{timestamp} server sshd[{pid}]: Invalid user {user} from {ip} port {port}\n"

def generate_successful_login():
    """Generate a successful login"""
    ip = random.choice(LEGITIMATE_IPS)
    user = random.choice(VALID_USERS)
    port = random.randint(50000, 60000)
    timestamp = get_timestamp()
    pid = random.randint(10000, 99999)
    
    if random.random() > 0.5:
        return f"{timestamp} server sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2\n"
    else:
        return f"{timestamp} server sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:abc{random.randint(100,999)}\n"

def simulate_ssh_logs(output_file='test_auth.log', duration=30, interval=1):
    """
    Simulate SSH log entries
    
    Args:
        output_file: File to write logs to
        duration: How long to run simulation (seconds)
        interval: Delay between log entries (seconds)
    """
    print(f"Simulating SSH login attempts for {duration} seconds...")
    print(f"Writing to: {output_file}")
    print("Run 'sudo python3 ssh_monitor.py -f -l {output_file}' in another terminal to monitor\n")
    
    with open(output_file, 'a') as f:
        start_time = time.time()
        
        while (time.time() - start_time) < duration:
            # Randomly generate different types of events
            rand = random.random()
            
            if rand < 0.5:  # 50% failed attempts
                entry = generate_failed_attempt()
                print(f"⚠️  Generated failed attempt")
            elif rand < 0.7:  # 20% invalid user
                entry = generate_invalid_user()
                print(f"❌ Generated invalid user attempt")
            else:  # 30% successful login
                entry = generate_successful_login()
                print(f"✓ Generated successful login")
            
            f.write(entry)
            f.flush()  # Ensure it's written immediately
            
            time.sleep(interval)
    
    print(f"\nSimulation complete! Generated logs for {duration} seconds.")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Simulate SSH log entries for testing')
    parser.add_argument('-o', '--output', default='test_auth.log',
                       help='Output log file (default: test_auth.log)')
    parser.add_argument('-d', '--duration', type=int, default=30,
                       help='Duration in seconds (default: 30)')
    parser.add_argument('-i', '--interval', type=float, default=1.0,
                       help='Interval between entries in seconds (default: 1.0)')
    
    args = parser.parse_args()
    
    simulate_ssh_logs(args.output, args.duration, args.interval)
