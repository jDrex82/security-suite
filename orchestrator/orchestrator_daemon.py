#!/usr/bin/env python3
"""
Security Suite Master Orchestrator v5.0
Runs 24/7 monitoring of network traffic

Components:
1. Traffic Capture (tcpdump)
2. PCAP Processing (ML detection)
3. Alert Management
4. Health Monitoring

Author: John Drexler
"""

import os
import sys
import time
import signal
import subprocess
import json
import logging
from datetime import datetime
from pathlib import Path
import threading
from queue import Queue

# Configuration
CONFIG = {
    'capture_interface': 'eth1',  # SPAN port interface
    'capture_filter': 'port 22 or port 3389 or port 80 or port 443 or port 389 or port 636 or port 445',
    'pcap_dir': '/var/lib/security_suite/pcap',
    'alerts_dir': '/var/lib/security_suite/alerts',
    'log_dir': '/var/log/security_suite',
    'models_dir': '/var/lib/security_suite/models',
    'rotation_interval': 300,  # 5 minutes in seconds
    'processing_interval': 60,  # Check for new files every 60 seconds
    'alert_log': '/var/log/security_suite/alerts.log',
    'daemon_log': '/var/log/security_suite/daemon.log',
    'pid_file': '/var/run/security_suite.pid'
}


class SecuritySuiteDaemon:
    """Main orchestrator daemon"""
    
    def __init__(self, config=None):
        self.config = config or CONFIG
        self.running = False
        self.capture_process = None
        self.alert_queue = Queue()
        self.threads = []
        
        # Setup logging
        self._setup_logging()
        
        # Ensure directories exist
        self._create_directories()
        
    def _setup_logging(self):
        """Configure logging"""
        os.makedirs(self.config['log_dir'], exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(self.config['daemon_log']),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('SecuritySuite')
        
    def _create_directories(self):
        """Create necessary directories"""
        dirs = [
            self.config['pcap_dir'],
            self.config['alerts_dir'],
            self.config['log_dir'],
            self.config['models_dir']
        ]
        
        for d in dirs:
            os.makedirs(d, exist_ok=True)
            self.logger.info(f"Directory ready: {d}")
    
    def _write_pid(self):
        """Write PID file"""
        with open(self.config['pid_file'], 'w') as f:
            f.write(str(os.getpid()))
    
    def _remove_pid(self):
        """Remove PID file"""
        try:
            os.remove(self.config['pid_file'])
        except:
            pass
    
    def start_capture(self):
        """Start tcpdump capture with rotation"""
        self.logger.info("Starting network capture...")
        
        pcap_pattern = os.path.join(
            self.config['pcap_dir'],
            'capture_%Y%m%d_%H%M%S.pcap'
        )
        
        # Build tcpdump command
        cmd = [
            'tcpdump',
            '-i', self.config['capture_interface'],
            '-w', pcap_pattern,
            '-G', str(self.config['rotation_interval']),  # Rotate every N seconds
            '-Z', 'root',  # Run as root
            self.config['capture_filter']
        ]
        
        try:
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self.logger.info(f"Capture started (PID: {self.capture_process.pid})")
            self.logger.info(f"Interface: {self.config['capture_interface']}")
            self.logger.info(f"Filter: {self.config['capture_filter']}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start capture: {e}")
            return False
    
    def stop_capture(self):
        """Stop tcpdump capture"""
        if self.capture_process:
            self.logger.info("Stopping network capture...")
            self.capture_process.terminate()
            try:
                self.capture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.capture_process.kill()
            self.logger.info("Capture stopped")
    
    def process_pcap_files(self):
        """Background thread: Process new PCAP files"""
        self.logger.info("Starting PCAP processing thread...")
        
        processed_files = set()
        
        while self.running:
            try:
                # Find unprocessed PCAP files
                pcap_files = sorted(Path(self.config['pcap_dir']).glob('capture_*.pcap'))
                
                for pcap_file in pcap_files:
                    if str(pcap_file) in processed_files:
                        continue
                    
                    # Skip file if it's still being written (< 10 seconds old)
                    age = time.time() - pcap_file.stat().st_mtime
                    if age < 10:
                        continue
                    
                    self.logger.info(f"Processing: {pcap_file.name}")
                    
                    # Run ML detection
                    alerts = self._run_ml_detection(pcap_file)
                    
                    if alerts:
                        self.logger.warning(f"Detected {len(alerts)} anomalies in {pcap_file.name}")
                        for alert in alerts:
                            self.alert_queue.put(alert)
                    
                    processed_files.add(str(pcap_file))
                    
                    # Cleanup old PCAP files (keep last 1 hour)
                    if age > 3600:
                        pcap_file.unlink()
                        self.logger.info(f"Deleted old PCAP: {pcap_file.name}")
                
                time.sleep(self.config['processing_interval'])
                
            except Exception as e:
                self.logger.error(f"Processing error: {e}")
                time.sleep(10)
    
    def _run_ml_detection(self, pcap_file):
        """Run ML detection on PCAP file"""
        try:
            # Get path to data_ingestion module
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            integration_script = os.path.join(base_dir, 'data_ingestion', 'pcap_ml_integration.py')
            
            if not os.path.exists(integration_script):
                self.logger.error(f"ML integration script not found: {integration_script}")
                return []
            
            # Run detection
            result = subprocess.run(
                ['python3', integration_script, str(pcap_file)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Parse JSON output
            anomaly_file = str(pcap_file).replace('.pcap', '_anomalies.json')
            if os.path.exists(anomaly_file):
                with open(anomaly_file, 'r') as f:
                    data = json.load(f)
                    return data.get('alerts', [])
            
            return []
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Detection timeout: {pcap_file}")
            return []
        except Exception as e:
            self.logger.error(f"Detection failed: {e}")
            return []
    
    def handle_alerts(self):
        """Background thread: Handle alert queue"""
        self.logger.info("Starting alert handler thread...")
        
        alert_file = self.config['alert_log']
        
        while self.running:
            try:
                # Get alert from queue (timeout 1 second)
                if not self.alert_queue.empty():
                    alert = self.alert_queue.get(timeout=1)
                    
                    # Log to file
                    with open(alert_file, 'a') as f:
                        timestamp = datetime.now().isoformat()
                        severity = alert.get('severity', 'UNKNOWN')
                        user = alert.get('user', 'unknown')
                        source = alert.get('source_ip', 'unknown')
                        score = alert.get('anomaly_score', 0)
                        
                        log_line = f"[{timestamp}] [{severity}] User: {user}, Source: {source}, Score: {score}\n"
                        f.write(log_line)
                    
                    # Console output for debugging
                    self.logger.warning(f"ALERT: [{alert['severity']}] {alert['user']} from {alert['source_ip']}")
                    
                    self.alert_queue.task_done()
                else:
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"Alert handling error: {e}")
                time.sleep(1)
    
    def health_check(self):
        """Background thread: Monitor system health"""
        self.logger.info("Starting health check thread...")
        
        while self.running:
            try:
                # Check if capture is still running
                if self.capture_process and self.capture_process.poll() is not None:
                    self.logger.error("Capture process died! Restarting...")
                    self.start_capture()
                
                # Log stats
                pcap_count = len(list(Path(self.config['pcap_dir']).glob('*.pcap')))
                alert_count = self.alert_queue.qsize()
                self.logger.info(f"Health: {pcap_count} PCAP files, {alert_count} queued alerts")
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Health check error: {e}")
                time.sleep(30)
    
    def start(self):
        """Start the daemon"""
        self.logger.info("=" * 80)
        self.logger.info("Security Suite Orchestrator v5.0 - Starting")
        self.logger.info("=" * 80)
        
        self._write_pid()
        self.running = True
        
        # Start capture
        if not self.start_capture():
            self.logger.error("Failed to start capture. Exiting.")
            return False
        
        # Start background threads
        threads = [
            threading.Thread(target=self.process_pcap_files, name="PCAP-Processor", daemon=True),
            threading.Thread(target=self.handle_alerts, name="Alert-Handler", daemon=True),
            threading.Thread(target=self.health_check, name="Health-Monitor", daemon=True)
        ]
        
        for t in threads:
            t.start()
            self.threads.append(t)
            self.logger.info(f"Started thread: {t.name}")
        
        self.logger.info("=" * 80)
        self.logger.info("DAEMON RUNNING - Press Ctrl+C to stop")
        self.logger.info("=" * 80)
        
        # Main loop
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        
        self.stop()
        return True
    
    def stop(self):
        """Stop the daemon"""
        self.logger.info("=" * 80)
        self.logger.info("Security Suite Orchestrator - Stopping")
        self.logger.info("=" * 80)
        
        self.running = False
        
        # Stop capture
        self.stop_capture()
        
        # Wait for threads
        for t in self.threads:
            self.logger.info(f"Waiting for thread: {t.name}")
            t.join(timeout=5)
        
        # Process remaining alerts
        while not self.alert_queue.empty():
            self.alert_queue.get()
            self.alert_queue.task_done()
        
        self._remove_pid()
        self.logger.info("Daemon stopped")


def main():
    """Main entry point"""
    if os.geteuid() != 0:
        print("[ERROR] This daemon must be run as root (for tcpdump)")
        print("Usage: sudo python3 orchestrator_daemon.py")
        sys.exit(1)
    
    # Check if already running
    if os.path.exists(CONFIG['pid_file']):
        print(f"[WARNING] PID file exists: {CONFIG['pid_file']}")
        print("Daemon may already be running. Remove PID file if not.")
        sys.exit(1)
    
    daemon = SecuritySuiteDaemon()
    
    # Setup signal handlers
    def signal_handler(sig, frame):
        daemon.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    daemon.start()


if __name__ == '__main__':
    main()
