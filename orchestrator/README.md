# Master Orchestrator - Security Suite v5.0

**Priority #3: Continuous 24/7 Network Monitoring**

## Overview

The Master Orchestrator is a daemon that runs continuously, capturing network traffic and detecting anomalies in real-time.

## Architecture

```
┌─────────────────────────────────────────┐
│         ORCHESTRATOR DAEMON             │
├─────────────────────────────────────────┤
│                                         │
│  📡 Traffic Capture (tcpdump)           │
│     ├─ Monitors SPAN port               │
│     ├─ Rotates every 5 minutes          │
│     └─ Filters: SSH, RDP, HTTP, LDAP    │
│                                         │
│  🔍 PCAP Processing                     │
│     ├─ Watches for new files            │
│     ├─ Runs ML detection                │
│     └─ Extracts login events            │
│                                         │
│  🚨 Alert Management                    │
│     ├─ Queues anomalies                 │
│     ├─ Logs to file                     │
│     └─ Ready for forwarding             │
│                                         │
│  ❤️  Health Monitoring                  │
│     ├─ Process health checks            │
│     ├─ Auto-restart on failure          │
│     └─ Resource monitoring              │
│                                         │
└─────────────────────────────────────────┘
```

## Components

### 1. orchestrator_daemon.py
Main daemon process that coordinates all monitoring activities.

**Features:**
- Runs tcpdump with automatic PCAP rotation
- Processes PCAP files with ML detection
- Manages alert queue
- Health monitoring and auto-recovery
- Multi-threaded architecture

### 2. security-suite-control.sh
Control script for daemon management.

**Commands:**
```bash
security-suite start    # Start monitoring
security-suite stop     # Stop monitoring
security-suite restart  # Restart daemon
security-suite status   # Show status and stats
security-suite logs     # Tail daemon logs
security-suite alerts   # Tail alert logs
```

### 3. security-suite.service
Systemd service for automatic startup and management.

**Features:**
- Auto-start on boot
- Auto-restart on failure
- Resource limits
- Security hardening

## Installation

### Quick Install
```bash
cd orchestrator
sudo bash install_orchestrator.sh
```

### Manual Install
```bash
# 1. Copy files
sudo mkdir -p /opt/security_suite/orchestrator
sudo cp orchestrator_daemon.py /opt/security_suite/orchestrator/
sudo cp security-suite-control.sh /opt/security_suite/orchestrator/
sudo chmod +x /opt/security_suite/orchestrator/*.sh

# 2. Install systemd service
sudo cp security-suite.service /etc/systemd/system/
sudo systemctl daemon-reload

# 3. Create launcher
sudo ln -s /opt/security_suite/orchestrator/security-suite-control.sh /usr/local/bin/security-suite

# 4. Install dependencies
sudo apt-get install tcpdump
```

## Configuration

Edit `/opt/security_suite/orchestrator/orchestrator_daemon.py`:

```python
CONFIG = {
    'capture_interface': 'eth1',  # Your SPAN port interface
    'capture_filter': 'port 22 or port 3389 or port 80 or port 443',
    'rotation_interval': 300,  # PCAP rotation (5 min)
    'processing_interval': 60,  # Check for new files (1 min)
}
```

### Network Interface Setup

**Find your interface:**
```bash
ip link show
```

**Configure SPAN port:** (on your switch)
```
# Cisco example:
monitor session 1 source interface Gi1/0/1-24
monitor session 1 destination interface Gi1/0/48

# Connect mini PC eth1 to Gi1/0/48
```

## Usage

### Start Monitoring
```bash
sudo security-suite start
```

**Expected output:**
```
[*] Starting Security Suite Orchestrator...
[+] Daemon started successfully
Status: RUNNING (PID: 12345)
```

### Check Status
```bash
sudo security-suite status
```

**Output:**
```
==============================================
Security Suite Status
==============================================
Status: RUNNING (PID: 12345)
Uptime: 2:15:30
CPU: 2.3%
Memory: 1.8%
Active PCAP files: 3
Alerts today: 7
==============================================
```

### View Alerts in Real-Time
```bash
sudo security-suite alerts
```

**Output:**
```
[2025-12-05T14:23:15] [CRITICAL] User: attacker_192.168.1.50, Source: 203.0.113.25, Score: 0.85
[2025-12-05T14:25:32] [HIGH] User: compromised_admin, Source: 198.51.100.10, Score: 0.72
```

### View Daemon Logs
```bash
sudo security-suite logs
```

### Stop Monitoring
```bash
sudo security-suite stop
```

## Systemd Management

### Enable Auto-Start on Boot
```bash
sudo systemctl enable security-suite
```

### Manual Control
```bash
# Start
sudo systemctl start security-suite

# Stop
sudo systemctl stop security-suite

# Status
sudo systemctl status security-suite

# Restart
sudo systemctl restart security-suite
```

## File Locations

```
/opt/security_suite/orchestrator/     # Daemon code
/var/lib/security_suite/pcap/         # Captured PCAP files
/var/lib/security_suite/alerts/       # Alert reports (JSON)
/var/lib/security_suite/models/       # ML models
/var/log/security_suite/daemon.log    # Daemon logs
/var/log/security_suite/alerts.log    # Alert logs
/var/run/security_suite.pid           # PID file
```

## How It Works

### Capture Phase (every 5 minutes)
```
tcpdump → capture_20251205_143000.pcap → rotate → capture_20251205_143500.pcap
```

### Processing Phase (every 60 seconds)
```
1. Scan /var/lib/security_suite/pcap/
2. Find unprocessed .pcap files
3. Run: python3 pcap_ml_integration.py capture.pcap
4. Parse: capture_anomalies.json
5. Queue alerts
6. Delete old PCAP (>1 hour)
```

### Alert Phase (real-time)
```
1. Pop alert from queue
2. Log to /var/log/security_suite/alerts.log
3. [Future] Forward to email/Slack/SIEM
```

## Performance

**Resource Usage:**
- CPU: 1-3% (idle)
- Memory: 50-100 MB
- Disk: ~10 MB/min (PCAP, auto-deleted after 1 hour)
- Network: Zero impact (read-only SPAN port)

**Processing Speed:**
- PCAP parsing: ~1000 packets/sec
- ML inference: <1ms per event
- Can handle ~10,000 logins/hour

## Monitoring

### Health Checks
The daemon performs self-checks every 60 seconds:
- Is tcpdump still running?
- Are threads responsive?
- Is disk space available?

**Auto-recovery:**
- Restarts tcpdump if crashed
- Cleans up old PCAP files
- Logs all issues

### Logs
All activity logged to `/var/log/security_suite/daemon.log`:
```
2025-12-05 14:23:00 [INFO] Starting network capture...
2025-12-05 14:23:01 [INFO] Capture started (PID: 12350)
2025-12-05 14:28:15 [INFO] Processing: capture_20251205_142300.pcap
2025-12-05 14:28:22 [WARNING] Detected 3 anomalies in capture_20251205_142300.pcap
```

## Troubleshooting

### "Daemon failed to start"
```bash
# Check permissions
sudo ls -la /var/lib/security_suite/
sudo ls -la /var/log/security_suite/

# Check interface exists
ip link show eth1

# Check tcpdump installed
which tcpdump
```

### "No packets captured"
```bash
# Verify SPAN port configured
# Check interface is up
sudo ip link set eth1 up

# Test manual capture
sudo tcpdump -i eth1 -c 10
```

### "High CPU usage"
```bash
# Check PCAP file count
ls /var/lib/security_suite/pcap/ | wc -l

# If >20 files, increase processing interval
# Edit orchestrator_daemon.py:
# 'processing_interval': 120  # 2 minutes instead of 1
```

## Security

The daemon runs as root (required for tcpdump) but implements security hardening:
- No shell access
- Limited file system access (ReadWritePaths)
- Private tmp directory
- No privilege escalation

## Next Steps

**Priority #4: Alert Forwarding**
- Email notifications (SMTP)
- Slack webhooks
- Syslog forwarding (SIEM)
- Alert deduplication

**Priority #5: Model Persistence**
- Save trained ML models
- Load on startup
- Auto-retrain weekly

**Priority #6: Dashboard**
- Web UI for monitoring
- Real-time alert feed
- Configuration editor

## Status

✅ **COMPLETE** - Orchestrator tested and working  
🚀 **PRODUCTION READY** - Deploy to mini PC

---

**Author:** John Drexler  
**Version:** 5.0  
**Date:** December 2025
