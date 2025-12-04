# SSH Login Attempt Monitor

A Python script to monitor and analyze SSH login attempts from system authentication logs. Useful for security monitoring, intrusion detection, and identifying brute-force attacks.

## Features

- ✅ Parse SSH authentication logs (auth.log or secure)
- ✅ Detect failed login attempts
- ✅ Track successful logins (both password and publickey)
- ✅ Identify invalid user attempts
- ✅ Real-time monitoring mode (like tail -f)
- ✅ Statistical summary with top attacking IPs
- ✅ No external dependencies - uses Python standard library only

## Requirements

- Python 3.6 or higher
- Access to system authentication logs (usually requires root/sudo)
- Linux system with SSH logging enabled

## Installation

1. Download the script:
```bash
curl -O https://raw.githubusercontent.com/yourusername/ssh-monitor/main/ssh_monitor.py
# or
wget https://raw.githubusercontent.com/yourusername/ssh-monitor/main/ssh_monitor.py
```

2. Make it executable:
```bash
chmod +x ssh_monitor.py
```

3. (Optional) Move to system path:
```bash
sudo mv ssh_monitor.py /usr/local/bin/ssh-monitor
```

## Usage

### Basic Analysis
Analyze the entire auth.log file:
```bash
sudo python3 ssh_monitor.py
```

### Analyze Last N Lines
Check only the most recent log entries:
```bash
sudo python3 ssh_monitor.py -n 100
```

### Real-Time Monitoring
Monitor SSH attempts as they happen (Ctrl+C to stop):
```bash
sudo python3 ssh_monitor.py -f
```

### Custom Log File
Specify a different log file location:
```bash
sudo python3 ssh_monitor.py -l /var/log/secure
```

### Command-Line Options

```
-h, --help                Show help message
-l, --log-file PATH       Path to auth log file (default: /var/log/auth.log)
-n, --lines NUMBER        Number of lines to analyze from end of file
-f, --follow              Follow the log file in real-time
```

## Output Format

### Event Types

The script identifies and reports the following SSH events:

- **[FAILED]** - Failed password attempts
- **[SUCCESS]** - Successful logins (password or publickey)
- **[INVALID]** - Attempts with non-existent usernames
- **[CONNECTION CLOSED]** - Closed connections

### Sample Output

```
======================================================================
SSH Login Attempt Monitor - Analyzing /var/log/auth.log
======================================================================

[FAILED] Oct 29 10:15:22 - User: root, IP: 192.168.1.100
[FAILED] Oct 29 10:15:25 - User: admin, IP: 192.168.1.100
[SUCCESS] Oct 29 10:17:30 - User: jdoe, IP: 10.0.0.5 (password)
[INVALID] Oct 29 10:18:12 - Invalid user: admin123, IP: 198.51.100.22
[SUCCESS] Oct 29 10:19:45 - User: ubuntu, IP: 10.0.0.10 (publickey)

======================================================================
SUMMARY
======================================================================

Total failed password attempts: 13
Total successful password logins: 3
Total successful publickey logins: 2
Total invalid user attempts: 4

======================================================================
TOP ATTACKING IPs
======================================================================
192.168.1.100: 7 failed attempts
  Usernames tried: root, admin, test
203.0.113.45: 3 failed attempts
  Usernames tried: oracle, postgres, root
```

## Common Use Cases

### 1. Daily Security Check
```bash
# Check today's failed login attempts
sudo python3 ssh_monitor.py -n 1000 | grep FAILED
```

### 2. Monitor for Brute Force Attacks
```bash
# Real-time monitoring with focus on failed attempts
sudo python3 ssh_monitor.py -f
```

### 3. Audit Successful Logins
```bash
# See who successfully logged in
sudo python3 ssh_monitor.py | grep SUCCESS
```

### 4. Identify Attack Sources
```bash
# Run full analysis to see top attacking IPs
sudo python3 ssh_monitor.py
```

## Automated Monitoring

### Set Up as a Systemd Service

Create `/etc/systemd/system/ssh-monitor.service`:

```ini
[Unit]
Description=SSH Login Monitor
After=sshd.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/ssh_monitor.py -f
Restart=always
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ssh-monitor
sudo systemctl start ssh-monitor
```

View logs:
```bash
sudo journalctl -u ssh-monitor -f
```

### Set Up as a Cron Job

Add to root's crontab for daily reports:
```bash
sudo crontab -e
```

Add line:
```
0 8 * * * /usr/bin/python3 /usr/local/bin/ssh_monitor.py -n 1000 > /var/log/ssh-daily-report.log
```

## Log File Locations

The script automatically checks these locations:
- `/var/log/auth.log` (Debian/Ubuntu)
- `/var/log/secure` (RHEL/CentOS/Fedora)

## Security Considerations

1. **Permissions**: Script requires root access to read auth logs
2. **Privacy**: Be mindful of log data when sharing outputs
3. **Rate Limiting**: Consider using fail2ban or similar tools to automatically block attackers
4. **Log Rotation**: Ensure your system's log rotation is configured properly

## Troubleshooting

### Permission Denied Error
```bash
# Run with sudo
sudo python3 ssh_monitor.py
```

### Log File Not Found
```bash
# Specify the correct log file location
python3 ssh_monitor.py -l /var/log/secure
```

### No SSH Events Found
- Verify SSH service is running: `sudo systemctl status sshd`
- Check log file contains SSH entries: `sudo grep sshd /var/log/auth.log`

## Integration with Other Tools

### fail2ban
Use the script's output to identify IPs for fail2ban configuration:
```bash
sudo python3 ssh_monitor.py | grep "TOP ATTACKING"
```

### Email Alerts
Combine with mail command for alerts:
```bash
sudo python3 ssh_monitor.py -n 100 | mail -s "SSH Login Report" admin@example.com
```

### Slack/Discord Webhooks
Parse output and send to chat platforms for team notifications.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## License

MIT License - feel free to use and modify as needed.

## Author

Created for security monitoring and system administration purposes.

## Changelog

### Version 1.0
- Initial release
- Basic log parsing
- Real-time monitoring
- Statistical analysis
- Top attacker identification
