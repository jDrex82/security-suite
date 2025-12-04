# Quick Deployment Guide - SSH Monitor

## For Testing (Without Real SSH)

If you want to test the monitor without actual SSH traffic:

### 1. Test with Sample Data
```bash
# Use the provided test log
python3 ssh_monitor.py -l test_auth.log
```

### 2. Test Real-Time Monitoring
```bash
# Terminal 1: Start the monitor in follow mode
python3 ssh_monitor.py -f -l simulated_auth.log

# Terminal 2: Generate simulated SSH attempts
python3 simulate_ssh_logs.py -d 60 -i 2 -o simulated_auth.log
```

## For Production Use (Real Linux Server)

### Prerequisites Check
```bash
# Check if SSH service is running
sudo systemctl status sshd

# Verify log file location
ls -la /var/log/auth.log    # Debian/Ubuntu
# OR
ls -la /var/log/secure       # RHEL/CentOS/Fedora
```

### Installation

1. **Copy the script to your server:**
```bash
# Using scp
scp ssh_monitor.py user@your-server:/tmp/

# On the server
sudo mv /tmp/ssh_monitor.py /usr/local/bin/ssh-monitor
sudo chmod +x /usr/local/bin/ssh-monitor
```

2. **Test it works:**
```bash
# Analyze current logs
sudo ssh-monitor

# Monitor in real-time
sudo ssh-monitor -f
```

### Common Commands

```bash
# View last 100 lines of SSH attempts
sudo ssh-monitor -n 100

# Check for attacks in the last 500 lines
sudo ssh-monitor -n 500 | grep FAILED

# Real-time monitoring (press Ctrl+C to stop)
sudo ssh-monitor -f

# Specific log file
sudo ssh-monitor -l /var/log/secure

# Get help
ssh-monitor --help
```

### Set Up Email Alerts

Create a daily report script at `/usr/local/bin/ssh-daily-report.sh`:

```bash
#!/bin/bash
REPORT_FILE="/tmp/ssh-report-$(date +%Y%m%d).txt"

echo "SSH Security Report - $(date)" > "$REPORT_FILE"
echo "================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

/usr/local/bin/ssh-monitor -n 1000 >> "$REPORT_FILE"

# Send via email (requires mailutils)
cat "$REPORT_FILE" | mail -s "Daily SSH Report - $(hostname)" admin@example.com

# Clean up
rm "$REPORT_FILE"
```

Make it executable and add to crontab:
```bash
sudo chmod +x /usr/local/bin/ssh-daily-report.sh

# Add to crontab (run daily at 8 AM)
sudo crontab -e
# Add line:
# 0 8 * * * /usr/local/bin/ssh-daily-report.sh
```

### Integration with fail2ban

After identifying problematic IPs, add them to fail2ban:

```bash
# View top attackers
sudo ssh-monitor | grep "TOP ATTACKING"

# Manually ban an IP with fail2ban
sudo fail2ban-client set sshd banip 192.168.1.100
```

### Set Up as Systemd Service (Real-Time Monitoring)

1. Create service file `/etc/systemd/system/ssh-monitor.service`:
```ini
[Unit]
Description=SSH Login Attempt Monitor
After=sshd.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/ssh-monitor -f
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ssh-monitor

[Install]
WantedBy=multi-user.target
```

2. Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ssh-monitor
sudo systemctl start ssh-monitor
```

3. View real-time logs:
```bash
sudo journalctl -u ssh-monitor -f
```

4. Check status:
```bash
sudo systemctl status ssh-monitor
```

### Performance Considerations

For servers with high SSH traffic:

```bash
# Analyze only recent entries to reduce load
sudo ssh-monitor -n 1000

# Use in cron jobs instead of continuous monitoring
# Add to /etc/cron.hourly/ssh-monitor
```

### Troubleshooting

**Problem: Permission Denied**
```bash
# Solution: Run with sudo
sudo ssh-monitor
```

**Problem: Log file not found**
```bash
# Find your log file
sudo find /var/log -name "*auth*" -o -name "*secure*"

# Use the correct path
sudo ssh-monitor -l /path/to/your/log
```

**Problem: No SSH events found**
```bash
# Check SSH is logging
sudo grep sshd /var/log/auth.log | tail -20

# Verify SSH service is running
sudo systemctl status sshd
```

**Problem: Script shows old data**
```bash
# Make sure you're checking the active log
ls -lh /var/log/auth.log*

# Use the non-rotated file
sudo ssh-monitor -l /var/log/auth.log
```

### Security Best Practices

1. **Review logs regularly**
   ```bash
   sudo ssh-monitor -n 500 | less
   ```

2. **Identify attack patterns**
   - Multiple failed attempts from same IP = brute force
   - Many invalid usernames = scanning for accounts
   - Attempts on common usernames (root, admin) = automated attack

3. **Take action on findings**
   - Block persistent attackers with firewall
   - Disable password authentication (use keys only)
   - Change SSH port from default 22
   - Use fail2ban for automatic blocking

4. **Keep monitoring**
   - Set up automated reports
   - Check logs after security incidents
   - Monitor during credential changes

## Testing on a Live System

Want to test without waiting for real attacks?

```bash
# From another machine, intentionally fail a login
# (with permission on your own systems only!)
ssh wronguser@your-server  # Enter wrong password

# Then check the monitor
sudo ssh-monitor -n 10
```

## Files Included

- `ssh_monitor.py` - Main monitoring script
- `test_auth.log` - Sample log data for testing
- `simulate_ssh_logs.py` - Generate test logs
- `README.md` - Full documentation
- `DEPLOYMENT.md` - This file

## Next Steps

1. Test with sample data (no root required)
2. Deploy to your server
3. Set up automated monitoring
4. Configure alerts
5. Integrate with fail2ban or firewall rules

## Support

For issues or questions:
- Check the README.md for detailed documentation
- Review the troubleshooting section above
- Ensure you have proper permissions (sudo/root)
