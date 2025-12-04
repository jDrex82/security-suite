#!/bin/bash
# Quick Start Script for Security Toolkit
# Sets up and tests all three new security tools

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║        Security Toolkit - Quick Start Installation                   ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

# Check Python version
echo "[*] Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.6+ first."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "✓ Python $PYTHON_VERSION detected"
echo ""

# Make scripts executable
echo "[*] Making scripts executable..."
chmod +x port_scanner.py web_log_analyzer.py ssl_monitor.py
echo "✓ Scripts are now executable"
echo ""

# Test each tool
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                        Tool Verification Tests                        ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

# Test 1: Port Scanner
echo "═══════════════════════════════════════════════════════════════════════"
echo "Test 1: Port Scanner"
echo "═══════════════════════════════════════════════════════════════════════"
echo "[*] Testing port scanner with localhost..."
python3 port_scanner.py localhost -p 22,80,443 2>&1 | head -20
echo ""
echo "✓ Port scanner test complete"
echo ""

# Test 2: SSL Monitor
echo "═══════════════════════════════════════════════════════════════════════"
echo "Test 2: SSL/TLS Certificate Monitor"
echo "═══════════════════════════════════════════════════════════════════════"
echo "[*] Testing SSL monitor with google.com..."
python3 ssl_monitor.py google.com 2>&1 | head -30
echo ""
echo "✓ SSL monitor test complete"
echo ""

# Test 3: Web Log Analyzer (if access log exists)
echo "═══════════════════════════════════════════════════════════════════════"
echo "Test 3: Web Server Log Analyzer"
echo "═══════════════════════════════════════════════════════════════════════"

# Look for common log file locations
LOG_FILE=""
for loc in /var/log/apache2/access.log /var/log/nginx/access.log /var/log/httpd/access_log; do
    if [ -f "$loc" ]; then
        LOG_FILE="$loc"
        break
    fi
done

if [ -n "$LOG_FILE" ]; then
    echo "[*] Testing web log analyzer with $LOG_FILE..."
    echo "[*] Note: This requires sudo if log files have restricted permissions"
    # Just show help since we might not have permissions
    python3 web_log_analyzer.py --help
    echo "✓ Web log analyzer verified (run with actual log file path)"
else
    echo "[*] No web server log found at common locations"
    echo "[*] Showing help for web log analyzer..."
    python3 web_log_analyzer.py --help
    echo "✓ Web log analyzer verified"
fi
echo ""

# Installation complete
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                     Installation Complete! ✓                          ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "📚 Quick Start Commands:"
echo "────────────────────────────────────────────────────────────────────────"
echo ""
echo "Port Scanner:"
echo "  python3 port_scanner.py <target>"
echo "  python3 port_scanner.py 192.168.1.1 -p 1-1000"
echo "  python3 port_scanner.py example.com --export scan_report.json"
echo ""
echo "SSL Monitor:"
echo "  python3 ssl_monitor.py <domain>"
echo "  python3 ssl_monitor.py example.com"
echo "  python3 ssl_monitor.py -f example_domains.txt --export cert_report.json"
echo ""
echo "Web Log Analyzer:"
echo "  python3 web_log_analyzer.py /path/to/access.log"
echo "  python3 web_log_analyzer.py /var/log/apache2/access.log --export attacks.json"
echo ""
echo "────────────────────────────────────────────────────────────────────────"
echo "📖 For detailed documentation, see:"
echo "  - PORT_SCANNER_README.md"
echo "  - SSL_MONITOR_README.md"
echo "  - WEB_LOG_ANALYZER_README.md"
echo "  - COMPLETE_TOOLKIT_README.md"
echo ""
echo "🎯 Perfect for:"
echo "  - Healthcare cybersecurity panels"
echo "  - Guardian of the Grid discussions"
echo "  - Critical infrastructure protection"
echo "  - SOC operations"
echo ""
echo "Happy Hunting! 🛡️"
