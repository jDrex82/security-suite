#!/bin/bash
# Install Security Suite Orchestrator
# Run as: sudo bash install_orchestrator.sh

set -e

echo "=============================================="
echo "Security Suite Orchestrator - Installation"
echo "=============================================="
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Must run as root"
    echo "Usage: sudo bash install_orchestrator.sh"
    exit 1
fi

# Check if base suite is installed
if [ ! -d "/opt/security_suite" ]; then
    echo "[ERROR] Base security suite not found at /opt/security_suite"
    echo "Please install the base suite first"
    exit 1
fi

# Check if data_ingestion is installed
if [ ! -d "/opt/security_suite/data_ingestion" ]; then
    echo "[ERROR] Data ingestion module not found"
    echo "Please install data_ingestion first"
    exit 1
fi

# Create orchestrator directory
echo "[1/6] Creating orchestrator directory..."
mkdir -p /opt/security_suite/orchestrator
cp orchestrator_daemon.py /opt/security_suite/orchestrator/
cp security-suite-control.sh /opt/security_suite/orchestrator/
chmod +x /opt/security_suite/orchestrator/security-suite-control.sh
echo "  ✓ Directory created"

# Create required directories
echo ""
echo "[2/6] Creating data directories..."
mkdir -p /var/lib/security_suite/pcap
mkdir -p /var/lib/security_suite/alerts
mkdir -p /var/lib/security_suite/models
mkdir -p /var/log/security_suite
chmod 755 /var/lib/security_suite/pcap
chmod 755 /var/lib/security_suite/alerts
chmod 755 /var/log/security_suite
echo "  ✓ Directories created"

# Install systemd service
echo ""
echo "[3/6] Installing systemd service..."
cp security-suite.service /etc/systemd/system/
systemctl daemon-reload
echo "  ✓ Service installed"

# Create launcher commands
echo ""
echo "[4/6] Creating launcher commands..."
cat > /usr/local/bin/security-suite << 'EOF'
#!/bin/bash
/opt/security_suite/orchestrator/security-suite-control.sh "$@"
EOF
chmod +x /usr/local/bin/security-suite
echo "  ✓ Commands created"

# Check dependencies
echo ""
echo "[5/6] Checking dependencies..."
MISSING=""

if ! command -v tcpdump &> /dev/null; then
    echo "  [!] tcpdump not found - installing..."
    apt-get update > /dev/null 2>&1
    apt-get install -y tcpdump > /dev/null 2>&1
    echo "  ✓ tcpdump installed"
else
    echo "  ✓ tcpdump found"
fi

if ! command -v python3 &> /dev/null; then
    MISSING="$MISSING python3"
fi

if [ -n "$MISSING" ]; then
    echo "  [ERROR] Missing:$MISSING"
    exit 1
fi

echo "  ✓ All dependencies satisfied"

# Test configuration
echo ""
echo "[6/6] Testing configuration..."

# Create test config
python3 << 'PYTEST'
import os
import sys

# Test imports
sys.path.insert(0, '/opt/security_suite/data_ingestion')
try:
    from pcap_reader import PCAPReader
    from enhanced_detector import EnhancedLoginDetector
    print("  ✓ ML modules importable")
except Exception as e:
    print(f"  [ERROR] Import failed: {e}")
    sys.exit(1)

# Test directories
dirs = [
    '/var/lib/security_suite/pcap',
    '/var/lib/security_suite/alerts',
    '/var/log/security_suite'
]
for d in dirs:
    if not os.path.exists(d):
        print(f"  [ERROR] Missing directory: {d}")
        sys.exit(1)
print("  ✓ All directories accessible")
PYTEST

if [ $? -ne 0 ]; then
    echo ""
    echo "[ERROR] Configuration test failed"
    exit 1
fi

# Summary
echo ""
echo "=============================================="
echo "✅ INSTALLATION COMPLETE"
echo "=============================================="
echo ""
echo "Commands available:"
echo "  security-suite start    - Start monitoring"
echo "  security-suite stop     - Stop monitoring"
echo "  security-suite status   - Check status"
echo "  security-suite logs     - View logs"
echo "  security-suite alerts   - View alerts"
echo ""
echo "Systemd service:"
echo "  systemctl start security-suite"
echo "  systemctl enable security-suite  (auto-start on boot)"
echo "  systemctl status security-suite"
echo ""
echo "Next steps:"
echo "1. Configure network interface in orchestrator_daemon.py (default: eth1)"
echo "2. Start the daemon: sudo security-suite start"
echo "3. Monitor alerts: sudo security-suite alerts"
echo ""
echo "=============================================="
