#!/bin/bash
# ADVANCED SECURITY TOOLS LAUNCHER
# Quick launcher for Network Traffic Monitor, Ransomware Detector, and AD Monitor

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║         ADVANCED SECURITY TOOLS - QUICK LAUNCHER v3.0          ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    echo "[✓] Platform: Linux"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    OS="windows"
    echo "[✓] Platform: Windows"
else
    OS="unknown"
    echo "[!] Platform: Unknown (assuming Linux)"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "AVAILABLE TOOLS"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "1. Network Traffic Monitor (NTM)"
echo "   → Real-time traffic analysis"
echo "   → C2 beaconing detection"
echo "   → Data exfiltration monitoring"
echo ""
echo "2. Ransomware Behavior Detector (RBD)"
echo "   → Mass encryption detection"
echo "   → File entropy analysis"
echo "   → Backup tampering alerts"
echo ""
echo "3. Active Directory Monitor (ADSM)"
echo "   → Golden/Silver Ticket detection"
echo "   → GPO change monitoring"
echo "   → Domain security (Windows only)"
echo ""
echo "4. Run All Tools (Recommended)"
echo ""
echo "5. Exit"
echo ""
read -p "Select tool [1-5]: " TOOL_CHOICE

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "MONITORING MODE"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "1. Quick Test (5 minutes)"
echo "2. Short Monitoring (1 hour)"
echo "3. Full Monitoring (24 hours)"
echo ""
read -p "Select mode [1-3]: " MODE_CHOICE

# Set duration based on choice
case $MODE_CHOICE in
    1)
        DURATION=300
        INTERVAL=30
        MODE_NAME="Quick Test"
        ;;
    2)
        DURATION=3600
        INTERVAL=60
        MODE_NAME="Short Monitoring"
        ;;
    3)
        DURATION=86400
        INTERVAL=300
        MODE_NAME="Full Monitoring"
        ;;
    *)
        echo "[✗] Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "[✓] Mode: $MODE_NAME"
echo "[✓] Duration: ${DURATION}s | Interval: ${INTERVAL}s"

# Create logs directory
mkdir -p ./logs
echo ""
echo "[✓] Log directory: ./logs"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "STARTING TOOLS"
echo "════════════════════════════════════════════════════════════════"
echo ""

case $TOOL_CHOICE in
    1)
        echo "[*] Starting Network Traffic Monitor..."
        echo ""
        python3 network_traffic_monitor.py --monitor --duration $DURATION --interval $INTERVAL --export ./logs/ntm_results.json
        ;;
    2)
        echo "[*] Starting Ransomware Behavior Detector..."
        echo ""
        python3 ransomware_detector.py --monitor --duration $DURATION --interval $INTERVAL --export ./logs/rbd_results.json
        ;;
    3)
        if [[ "$OS" == "windows" ]]; then
            echo "[*] Starting Active Directory Monitor..."
            echo ""
            python ad_monitor.py --scan --export ./logs/adsm_results.json
        else
            echo "[✗] Active Directory Monitor is Windows-only"
            exit 1
        fi
        ;;
    4)
        echo "[*] Starting all tools in background..."
        echo ""
        
        python3 network_traffic_monitor.py --monitor --duration $DURATION --interval $INTERVAL --export ./logs/ntm_results.json &
        NTM_PID=$!
        echo "[✓] Network Traffic Monitor started (PID: $NTM_PID)"
        
        python3 ransomware_detector.py --monitor --duration $DURATION --interval $INTERVAL --export ./logs/rbd_results.json &
        RBD_PID=$!
        echo "[✓] Ransomware Detector started (PID: $RBD_PID)"
        
        if [[ "$OS" == "windows" ]]; then
            python ad_monitor.py --scan --export ./logs/adsm_results.json &
            ADSM_PID=$!
            echo "[✓] AD Monitor started (PID: $ADSM_PID)"
        fi
        
        echo ""
        echo "[*] All tools running. Press Ctrl+C to stop."
        echo ""
        
        # Wait for background processes
        wait $NTM_PID 2>/dev/null
        wait $RBD_PID 2>/dev/null
        ;;
    5)
        echo "[*] Exiting..."
        exit 0
        ;;
    *)
        echo "[✗] Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "MONITORING COMPLETE"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "[✓] Results saved to ./logs/"
echo ""
echo "Next steps:"
echo "  1. Review results: cat ./logs/*.json"
echo "  2. Check for alerts: grep -i critical ./logs/*.json"
echo "  3. Set up continuous monitoring (see docs/INTEGRATION_GUIDE.md)"
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    MONITORING SESSION COMPLETE                 ║"
echo "╚════════════════════════════════════════════════════════════════╝"
