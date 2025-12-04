#!/bin/bash
# QUICKSTART SCRIPT FOR ADVANCED SECURITY SUITE
# Run this on a fresh system to get immediate protection

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║     ADVANCED SECURITY SUITE - QUICK START DEPLOYMENT          ║"
echo "║                      Version 3.0.0                            ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    echo "[✓] Detected OS: Linux"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    OS="windows"
    echo "[✓] Detected OS: Windows"
else
    echo "[!] Unknown OS. Assuming Linux."
    OS="linux"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "STEP 1: Pre-flight Checks"
echo "════════════════════════════════════════════════════════════════"

# Check Python version
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo "[✓] Python 3 installed: $PYTHON_VERSION"
else
    echo "[✗] Python 3 not found. Please install Python 3.6 or higher."
    exit 1
fi

# Check permissions
if [[ $EUID -ne 0 ]] && [[ "$OS" == "linux" ]]; then
   echo "[!] Warning: Not running as root. Some features may be limited."
   echo "    For full functionality, run with: sudo ./QUICKSTART_ADVANCED.sh"
else
    echo "[✓] Running with elevated privileges"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "STEP 2: Tool Selection"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Which tools would you like to deploy?"
echo ""
echo "1) Network Traffic Monitor (NTM) - Real-time traffic analysis"
echo "2) Ransomware Behavior Detector (RBD) - Ransomware detection"
echo "3) Active Directory Monitor (ADSM) - AD security (Windows only)"
echo "4) All Tools (Recommended)"
echo ""
read -p "Select option [1-4]: " TOOL_CHOICE

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "STEP 3: Deployment Mode"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "1) Quick Test (5 minutes) - Immediate results"
echo "2) Short Monitoring (1 hour) - Good for initial testing"
echo "3) Full Monitoring (24 hours) - Production deployment"
echo ""
read -p "Select mode [1-3]: " MODE_CHOICE

# Set duration based on choice
case $MODE_CHOICE in
    1)
        DURATION=300
        INTERVAL=30
        MODE_NAME="Quick Test (5 min)"
        ;;
    2)
        DURATION=3600
        INTERVAL=60
        MODE_NAME="Short Monitoring (1 hour)"
        ;;
    3)
        DURATION=86400
        INTERVAL=300
        MODE_NAME="Full Monitoring (24 hours)"
        ;;
    *)
        echo "[✗] Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "[✓] Selected: $MODE_NAME"
echo "[✓] Duration: ${DURATION}s | Interval: ${INTERVAL}s"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "STEP 4: Creating Baselines"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Create baselines based on tool choice
case $TOOL_CHOICE in
    1)
        echo "[*] Creating Network Traffic Monitor baseline..."
        python3 network_traffic_monitor.py --baseline
        TOOLS="ntm"
        ;;
    2)
        echo "[*] Ransomware Detector doesn't require baseline"
        echo "[✓] Ready to monitor"
        TOOLS="rbd"
        ;;
    3)
        if [[ "$OS" == "windows" ]]; then
            echo "[*] Creating Active Directory baseline..."
            python ad_monitor.py --baseline
            TOOLS="adsm"
        else
            echo "[✗] Active Directory Monitor is Windows-only"
            exit 1
        fi
        ;;
    4)
        echo "[*] Creating baselines for all tools..."
        python3 network_traffic_monitor.py --baseline
        if [[ "$OS" == "windows" ]]; then
            python ad_monitor.py --baseline
        fi
        echo "[✓] Baselines created"
        TOOLS="all"
        ;;
    *)
        echo "[✗] Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "STEP 5: Starting Monitoring"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Create log directory
mkdir -p ./logs
echo "[✓] Log directory created: ./logs"

echo ""
echo "[*] Starting monitoring tools..."
echo "[*] Logs will be saved to ./logs/"
echo ""
echo "Press Ctrl+C to stop monitoring early"
echo ""

# Start tools based on selection
case $TOOL_CHOICE in
    1)
        echo "────────────────────────────────────────────────────────────────"
        echo "  NETWORK TRAFFIC MONITOR - ACTIVE"
        echo "────────────────────────────────────────────────────────────────"
        python3 network_traffic_monitor.py --monitor --duration $DURATION --interval $INTERVAL --export ./logs/ntm_results.json
        ;;
    2)
        echo "────────────────────────────────────────────────────────────────"
        echo "  RANSOMWARE BEHAVIOR DETECTOR - ACTIVE"
        echo "────────────────────────────────────────────────────────────────"
        python3 ransomware_detector.py --monitor --duration $DURATION --interval $INTERVAL --export ./logs/rbd_results.json
        ;;
    3)
        echo "────────────────────────────────────────────────────────────────"
        echo "  ACTIVE DIRECTORY MONITOR - SCANNING"
        echo "────────────────────────────────────────────────────────────────"
        python ad_monitor.py --scan --export ./logs/adsm_results.json
        ;;
    4)
        echo "────────────────────────────────────────────────────────────────"
        echo "  ALL TOOLS - ACTIVE"
        echo "────────────────────────────────────────────────────────────────"
        echo ""
        echo "[*] Starting Network Traffic Monitor in background..."
        python3 network_traffic_monitor.py --monitor --duration $DURATION --interval $INTERVAL --export ./logs/ntm_results.json &
        NTM_PID=$!
        
        echo "[*] Starting Ransomware Detector in background..."
        python3 ransomware_detector.py --monitor --duration $DURATION --interval $INTERVAL --export ./logs/rbd_results.json &
        RBD_PID=$!
        
        if [[ "$OS" == "windows" ]]; then
            echo "[*] Running Active Directory Monitor scan..."
            python ad_monitor.py --scan --export ./logs/adsm_results.json
        fi
        
        echo ""
        echo "[✓] All tools running in background"
        echo "    NTM PID: $NTM_PID"
        echo "    RBD PID: $RBD_PID"
        echo ""
        echo "[*] Monitoring for $DURATION seconds..."
        echo "[*] Press Ctrl+C to stop"
        
        # Wait for background processes
        wait $NTM_PID 2>/dev/null
        wait $RBD_PID 2>/dev/null
        ;;
esac

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "DEPLOYMENT COMPLETE"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "[✓] Monitoring session completed"
echo ""
echo "Results saved to:"
if [[ "$TOOLS" == "ntm" ]] || [[ "$TOOLS" == "all" ]]; then
    echo "  • Network Traffic Monitor: ./logs/ntm_results.json"
fi
if [[ "$TOOLS" == "rbd" ]] || [[ "$TOOLS" == "all" ]]; then
    echo "  • Ransomware Detector: ./logs/rbd_results.json"
fi
if [[ "$TOOLS" == "adsm" ]] || [[ "$TOOLS" == "all" ]]; then
    if [[ "$OS" == "windows" ]]; then
        echo "  • Active Directory Monitor: ./logs/adsm_results.json"
    fi
fi
echo ""
echo "Next Steps:"
echo "  1. Review the results in ./logs/*.json"
echo "  2. Check for any CRITICAL or HIGH severity alerts"
echo "  3. Configure continuous monitoring (see INTEGRATION_GUIDE.md)"
echo "  4. Set up SIEM integration for centralized logging"
echo ""
echo "For detailed documentation, see:"
echo "  • NEW_TOOLS_README.md - Tool documentation"
echo "  • INTEGRATION_GUIDE.md - Deployment guide"
echo "  • MANIFEST.md - Technical specifications"
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                   DEPLOYMENT SUCCESSFUL!                       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
