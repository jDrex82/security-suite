#!/bin/bash
# Security Suite Control Script
# Manage the orchestrator daemon

set -e

DAEMON_PID="/var/run/security_suite.pid"
LOG_FILE="/var/log/security_suite/daemon.log"
ALERT_LOG="/var/log/security_suite/alerts.log"

function show_status() {
    echo "=============================================="
    echo "Security Suite Status"
    echo "=============================================="
    
    if [ -f "$DAEMON_PID" ]; then
        PID=$(cat "$DAEMON_PID")
        if ps -p "$PID" > /dev/null 2>&1; then
            echo "Status: RUNNING (PID: $PID)"
            
            # Show stats
            UPTIME=$(ps -p "$PID" -o etime= | tr -d ' ')
            CPU=$(ps -p "$PID" -o %cpu= | tr -d ' ')
            MEM=$(ps -p "$PID" -o %mem= | tr -d ' ')
            
            echo "Uptime: $UPTIME"
            echo "CPU: ${CPU}%"
            echo "Memory: ${MEM}%"
            
            # Count files
            PCAP_COUNT=$(ls /var/lib/security_suite/pcap/*.pcap 2>/dev/null | wc -l)
            echo "Active PCAP files: $PCAP_COUNT"
            
            # Count alerts today
            if [ -f "$ALERT_LOG" ]; then
                TODAY=$(date +%Y-%m-%d)
                ALERT_COUNT=$(grep "$TODAY" "$ALERT_LOG" 2>/dev/null | wc -l)
                echo "Alerts today: $ALERT_COUNT"
            fi
        else
            echo "Status: STOPPED (stale PID file)"
            rm -f "$DAEMON_PID"
        fi
    else
        echo "Status: STOPPED"
    fi
    
    echo "=============================================="
}

function start_daemon() {
    echo "[*] Starting Security Suite Orchestrator..."
    
    if [ -f "$DAEMON_PID" ]; then
        PID=$(cat "$DAEMON_PID")
        if ps -p "$PID" > /dev/null 2>&1; then
            echo "[!] Already running (PID: $PID)"
            exit 1
        else
            rm -f "$DAEMON_PID"
        fi
    fi
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo "[ERROR] Must run as root"
        exit 1
    fi
    
    # Start daemon
    cd /opt/security_suite/orchestrator
    python3 orchestrator_daemon.py &
    
    sleep 2
    
    if [ -f "$DAEMON_PID" ]; then
        echo "[+] Daemon started successfully"
        show_status
    else
        echo "[!] Failed to start daemon"
        exit 1
    fi
}

function stop_daemon() {
    echo "[*] Stopping Security Suite Orchestrator..."
    
    if [ ! -f "$DAEMON_PID" ]; then
        echo "[!] Not running"
        exit 1
    fi
    
    PID=$(cat "$DAEMON_PID")
    
    if ! ps -p "$PID" > /dev/null 2>&1; then
        echo "[!] Not running (stale PID)"
        rm -f "$DAEMON_PID"
        exit 1
    fi
    
    # Send SIGTERM
    kill -TERM "$PID"
    
    # Wait for shutdown
    for i in {1..10}; do
        if ! ps -p "$PID" > /dev/null 2>&1; then
            echo "[+] Daemon stopped"
            rm -f "$DAEMON_PID"
            return
        fi
        sleep 1
    done
    
    # Force kill if still running
    echo "[!] Daemon not responding, forcing shutdown..."
    kill -KILL "$PID"
    rm -f "$DAEMON_PID"
    echo "[+] Daemon killed"
}

function restart_daemon() {
    stop_daemon
    sleep 2
    start_daemon
}

function show_logs() {
    if [ -f "$LOG_FILE" ]; then
        tail -f "$LOG_FILE"
    else
        echo "[!] Log file not found: $LOG_FILE"
        exit 1
    fi
}

function show_alerts() {
    if [ -f "$ALERT_LOG" ]; then
        tail -f "$ALERT_LOG"
    else
        echo "[!] Alert log not found: $ALERT_LOG"
        exit 1
    fi
}

function show_help() {
    echo "Security Suite Control Script"
    echo ""
    echo "Usage: $0 {start|stop|restart|status|logs|alerts}"
    echo ""
    echo "Commands:"
    echo "  start    - Start the orchestrator daemon"
    echo "  stop     - Stop the orchestrator daemon"
    echo "  restart  - Restart the orchestrator daemon"
    echo "  status   - Show daemon status and stats"
    echo "  logs     - Tail daemon logs (Ctrl+C to exit)"
    echo "  alerts   - Tail alert logs (Ctrl+C to exit)"
    echo ""
}

# Main
case "$1" in
    start)
        start_daemon
        ;;
    stop)
        stop_daemon
        ;;
    restart)
        restart_daemon
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs
        ;;
    alerts)
        show_alerts
        ;;
    *)
        show_help
        exit 1
        ;;
esac
