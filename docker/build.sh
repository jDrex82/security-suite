#!/bin/bash
# Docker Build Helper for Security Suite v5.0

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

echo "=============================================================================="
echo "           Security Suite v5.0 - Docker Build Helper                         "
echo "=============================================================================="
echo ""

function show_help() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build       - Build Docker image"
    echo "  test        - Build and run tests"
    echo "  run         - Build and run orchestrator"
    echo "  shell       - Build and open interactive shell"
    echo "  compose     - Build and start with docker-compose"
    echo "  clean       - Remove images and containers"
    echo "  help        - Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 build          # Build image"
    echo "  $0 test           # Build and test"
    echo "  $0 shell          # Interactive mode"
    echo ""
}

function build_image() {
    echo "[*] Building Docker image..."
    echo "    Context: $PROJECT_DIR"
    echo "    Dockerfile: $SCRIPT_DIR/Dockerfile"
    echo ""
    
    cd "$PROJECT_DIR"
    docker build \
        -t security-suite:v5.0 \
        -t security-suite:latest \
        -f docker/Dockerfile \
        .
    
    echo ""
    echo "[+] Build complete!"
    docker images security-suite
}

function run_tests() {
    echo "[*] Building and running tests..."
    echo ""
    
    build_image
    
    echo ""
    echo "[*] Running test suite..."
    echo ""
    
    docker run --rm security-suite:v5.0
}

function run_orchestrator() {
    echo "[*] Building and running orchestrator..."
    echo ""
    
    build_image
    
    echo ""
    echo "[*] Starting orchestrator daemon..."
    echo ""
    
    docker run -d \
        --name security-suite \
        --privileged \
        --network host \
        --restart unless-stopped \
        security-suite:v5.0 \
        python3 /opt/security_suite/orchestrator/orchestrator_daemon.py
    
    echo ""
    echo "[+] Orchestrator started!"
    echo ""
    echo "Commands:"
    echo "  docker logs -f security-suite           # View logs"
    echo "  docker exec security-suite tail -f /var/log/security_suite/alerts.log  # View alerts"
    echo "  docker stop security-suite              # Stop"
    echo ""
}

function run_shell() {
    echo "[*] Building and opening interactive shell..."
    echo ""
    
    build_image
    
    echo ""
    echo "[*] Starting shell..."
    echo ""
    
    docker run -it --rm \
        --privileged \
        --network host \
        security-suite:v5.0 \
        /bin/bash
}

function run_compose() {
    echo "[*] Starting with docker-compose..."
    echo ""
    
    cd "$SCRIPT_DIR"
    docker-compose up --build
}

function clean() {
    echo "[*] Cleaning up Docker artifacts..."
    echo ""
    
    # Stop and remove container
    docker stop security-suite 2>/dev/null || true
    docker rm security-suite 2>/dev/null || true
    
    # Remove images
    docker rmi security-suite:v5.0 2>/dev/null || true
    docker rmi security-suite:latest 2>/dev/null || true
    
    # Remove volumes (optional)
    read -p "Remove volumes too? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cd "$SCRIPT_DIR"
        docker-compose down -v
        echo "[+] Volumes removed"
    fi
    
    echo ""
    echo "[+] Cleanup complete!"
}

# Main
case "${1:-help}" in
    build)
        build_image
        ;;
    test)
        run_tests
        ;;
    run)
        run_orchestrator
        ;;
    shell)
        run_shell
        ;;
    compose)
        run_compose
        ;;
    clean)
        clean
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
