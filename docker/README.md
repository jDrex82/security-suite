# Docker Build & Test Guide - Security Suite v5.0

Complete Docker setup to build from GitHub and test all components.

## Quick Start

### Option 1: Docker Compose (Recommended)
```bash
cd docker
docker-compose build
docker-compose up
```

### Option 2: Docker CLI
```bash
cd docker
docker build -t security-suite:v5.0 -f Dockerfile ..
docker run --rm security-suite:v5.0
```

## What Gets Tested

The Docker container runs a comprehensive test suite that validates:

### ✅ Phase 1: Structure Validation
- Directory structure
- All module directories present
- Log and data directories

### ✅ Phase 2: Python Module Imports
- v4.1 tools import correctly
- v5.0 ML detectors import correctly
- Data ingestion modules import correctly
- Orchestrator imports correctly

### ✅ Phase 3: v4.1 Tools (Legacy Suite)
- Port scanner
- Network monitor
- Vulnerability scanner
- (All 26 legacy tools if present)

### ✅ Phase 4: v5.0 ML Engine
- Login anomaly detector (with synthetic data)
- IoT anomaly detector
- Network traffic detector
- ML model training and inference

### ✅ Phase 5: Data Ingestion (PCAP Processing)
- Test PCAP generation
- PCAP reader functionality
- Event extraction
- ML detection pipeline
- Alert generation

### ✅ Phase 6: Orchestrator (Daemon System)
- Module imports
- Configuration validation
- Control script syntax
- Thread management

### ✅ Phase 7: Integration Tests
- End-to-end workflow: PCAP → Events → ML → Alerts
- JSON output validation

### ✅ Phase 8: System Checks
- Python 3 available
- tcpdump available
- Git available
- Proper permissions

## Build Options

### Build from GitHub (Production)
```bash
docker build \
  --build-arg GITHUB_REPO=https://github.com/jDrex82/security-suite.git \
  --build-arg GITHUB_BRANCH=main \
  -t security-suite:v5.0 \
  -f docker/Dockerfile .
```

### Build from Local Files (Development)
```bash
# Default - uses COPY instead of git clone
docker build -t security-suite:v5.0-dev -f docker/Dockerfile .
```

## Run Modes

### 1. Test Mode (Default)
Runs comprehensive test suite:
```bash
docker run --rm security-suite:v5.0
```

**Expected output:**
```
==============================================================================
                SECURITY SUITE v5.0 - COMPREHENSIVE TEST
==============================================================================

PHASE 1: STRUCTURE VALIDATION
[1] Testing: Directory structure ... ✓ PASS
[2] Testing: v4.1 tools directory ... ✓ PASS
...

==============================================================================
                        ✅ ALL TESTS PASSED!
==============================================================================

Total Tests:  35
Passed:       35
Failed:       0
```

### 2. Production Mode (Orchestrator)
Run as 24/7 monitoring daemon:
```bash
docker run -d \
  --name security-suite \
  --privileged \
  --network host \
  -v $(pwd)/pcap:/var/lib/security_suite/pcap \
  -v $(pwd)/logs:/var/log/security_suite \
  security-suite:v5.0 \
  python3 /opt/security_suite/orchestrator/orchestrator_daemon.py
```

**Monitor logs:**
```bash
docker logs -f security-suite
```

**View alerts:**
```bash
docker exec security-suite tail -f /var/log/security_suite/alerts.log
```

### 3. Interactive Mode (Debug)
Get a shell inside the container:
```bash
docker run -it --rm security-suite:v5.0 /bin/bash
```

**Inside container:**
```bash
# Test individual components
cd /opt/security_suite/v5_ml_engine
python3 login_anomaly_detector_ml.py

# Generate PCAP and test
cd /opt/security_suite/data_ingestion
python3 generate_test_pcap.py
python3 pcap_ml_integration.py sample_traffic.pcap
```

## Docker Compose Commands

### Build and Start
```bash
cd docker
docker-compose up --build
```

### Run in Background
```bash
docker-compose up -d
```

### View Logs
```bash
docker-compose logs -f
```

### Stop
```bash
docker-compose down
```

### Clean Everything
```bash
docker-compose down -v  # Also removes volumes
```

## Customization

### Change Test Behavior
Edit `docker-compose.yml`:
```yaml
# Run orchestrator instead of tests
command: python3 /opt/security_suite/orchestrator/orchestrator_daemon.py

# Or interactive mode
command: /bin/bash
stdin_open: true
tty: true
```

### Change Network Interface
Edit `docker-compose.yml`:
```yaml
environment:
  - CAPTURE_INTERFACE=eth1  # Your SPAN port
```

### Mount Local Code (Development)
```yaml
volumes:
  - ../:/opt/security_suite  # Mount local files
```

## Troubleshooting

### Build Fails
```bash
# Check Docker version
docker --version  # Need 20.10+

# Clean build cache
docker system prune -a

# Rebuild without cache
docker build --no-cache -t security-suite:v5.0 -f docker/Dockerfile .
```

### Tests Fail
```bash
# Run interactively to debug
docker run -it --rm security-suite:v5.0 /bin/bash

# Check logs
ls /tmp/test_output_*.log

# Run specific test
cd /opt/security_suite/data_ingestion
python3 generate_test_pcap.py
```

### Permission Issues
```bash
# Make sure scripts are executable
chmod +x docker/run_tests.sh

# Check volumes
docker volume ls
docker volume inspect security-suite_pcap_data
```

## Production Deployment

### 1. Build Image
```bash
docker build -t security-suite:v5.0 -f docker/Dockerfile .
```

### 2. Test Image
```bash
docker run --rm security-suite:v5.0
# Should show: ✅ ALL TESTS PASSED!
```

### 3. Deploy with Compose
```bash
# Edit docker-compose.yml for production
# Change command to orchestrator
# Set proper network interface

docker-compose up -d
```

### 4. Monitor
```bash
# Check status
docker ps

# View logs
docker logs security-suite

# View alerts
docker exec security-suite tail -f /var/log/security_suite/alerts.log

# Check health
docker inspect --format='{{.State.Health.Status}}' security-suite
```

### 5. Auto-Start on Boot
```bash
# Add to docker-compose.yml:
restart: always

# Or with systemd:
sudo systemctl enable docker
```

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Test Security Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Build Docker image
        run: docker build -t security-suite:test -f docker/Dockerfile .
      
      - name: Run tests
        run: docker run --rm security-suite:test
      
      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v2
        with:
          name: test-results
          path: /tmp/test_output_*.log
```

## Performance

**Build time:** ~2-3 minutes  
**Image size:** ~500 MB  
**Test runtime:** ~60 seconds  
**Memory usage:** 256 MB - 1 GB  
**CPU usage:** 0.5 - 2.0 cores  

## File Structure

```
docker/
├── Dockerfile                 # Main build file
├── docker-compose.yml         # Orchestration config
├── .dockerignore             # Exclude files
├── run_tests.sh              # Test suite
└── README.md                 # This file
```

## Security Notes

### Privileged Mode
The container requires `--privileged` mode for tcpdump to capture packets. This is standard for network monitoring tools.

### Network Access
Use `--network host` to access the host's network interfaces. For SPAN port monitoring, this is required.

### Volumes
Mount volumes to persist data:
- PCAP files: `/var/lib/security_suite/pcap`
- Alerts: `/var/lib/security_suite/alerts`
- Logs: `/var/log/security_suite`

## Next Steps

1. **Test locally:**
   ```bash
   docker-compose up
   ```

2. **Push to registry:**
   ```bash
   docker tag security-suite:v5.0 yourregistry/security-suite:v5.0
   docker push yourregistry/security-suite:v5.0
   ```

3. **Deploy to production:**
   ```bash
   docker pull yourregistry/security-suite:v5.0
   docker-compose up -d
   ```

---

**Author:** John Drexler  
**Version:** 5.0  
**Date:** December 2025
