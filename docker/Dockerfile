# Security Suite v5.0 - Complete Docker Build
# Tests all tools from all versions (v4.1 + v5.0 + orchestrator)

FROM ubuntu:22.04

LABEL maintainer="John Drexler <drex.john@gmail.com>"
LABEL description="Security Suite v5.0 - ML-Powered Network Security Monitoring"
LABEL version="5.0"

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    tcpdump \
    net-tools \
    iputils-ping \
    iproute2 \
    git \
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Create directory structure
RUN mkdir -p /opt/security_suite \
    /var/lib/security_suite/pcap \
    /var/lib/security_suite/alerts \
    /var/lib/security_suite/models \
    /var/log/security_suite \
    /tmp/test_data

# Set working directory
WORKDIR /opt/security_suite

# Clone repository (or copy local files)
ARG GITHUB_REPO=https://github.com/jDrex82/security-suite.git
ARG GITHUB_BRANCH=main

# Option 1: Clone from GitHub (uncomment for production)
# RUN git clone --branch ${GITHUB_BRANCH} ${GITHUB_REPO} . || \
#     echo "Note: Using COPY instead of git clone"

# Option 2: Copy local files (for testing)
COPY . /opt/security_suite/

# Verify structure
RUN echo "=== Directory Structure ===" && \
    ls -la /opt/security_suite/ && \
    echo "" && \
    echo "=== Checking modules ===" && \
    ls -la /opt/security_suite/v4_1_tools/ 2>/dev/null || echo "v4_1_tools not found" && \
    ls -la /opt/security_suite/v5_ml_engine/ 2>/dev/null || echo "v5_ml_engine not found" && \
    ls -la /opt/security_suite/data_ingestion/ 2>/dev/null || echo "data_ingestion not found" && \
    ls -la /opt/security_suite/orchestrator/ 2>/dev/null || echo "orchestrator not found"

# Set permissions
RUN chmod +x /opt/security_suite/v4_1_tools/*.py 2>/dev/null || true && \
    chmod +x /opt/security_suite/v5_ml_engine/*.py 2>/dev/null || true && \
    chmod +x /opt/security_suite/data_ingestion/*.py 2>/dev/null || true && \
    chmod +x /opt/security_suite/orchestrator/*.py 2>/dev/null || true && \
    chmod +x /opt/security_suite/orchestrator/*.sh 2>/dev/null || true

# Set proper permissions for log directories
RUN chmod 777 /var/lib/security_suite/pcap \
    /var/lib/security_suite/alerts \
    /var/log/security_suite

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD test -f /var/run/security_suite.pid && ps -p $(cat /var/run/security_suite.pid) || exit 1

# Expose ports (if adding web dashboard later)
# EXPOSE 8080

# Default command: run test suite
CMD ["/opt/security_suite/docker/run_tests_v2.sh"]
