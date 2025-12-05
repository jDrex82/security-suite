# Data Ingestion Module - Installation Guide

## Quick Start (30 seconds)

### 1. Copy to your security-suite repo
```bash
cd /path/to/your/security-suite
cp -r /home/claude/security-suite/data_ingestion .
```

### 2. Copy base ML detector
```bash
# The enhanced detector needs login_anomaly_detector_ml.py
cp /mnt/user-data/uploads/login_anomaly_detector_ml.py data_ingestion/
```

### 3. Test it
```bash
cd data_ingestion
./run_full_test.sh
```

**Expected:** `✅ ALL TESTS PASSED`

---

## Usage

### Process PCAP
```bash
python3 pcap_ml_integration.py capture.pcap
# Output: capture_anomalies.json
```

### Live capture + analysis
```bash
sudo tcpdump -i eth1 -w capture.pcap port 22 or port 3389
python3 pcap_ml_integration.py capture.pcap
```

---

## Files

```
data_ingestion/
├── pcap_reader.py              # PCAP parser
├── enhanced_detector.py         # Optimized ML
├── pcap_ml_integration.py      # Full pipeline
├── generate_test_pcap.py       # Test data
├── run_full_test.sh            # Test script
└── README.md                   # Full docs
```

**Add:** `login_anomaly_detector_ml.py` (from v5_ml_engine)

---

## Next: Priority #3 - Orchestrator

Data ingestion is DONE. Ready for continuous operation.
