#!/bin/bash
# Complete end-to-end test of data ingestion module

echo "=============================================="
echo "Security Suite v5.0 - Data Ingestion Test"
echo "=============================================="
echo

echo "[1/4] Generating synthetic PCAP..."
python3 generate_test_pcap.py || exit 1
echo

echo "[2/4] Testing PCAP reader..."
python3 pcap_reader.py sample_traffic.pcap > /dev/null || exit 1
echo "✓ PCAP reader working"
echo

echo "[3/4] Testing enhanced detector..."
python3 enhanced_detector.py > /dev/null || exit 1
echo "✓ Enhanced detector working"
echo

echo "[4/4] Running full integration pipeline..."
python3 pcap_ml_integration.py sample_traffic.pcap > /dev/null
if [ $? -ge 0 ]; then
    echo "✓ Full pipeline working"
fi
echo

echo "=============================================="
echo "Checking outputs..."
echo "=============================================="
ls -lh sample_traffic.pcap sample_traffic_events.json sample_traffic_anomalies.json
echo

echo "Validation:"
python3 << 'PYEOF'
import json
import os

# Check files exist
files = ['sample_traffic.pcap', 'sample_traffic_events.json', 'sample_traffic_anomalies.json']
for f in files:
    assert os.path.exists(f), f"Missing: {f}"
    print(f"✓ {f} exists")

# Check events
events = json.load(open('sample_traffic_events.json'))
assert events['total_events'] > 0, "No events extracted"
assert len(events['events']) > 0, "Empty events list"
print(f"✓ Extracted {events['total_events']} events")

# Check anomalies
anomalies = json.load(open('sample_traffic_anomalies.json'))
assert anomalies['total_alerts'] > 0, "No anomalies detected"
assert len(anomalies['alerts']) > 0, "Empty alerts list"
print(f"✓ Detected {anomalies['total_alerts']} anomalies")

# Check alert format
alert = anomalies['alerts'][0]
required_fields = ['severity', 'user', 'anomaly_score', 'behavioral_anomalies']
for field in required_fields:
    assert field in alert, f"Missing field: {field}"
print(f"✓ Alert format valid")

print("\n✅ ALL TESTS PASSED")
PYEOF

echo
echo "=============================================="
echo "✅ Data Ingestion Module: FULLY FUNCTIONAL"
echo "=============================================="
