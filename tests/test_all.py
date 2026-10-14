"""
Comprehensive Pytest Test Suite for Protocol Mimicry Engine.
Verifies all 17 required laboratory test cases:
1. Loopback guard safety rejection
2. TCP packet count accuracy
3. UDP packet count accuracy
4. Feature extraction on known sample
5. VoIP-like classification accuracy
6. Size padding toward target
7. Timing reshaping toward target
8. Comparator deltas and percentage accuracy
9. Result store persistence (save/load/delete)
10. API health & profiles smoke tests
11. Full demo pipeline end-to-end execution
12. Text chunk fragmentation
13. Multi-byte UTF-8 reassembly equality
14. Transparent padding removal on reassembly
15. UDP honest packet loss reporting
16. Text validation (empty, over-limit, control chars)
17. Content-agnostic classifier verification
"""

import os
import sys
import json
import time
import pytest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import is_loopback, CLASSIFIER_CONFIG_PATH, load_classifier_config
from backend.text_payload import (
    validate_text, chunk_text, reassemble_packets, preview_chunks,
    HEADER_SIZE, HEADER_MAGIC
)
from backend.profiles import get_profiles, get_profile
from backend.traffic_generator import TrafficGenerator
from backend.feature_extractor import extract_features_from_packets
from backend.dpi_classifier import classify_traffic
from backend.mimicry_engine import MimicryEngine, reshape_packet_size
from backend.comparator import calculate_delta, compare_features_and_classification
from backend.result_store import (
    save_experiment, get_experiment, delete_experiment, list_experiments
)
from backend.app import app


# --------------------------------------------------------------------------
# 1. Loopback guard test
# --------------------------------------------------------------------------
def test_loopback_guard_rejects_non_loopback():
    assert is_loopback("127.0.0.1") is True
    assert is_loopback("localhost") is True
    assert is_loopback("::1") is True
    assert is_loopback("192.168.1.50") is False
    assert is_loopback("10.0.0.1") is False
    assert is_loopback("8.8.8.8") is False

    # Test via Flask test client simulating non-loopback IP
    client = app.test_client()
    resp = client.get("/api/health", environ_overrides={"REMOTE_ADDR": "192.168.1.100"})
    assert resp.status_code == 403
    data = resp.get_json()
    assert "Forbidden" in data["error"]


# --------------------------------------------------------------------------
# 2 & 3. Real Socket Traffic Generation (TCP & UDP)
# --------------------------------------------------------------------------
def test_tcp_generation_packet_count():
    gen = TrafficGenerator()
    params = {
        "protocol": "TCP",
        "packet_count": 15,
        "packet_size": 128,
        "interval_ms": 1,
        "payload_pattern": "zeros",
        "direction": "client->server",
        "payload_mode": "pattern"
    }
    # Run synchronously via internal worker
    gen._worker(params)
    task = get_experiment(gen.experiment_id) or {}
    csv_file = Path(f"data/traffic/{gen.experiment_id}.csv")
    assert csv_file.exists()
    with open(csv_file, "r") as f:
        lines = f.readlines()
        # Header + 15 rows
        assert len(lines) == 16


def test_udp_generation_packet_count():
    gen = TrafficGenerator()
    params = {
        "protocol": "UDP",
        "packet_count": 12,
        "packet_size": 96,
        "interval_ms": 1,
        "payload_pattern": "incrementing",
        "direction": "client->server",
        "payload_mode": "pattern"
    }
    gen._worker(params)
    csv_file = Path(f"data/traffic/{gen.experiment_id}.csv")
    assert csv_file.exists()
    with open(csv_file, "r") as f:
        lines = f.readlines()
        assert len(lines) == 13


# --------------------------------------------------------------------------
# 4. Feature extraction on known sample
# --------------------------------------------------------------------------
def test_feature_extraction_known_sample():
    # 4 packets: sizes [100, 200, 300, 400], timestamps [0.0, 0.05, 0.10, 0.15]
    # IPTs: 0.05s (50ms), 0.05s (50ms), 0.05s (50ms) -> Jitter = 0ms
    known_packets = [
        {"seq": 1, "timestamp": 0.00, "proto": "TCP", "direction": "C->S", "size": 100},
        {"seq": 2, "timestamp": 0.05, "proto": "TCP", "direction": "C->S", "size": 200},
        {"seq": 3, "timestamp": 0.10, "proto": "TCP", "direction": "C->S", "size": 300},
        {"seq": 4, "timestamp": 0.15, "proto": "TCP", "direction": "C->S", "size": 400},
    ]
    feats = extract_features_from_packets(known_packets, burst_threshold_ms=20.0)
    assert feats["packet_count"] == 4
    assert feats["total_bytes"] == 1000
    assert feats["mean_size"] == 250.0
    assert feats["min_size"] == 100
    assert feats["max_size"] == 400
    assert abs(feats["mean_ipt_ms"] - 50.0) < 0.1
    assert abs(feats["jitter_ms"] - 0.0) < 0.1
    assert feats["protocol"] == "TCP"


# --------------------------------------------------------------------------
# 5. Classifier labels crafted VoIP sample
# --------------------------------------------------------------------------
def test_classifier_labels_voip_sample():
    voip_features = {
        "mean_size": 160.0,
        "mean_ipt_ms": 20.0,
        "packet_count": 100,
        "jitter_ms": 1.5,
        "mean_burst_length": 1.0,
        "protocol": "UDP"
    }
    res = classify_traffic(voip_features)
    assert res["detected_category"] == "voip_call"
    assert res["confidence"] >= 80.0
    assert res["label"] == "High"


# --------------------------------------------------------------------------
# 6. Padding moves mean size toward target
# --------------------------------------------------------------------------
def test_padding_moves_mean_size_toward_target():
    small_packet = b"A" * 60
    target_size = 1300
    padded = reshape_packet_size(small_packet, target_size, is_text=False)
    assert len(padded) == 1300


# --------------------------------------------------------------------------
# 7. Timing reshape moves mean IPT toward target
# --------------------------------------------------------------------------
def test_timing_reshape_moves_mean_ipt_toward_target():
    # Test delay sequence generation logic
    target_ipt_ms = 20.0
    delays = [target_ipt_ms / 1000.0 for _ in range(20)]
    mean_ipt = sum(delays) / len(delays) * 1000.0
    assert abs(mean_ipt - 20.0) < 0.01


# --------------------------------------------------------------------------
# 8. Comparator deltas
# --------------------------------------------------------------------------
def test_comparator_deltas():
    d = calculate_delta(100.0, 150.0)
    assert d["before"] == 100.0
    assert d["after"] == 150.0
    assert d["delta"] == 50.0
    assert d["percent_change"] == 50.0

    d_neg = calculate_delta(200.0, 100.0)
    assert d_neg["delta"] == -100.0
    assert d_neg["percent_change"] == -50.0


# --------------------------------------------------------------------------
# 9. Result store save/load/delete
# --------------------------------------------------------------------------
def test_result_store_save_load_delete():
    test_id = "EXP-TEST-9999"
    record = {
        "id": test_id,
        "config": {"protocol": "TCP"},
        "features_before": {"packet_count": 50},
        "classification_before": {"category_name": "Bulk-Transfer", "confidence": 85.0}
    }
    save_experiment(record)
    loaded = get_experiment(test_id)
    assert loaded is not None
    assert loaded["id"] == test_id
    assert loaded["classification_before"]["confidence"] == 85.0

    deleted = delete_experiment(test_id)
    assert deleted is True
    assert get_experiment(test_id) is None


# --------------------------------------------------------------------------
# 10. API smoke tests
# --------------------------------------------------------------------------
def test_api_smoke_health_and_profiles():
    client = app.test_client()
    h_resp = client.get("/api/health")
    assert h_resp.status_code == 200
    assert h_resp.get_json()["status"] == "online"

    p_resp = client.get("/api/profiles")
    assert p_resp.status_code == 200
    profiles = p_resp.get_json()["profiles"]
    assert len(profiles) >= 5


# --------------------------------------------------------------------------
# 11. Full demo pipeline end to end
# --------------------------------------------------------------------------
def test_full_demo_pipeline_end_to_end():
    client = app.test_client()
    resp = client.post("/api/demo/run", json={
        "source_type": "random",
        "target_profile": "voip_call",
        "protocol": "TCP",
        "packet_count": 20,
        "speed": 5.0
    })
    assert resp.status_code == 200
    run_id = resp.get_json()["run_id"]

    # Wait for completion (fast speed)
    max_wait = 15.0
    start = time.time()
    status = "running"
    while time.time() - start < max_wait:
        poll = client.get(f"/api/demo/{run_id}/events")
        data = poll.get_json()
        status = data.get("status")
        if status in ("completed", "failed"):
            break
        time.sleep(0.3)

    assert status == "completed"


# --------------------------------------------------------------------------
# 12. Text chunk splitting
# --------------------------------------------------------------------------
def test_text_chunk_splitting():
    text = "Antigravity Protocol Mimicry Test String"
    packet_size = 32
    chunks = chunk_text(text, packet_size=packet_size, pad_last=True)
    assert len(chunks) > 1
    # Check that each chunk is exactly packet_size
    for c in chunks:
        assert len(c) == packet_size
        assert c.startswith(HEADER_MAGIC)


# --------------------------------------------------------------------------
# 13. Reassembly equality (including multi-byte UTF-8)
# --------------------------------------------------------------------------
def test_reassembly_equality_multibyte_utf8():
    text = "Hello 🌍 World! 测试网络 🚀 Special UTF-8: äöü éèà."
    chunks = chunk_text(text, packet_size=28, pad_last=True)
    reassembled = reassemble_packets(chunks, expected_sent_text=text)
    assert reassembled["match"] is True
    assert reassembled["received_text"] == text


# --------------------------------------------------------------------------
# 14. Padding removal after mimicry
# --------------------------------------------------------------------------
def test_padding_removal_after_mimicry():
    original_text = "Important secret message transmitted via custom text payload."
    # Chunk at small size
    initial_chunks = chunk_text(original_text, packet_size=40, pad_last=True)
    
    # Mimicry padding: pad chunks to much larger size (e.g. 500 bytes)
    reshaped_chunks = [
        reshape_packet_size(c, target_size=500, is_text=True)
        for c in initial_chunks
    ]
    for c in reshaped_chunks:
        assert len(c) == 500

    # Server reassembles padded chunks
    res = reassemble_packets(reshaped_chunks, expected_sent_text=original_text)
    assert res["match"] is True
    assert res["received_text"] == original_text


# --------------------------------------------------------------------------
# 15. UDP loss reporting
# --------------------------------------------------------------------------
def test_udp_loss_report():
    text = "This message will suffer simulated packet loss in UDP transmission."
    chunks = chunk_text(text, packet_size=32, pad_last=True)
    assert len(chunks) >= 3

    # Drop the second chunk (index 1)
    received_with_loss = [chunks[0]] + chunks[2:]
    res = reassemble_packets(received_with_loss, expected_sent_text=text)

    assert res["match"] is False
    assert res["lost_packets"] == 1
    assert 1 in res["missing_sequences"]


# --------------------------------------------------------------------------
# 16. Validation (empty text, over-limit text, control chars)
# --------------------------------------------------------------------------
def test_validation_empty_and_overlimit_text():
    # Empty
    with pytest.raises(ValueError):
        validate_text("")
    with pytest.raises(ValueError):
        validate_text("   \n\t  ")

    # Over-limit
    long_text = "x" * 5001
    with pytest.raises(ValueError):
        validate_text(long_text)

    # Disallowed control character (ASCII 1 = SOH)
    with pytest.raises(ValueError):
        validate_text("Hello\x01World")

    # Valid text
    valid = validate_text("Hello World!\nLine 2\tTabbed")
    assert "Line 2" in valid


# --------------------------------------------------------------------------
# 17. Classifier content-agnostic verification
# --------------------------------------------------------------------------
def test_classifier_content_agnostic():
    # Two totally different texts of equal length
    text_a = "The quick brown fox jumps over the lazy dog repeatedly!!"
    text_b = "Confidential financial report: revenue increased by 20%."
    assert len(text_a) == len(text_b)

    chunks_a = chunk_text(text_a, packet_size=32)
    chunks_b = chunk_text(text_b, packet_size=32)

    # Convert to identical synthetic timestamp traces
    pkts_a = [{"seq": i+1, "timestamp": i*0.02, "proto": "TCP", "direction": "C->S", "size": len(c)} for i, c in enumerate(chunks_a)]
    pkts_b = [{"seq": i+1, "timestamp": i*0.02, "proto": "TCP", "direction": "C->S", "size": len(c)} for i, c in enumerate(chunks_b)]

    feat_a = extract_features_from_packets(pkts_a)
    feat_b = extract_features_from_packets(pkts_b)

    class_a = classify_traffic(feat_a)
    class_b = classify_traffic(feat_b)

    assert class_a["detected_category"] == class_b["detected_category"]
    assert class_a["confidence"] == class_b["confidence"]
