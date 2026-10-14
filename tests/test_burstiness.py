"""
Automated Test Suite for Burstiness Cluster Detection and Metrics.
Verifies:
1. 10 transmissions separated by 10 ms intervals: exactly 1 cluster containing 10 transmissions (100% burst, 0% isolated).
2. 10 transmissions separated by 100 ms intervals: 0 clusters, 0 burst transmissions (0% burst, 100% isolated).
3. Two bursts separated by a long idle interval.
4. A burst containing exactly two transmissions.
5. Exactly 20 ms between arrivals according to documented threshold rule (< 20ms belongs to burst).
6. Empty trace and one-transmission trace handling without NaN or infinity.
7. Duplicate timestamps and unsorted input handling.
8. Missing or malformed timestamps handling.
9. Feature extraction and JSON serialization via API.
10. Burst and isolated ratio sum invariants (burst_cluster_ratio + isolated_transmission_ratio == 1.0).
"""

import pytest
from backend.app import app
from backend.feature_extractor import detect_burst_clusters, extract_features_from_packets


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestBurstClusterDetection:
    """Unit tests for the mathematical burst cluster detection algorithm."""

    def test_ten_transmissions_at_10ms_single_cluster(self):
        """10 transmissions separated by 10 ms intervals: 1 burst cluster containing all 10 transmissions."""
        # 10 packets: timestamps 0.000, 0.010, 0.020, ..., 0.090 seconds
        timestamps = [i * 0.010 for i in range(10)]
        res = detect_burst_clusters(timestamps, burst_threshold_ms=20.0)

        assert res["total_transmissions"] == 10
        assert res["burst_cluster_count"] == 1
        assert res["transmissions_in_bursts"] == 10
        assert res["isolated_transmission_count"] == 0
        assert res["burst_cluster_ratio"] == 1.0
        assert res["isolated_transmission_ratio"] == 0.0
        assert res["burst_threshold_ms"] == 20.0
        assert res["clusters"] == [10]
        assert res["mean_burst_length"] == 10.0
        assert res["burst_cluster_ratio"] + res["isolated_transmission_ratio"] == pytest.approx(1.0)

    def test_ten_transmissions_at_100ms_zero_clusters(self):
        """10 transmissions separated by 100 ms intervals: 0 burst clusters and 10 isolated transmissions."""
        # 10 packets: timestamps 0.0, 0.1, 0.2, ..., 0.9 seconds
        timestamps = [i * 0.100 for i in range(10)]
        res = detect_burst_clusters(timestamps, burst_threshold_ms=20.0)

        assert res["total_transmissions"] == 10
        assert res["burst_cluster_count"] == 0
        assert res["transmissions_in_bursts"] == 0
        assert res["isolated_transmission_count"] == 10
        assert res["burst_cluster_ratio"] == 0.0
        assert res["isolated_transmission_ratio"] == 1.0
        assert res["clusters"] == []
        assert res["burst_cluster_ratio"] + res["isolated_transmission_ratio"] == pytest.approx(1.0)

    def test_two_bursts_separated_by_long_idle(self):
        """Two distinct bursts separated by a long idle interval."""
        # Burst 1: 0, 5, 10 ms (3 packets, intervals 5ms)
        # Idle gap: 10ms -> 150ms (interval 140ms >= 20ms)
        # Burst 2: 150, 155, 160, 165 ms (4 packets, intervals 5ms)
        t_burst1 = [0.000, 0.005, 0.010]
        t_burst2 = [0.150, 0.155, 0.160, 0.165]
        timestamps = t_burst1 + t_burst2

        res = detect_burst_clusters(timestamps, burst_threshold_ms=20.0)
        assert res["total_transmissions"] == 7
        assert res["burst_cluster_count"] == 2
        assert res["clusters"] == [3, 4]
        assert res["transmissions_in_bursts"] == 7
        assert res["isolated_transmission_count"] == 0
        assert res["burst_cluster_ratio"] == 1.0
        assert res["isolated_transmission_ratio"] == 0.0
        assert res["mean_burst_length"] == 3.5

    def test_burst_containing_two_transmissions(self):
        """A burst cluster containing exactly two transmissions, plus an isolated packet."""
        # Packet 1 at 0.000s, Packet 2 at 0.012s (interval 12ms < 20ms -> cluster of 2)
        # Packet 3 at 0.100s (interval 88ms >= 20ms -> isolated)
        timestamps = [0.000, 0.012, 0.100]
        res = detect_burst_clusters(timestamps, burst_threshold_ms=20.0)

        assert res["total_transmissions"] == 3
        assert res["burst_cluster_count"] == 1
        assert res["clusters"] == [2]
        assert res["transmissions_in_bursts"] == 2
        assert res["isolated_transmission_count"] == 1
        assert res["burst_cluster_ratio"] == pytest.approx(2 / 3, abs=0.001)
        assert res["isolated_transmission_ratio"] == pytest.approx(1 / 3, abs=0.001)
        assert res["burst_cluster_ratio"] + res["isolated_transmission_ratio"] == pytest.approx(1.0)

    def test_exactly_twenty_ms_threshold_rule(self):
        """Arrivals separated by exactly 20 ms do not meet strict < 20 ms threshold."""
        # 3 packets separated by exactly 20.0 ms: 0.000, 0.020, 0.040
        timestamps = [0.000, 0.020, 0.040]
        res = detect_burst_clusters(timestamps, burst_threshold_ms=20.0)

        assert res["total_transmissions"] == 3
        assert res["burst_cluster_count"] == 0
        assert res["transmissions_in_bursts"] == 0
        assert res["isolated_transmission_count"] == 3
        assert res["burst_cluster_ratio"] == 0.0
        assert res["isolated_transmission_ratio"] == 1.0

        # Arrivals at 19.99 ms DO belong to a burst (< 20 ms)
        timestamps_under = [0.000, 0.01999]
        res_under = detect_burst_clusters(timestamps_under, burst_threshold_ms=20.0)
        assert res_under["burst_cluster_count"] == 1
        assert res_under["transmissions_in_bursts"] == 2
        assert res_under["isolated_transmission_count"] == 0

    def test_empty_trace_and_one_transmission_trace(self):
        """Handle empty and one-packet traces safely without NaN, ZeroDivisionError, or infinity."""
        # Empty trace
        res_empty = detect_burst_clusters([], burst_threshold_ms=20.0)
        assert res_empty["total_transmissions"] == 0
        assert res_empty["burst_cluster_count"] == 0
        assert res_empty["transmissions_in_bursts"] == 0
        assert res_empty["isolated_transmission_count"] == 0
        assert res_empty["burst_cluster_ratio"] == 0.0
        assert res_empty["isolated_transmission_ratio"] == 0.0
        assert res_empty["empty_data"] is True

        # One transmission trace
        res_single = detect_burst_clusters([0.050], burst_threshold_ms=20.0)
        assert res_single["total_transmissions"] == 1
        assert res_single["burst_cluster_count"] == 0
        assert res_single["transmissions_in_bursts"] == 0
        assert res_single["isolated_transmission_count"] == 1
        assert res_single["burst_cluster_ratio"] == 0.0
        assert res_single["isolated_transmission_ratio"] == 1.0
        assert res_single["empty_data"] is False

    def test_duplicate_timestamps_and_unsorted_input(self):
        """Handle duplicate timestamps (0 ms interval) and out-of-order input correctly."""
        # Unsorted list with duplicate timestamps
        raw = [0.080, 0.010, 0.010, 0.015]
        res = detect_burst_clusters(raw, burst_threshold_ms=20.0)

        # Sorted: 0.010, 0.010, 0.015 (burst of 3), 0.080 (isolated)
        assert res["total_transmissions"] == 4
        assert res["burst_cluster_count"] == 1
        assert res["clusters"] == [3]
        assert res["transmissions_in_bursts"] == 3
        assert res["isolated_transmission_count"] == 1
        assert res["burst_cluster_ratio"] == 0.75
        assert res["isolated_transmission_ratio"] == 0.25

    def test_missing_or_malformed_timestamps(self):
        """Filter out None, strings, or invalid inputs safely."""
        raw = [0.000, None, "malformed", 0.010, 0.015]
        res = detect_burst_clusters(raw, burst_threshold_ms=20.0)

        # 3 valid timestamps: 0.000, 0.010, 0.015 (all 1 burst of 3)
        assert res["total_transmissions"] == 3
        assert res["burst_cluster_count"] == 1
        assert res["transmissions_in_bursts"] == 3
        assert res["isolated_transmission_count"] == 0
        assert res["burst_cluster_ratio"] == 1.0


class TestFeatureExtractorIntegration:
    """Integration tests for extract_features_from_packets and API serialization."""

    def test_extract_features_burst_fields_presence(self):
        packets = [
            {"seq": 1, "timestamp": 0.000, "size": 512, "proto": "TCP", "direction": "C->S"},
            {"seq": 2, "timestamp": 0.010, "size": 512, "proto": "TCP", "direction": "C->S"},
            {"seq": 3, "timestamp": 0.020, "size": 512, "proto": "TCP", "direction": "C->S"},
            {"seq": 4, "timestamp": 0.150, "size": 512, "proto": "TCP", "direction": "C->S"}
        ]
        feat = extract_features_from_packets(packets, burst_threshold_ms=20.0)

        assert feat["total_transmissions"] == 4
        assert feat["burst_cluster_count"] == 1
        assert feat["transmissions_in_bursts"] == 3
        assert feat["isolated_transmission_count"] == 1
        assert feat["burst_cluster_ratio"] == 0.75
        assert feat["isolated_transmission_ratio"] == 0.25
        assert feat["burst_threshold_ms"] == 20.0
        assert feat["burst_cluster_ratio"] + feat["isolated_transmission_ratio"] == pytest.approx(1.0)

    def test_extract_features_empty_packet_list(self):
        feat = extract_features_from_packets([])
        assert feat["empty_data"] is True
        assert feat["packet_count"] == 0
        assert feat["total_transmissions"] == 0
        assert feat["burst_cluster_count"] == 0
        assert feat["burst_cluster_ratio"] == 0.0
        assert feat["isolated_transmission_ratio"] == 0.0

    def test_api_features_endpoint_returns_burst_metrics(self, client):
        # Generate a short traffic run to verify API output
        gen_res = client.post("/api/traffic/generate", json={
            "protocol": "TCP",
            "packet_count": 20,
            "packet_size": 256,
            "interval_ms": 10,  # 10ms pacing -> all 20 packets in 1 burst cluster under 20ms threshold
            "payload_mode": "pattern"
        })
        assert gen_res.status_code == 200
        exp_id = gen_res.get_json()["experiment_id"]

        import time
        for _ in range(40):
            time.sleep(0.1)
            st = client.get(f"/api/traffic/{exp_id}/status").get_json()
            if st.get("status") in ("completed", "failed"):
                break

        res = client.get(f"/api/features/{exp_id}?refresh=true")
        assert res.status_code == 200
        data = res.get_json()
        assert "features_before" in data
        fb = data["features_before"]

        # Validate all required burst metrics are serialized in the API response
        assert "burst_cluster_count" in fb
        assert "isolated_transmission_count" in fb
        assert "burst_cluster_ratio" in fb
        assert "isolated_transmission_ratio" in fb
        assert "burst_threshold_ms" in fb
        assert "total_transmissions" in fb
        assert "transmissions_in_bursts" in fb

        # Under 10ms intervals, transmissions must be in burst clusters
        assert fb["burst_cluster_count"] >= 1
        assert fb["transmissions_in_bursts"] > 0
        assert fb["burst_cluster_ratio"] > 0.0
        assert fb["burst_cluster_ratio"] + fb["isolated_transmission_ratio"] == pytest.approx(1.0)
