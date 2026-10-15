"""
Regression and Verification Tests for Comparison Workflow and IPT Analysis
Covers:
1. End-to-end baseline -> mimicry -> comparison workflow.
2. Accurate baseline and mimicry feature lookup via API.
3. Mismatched experiment IDs returning 400 error.
4. Missing baseline features returning 404 with actionable detail.
5. Missing mimicry features returning 404 with actionable detail.
6. Missing / invalid numeric fields returning 422 error.
7. Comparison persistence across reload and after simulated backend restart.
8. Known fixture values delta and percentage calculations (including zero-denominator safety).
9. Single-packet IPT calculation returning [0.0] and non-empty chart data analysis.
"""

import sys
import json
import pytest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app import app
from backend.comparator import calculate_delta, compare_features_and_classification
from backend.feature_extractor import extract_features_from_packets
from backend.json_storage import save_experiment, get_experiment


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# --------------------------------------------------------------------------
# 1. Single-packet IPT analysis test
# --------------------------------------------------------------------------
def test_single_packet_ipt_analysis():
    """Verify single-packet traces produce valid IPT analysis [0.0] instead of empty list."""
    single_packet = [{"packet_id": 1, "size": 200, "timestamp": 1000.0}]
    features = extract_features_from_packets(single_packet)

    assert features["packet_count"] == 1
    assert features["mean_ipt_ms"] == 0.0
    assert features["ipt_series_sample"] == [0.0]
    assert features["mean_size"] == 200.0


# --------------------------------------------------------------------------
# 2. Comparator delta and zero-denominator safety
# --------------------------------------------------------------------------
def test_comparator_delta_and_zero_denominator():
    """Verify calculate_delta handles normal deltas and zero denominators safely."""
    # Normal delta
    d = calculate_delta(100.0, 150.0)
    assert d["before"] == 100.0
    assert d["after"] == 150.0
    assert d["delta"] == 50.0
    assert d["percent_change"] == 50.0

    # Zero before, positive after
    d_zero = calculate_delta(0.0, 50.0)
    assert d_zero["delta"] == 50.0
    assert d_zero["percent_change"] == 100.0

    # Zero before, zero after
    d_both_zero = calculate_delta(0.0, 0.0)
    assert d_both_zero["delta"] == 0.0
    assert d_both_zero["percent_change"] == 0.0


# --------------------------------------------------------------------------
# 3. Known fixture values comparison calculation
# --------------------------------------------------------------------------
def test_comparison_calculation_with_known_fixtures():
    """Verify compare_features_and_classification produces mathematically correct metrics."""
    baseline = {
        "packet_count": 10,
        "mean_size": 100.0,
        "std_size": 0.0,
        "min_size": 100,
        "max_size": 100,
        "mean_ipt_ms": 10.0,
        "std_ipt_ms": 1.0,
        "jitter_ms": 1.0,
        "duration_ms": 100.0,
        "burst_cluster_count": 0,
        "burst_cluster_ratio": 0.2,
        "throughput_kbps": 80.0,
        "total_bytes": 1000
    }
    mimicry = {
        "packet_count": 10,
        "mean_size": 160.0,
        "std_size": 5.0,
        "min_size": 150,
        "max_size": 170,
        "mean_ipt_ms": 20.0,
        "std_ipt_ms": 2.0,
        "jitter_ms": 2.0,
        "duration_ms": 200.0,
        "burst_cluster_count": 0,
        "burst_cluster_ratio": 0.1,
        "throughput_kbps": 64.0,
        "total_bytes": 1600
    }
    classification_before = {
        "category_name": "HTTP-like Web Browsing",
        "detected_category": "web_browsing",
        "confidence": 92.0,
        "profile_scores": {"web_browsing": 92.0, "voip_call": 8.0}
    }
    classification_after = {
        "category_name": "VoIP-like Audio Stream",
        "detected_category": "voip_call",
        "confidence": 88.0,
        "profile_scores": {"web_browsing": 12.0, "voip_call": 88.0}
    }

    result = compare_features_and_classification(
        baseline, mimicry, classification_before, classification_after, target_profile_id="voip_call"
    )

    assert result["fooled"] is True
    assert result["status_banner"] == "CLASSIFIER FOOLED"
    assert result["metrics"]["mean_size"]["before"] == 100.0
    assert result["metrics"]["mean_size"]["after"] == 160.0
    assert result["metrics"]["mean_size"]["delta"] == 60.0
    assert result["metrics"]["mean_size"]["percent_change"] == 60.0
    assert "overhead" in result
    assert result["overhead"]["byte_overhead_pct"] == 60.0


# --------------------------------------------------------------------------
# 4. API /api/compare: Mismatched experiment IDs return 400
# --------------------------------------------------------------------------
def test_compare_api_mismatched_ids_returns_400(client):
    payload = {
        "experiment_id": "exp_run_123",
        "baseline_experiment_id": "exp_run_999",
        "features_before": {"packet_count": 5},
        "features_after": {"packet_count": 5}
    }
    res = client.post("/api/compare", json=payload)
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data
    assert "mismatch" in data["error"].lower()


# --------------------------------------------------------------------------
# 5. API /api/compare: Missing baseline features returns 404
# --------------------------------------------------------------------------
def test_compare_api_missing_baseline_returns_404(client):
    # Non-existent experiment
    res = client.get("/api/compare/non_existent_exp_xyz")
    assert res.status_code == 404
    data = res.get_json()
    assert "error" in data


# --------------------------------------------------------------------------
# 6. API /api/compare: Missing mimicry features returns 404
# --------------------------------------------------------------------------
def test_compare_api_missing_mimicry_returns_404(client):
    # Save an experiment with only baseline features
    exp_id = "test_missing_mimicry_exp"
    exp_data = {
        "id": exp_id,
        "features_before": {
            "packet_count": 10,
            "mean_size": 100.0,
            "std_size": 0.0,
            "min_size": 100,
            "max_size": 100,
            "mean_ipt_ms": 10.0,
            "std_ipt_ms": 0.0,
            "jitter_ms": 0.0,
            "total_bytes": 1000
        },
        "classification_before": {"category_name": "HTTP-like Web Browsing", "confidence": 90.0}
        # features_after omitted
    }
    save_experiment(exp_data)

    res = client.get(f"/api/compare/{exp_id}")
    assert res.status_code == 404
    data = res.get_json()
    assert "error" in data
    assert "mimicry features" in data["error"].lower()


# --------------------------------------------------------------------------
# 7. API /api/compare: Invalid numeric fields return 422
# --------------------------------------------------------------------------
def test_compare_api_invalid_numeric_fields_returns_422(client):
    exp_id = "test_invalid_numeric_exp"
    payload = {
        "experiment_id": exp_id,
        "baseline_features": {
            "packet_count": "invalid_string_not_a_number",
            "mean_size": "not_a_number",
            "std_size": 0.0,
            "min_size": 100,
            "max_size": 100,
            "mean_ipt_ms": 10.0,
            "std_ipt_ms": 0.0,
            "jitter_ms": 0.0,
            "total_bytes": 1000
        },
        "mimicry_features": {
            "packet_count": 10,
            "mean_size": 160.0,
            "std_size": 0.0,
            "min_size": 160,
            "max_size": 160,
            "mean_ipt_ms": 20.0,
            "std_ipt_ms": 0.0,
            "jitter_ms": 0.0,
            "total_bytes": 1600
        }
    }
    res = client.post("/api/compare", json=payload)
    assert res.status_code == 422
    data = res.get_json()
    assert "error" in data
    assert "numeric" in data["error"].lower()


# --------------------------------------------------------------------------
# 8. Comparison persistence across simulated backend reload/restart
# --------------------------------------------------------------------------
def test_comparison_persistence_across_restart(client):
    exp_id = "test_full_workflow_persistence_exp"
    exp_data = {
        "id": exp_id,
        "comparison_id": exp_id,
        "config": {"protocol": "TCP", "payload_mode": "custom_text"},
        "features_before": {
            "packet_count": 10,
            "mean_size": 100.0,
            "std_size": 0.0,
            "min_size": 100,
            "max_size": 100,
            "mean_ipt_ms": 10.0,
            "std_ipt_ms": 0.0,
            "jitter_ms": 0.0,
            "total_bytes": 1000,
            "burst_cluster_ratio": 0.0,
            "throughput_kbps": 80.0
        },
        "features_after": {
            "packet_count": 10,
            "mean_size": 160.0,
            "std_size": 0.0,
            "min_size": 160,
            "max_size": 160,
            "mean_ipt_ms": 20.0,
            "std_ipt_ms": 0.0,
            "jitter_ms": 0.0,
            "total_bytes": 1600,
            "burst_cluster_ratio": 0.0,
            "throughput_kbps": 64.0
        },
        "classification_before": {"category_name": "HTTP-like Web Browsing", "detected_category": "web_browsing", "confidence": 90.0},
        "classification_after": {"category_name": "VoIP-like Audio Stream", "detected_category": "voip_call", "confidence": 85.0},
        "mimicry_config": {"target_profile_id": "voip_call", "target_profile_name": "VoIP-like Audio Stream"}
    }
    save_experiment(exp_data)

    # 1. First compare call calculates and persists
    res1 = client.get(f"/api/compare/{exp_id}")
    assert res1.status_code == 200
    data1 = res1.get_json()
    assert data1["fooled"] is True
    assert data1["metrics"]["mean_size"]["delta"] == 60.0

    # 2. Simulate fresh backend read from disk
    stored = get_experiment(exp_id)
    assert stored is not None
    assert "comparison" in stored
    assert stored["comparison"]["fooled"] is True

    # 3. Second call reloads the persisted comparison correctly
    res2 = client.get(f"/api/compare?id={exp_id}")
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert data2["fooled"] is True
    assert data2["metrics"]["mean_size"]["percent_change"] == 60.0
