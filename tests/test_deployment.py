"""
Automated Deployment Verification Suite for Protocol Mimicry Engine.
Verifies all deployment requirements specified in Master Prompt Section 7.
"""

import os
import sys
import json
import time
import pytest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import is_loopback, get_allowed_origins, is_origin_allowed, STORAGE_DIR, EXPERIMENTS_PATH
from backend.app import app
from backend.result_store import get_experiment, list_experiments


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# 1. Health Check
def test_deployment_health_check(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "online"
    assert "version" in data
    assert data["loopback_only"] is True
    assert "storage" in data


# 2. CORS Preflight & Response Headers
def test_deployment_cors_headers(client):
    res = client.options("/api/experiments", headers={
        "Origin": "https://chameleon-net.vercel.app",
        "Access-Control-Request-Method": "GET"
    })
    assert res.status_code in (200, 204)

    res = client.get("/api/health", headers={"Origin": "https://test-preview-123.vercel.app"})
    assert res.status_code == 200
    assert res.headers.get("Access-Control-Allow-Origin") == "https://test-preview-123.vercel.app"
    assert "Access-Control-Allow-Methods" in res.headers


# 3. Input Validation Rejections
def test_deployment_input_validation(client):
    res = client.get("/api/experiments/../../etc/passwd")
    assert res.status_code in (400, 404)

    res = client.post("/api/traffic/generate", json={
        "protocol": "TCP",
        "packet_count": 999999,
        "packet_size": 100
    })
    assert res.status_code == 400

    res = client.post("/api/traffic/generate", json={
        "protocol": "ICMP_RAW",
        "packet_count": 10,
        "packet_size": 100
    })
    assert res.status_code == 400


# 4. Real TCP Socket Experiment via API
def test_deployment_real_tcp_experiment(client):
    res = client.post("/api/traffic/generate", json={
        "protocol": "TCP",
        "packet_count": 15,
        "packet_size": 250,
        "interval_ms": 1,
        "payload_pattern": "text-like"
    })
    assert res.status_code == 200
    exp_id = res.get_json()["experiment_id"]
    assert exp_id.startswith("EXP-")

    time.sleep(1.2)

    res_f = client.get(f"/api/features/{exp_id}")
    assert res_f.status_code == 200
    feat_data = res_f.get_json()
    assert "features_before" in feat_data
    assert feat_data["features_before"]["packet_count"] >= 15

    res_c = client.post(f"/api/classify/{exp_id}?stage=before")
    assert res_c.status_code == 200
    class_data = res_c.get_json()["classification"]
    assert "category_name" in class_data
    assert "confidence" in class_data

    res_m = client.post("/api/mimicry/apply", json={
        "id": exp_id,
        "target_profile": "voip_call",
        "toggles": {"padding": True, "timing": True, "burst": True}
    })
    assert res_m.status_code == 200
    mimic_res = res_m.get_json()
    assert "mimicry_result" in mimic_res
    assert "comparison" in mimic_res
    assert "fooled" in mimic_res["comparison"]


# 5. Real UDP Custom Text Integrity
def test_deployment_real_udp_custom_text_integrity(client):
    test_text = "Vercel + Render Deployment: Protocol Mimicry Test 🚀"
    res = client.post("/api/traffic/generate", json={
        "protocol": "UDP",
        "packet_count": 20,
        "packet_size": 180,
        "interval_ms": 1,
        "payload_mode": "custom_text",
        "custom_text": test_text
    })
    assert res.status_code == 200
    exp_id = res.get_json()["experiment_id"]

    time.sleep(1.2)

    res_m = client.post("/api/mimicry/apply", json={
        "id": exp_id,
        "target_profile": "dns_lookup",
        "toggles": {"padding": True, "timing": True, "burst": True},
        "original_text": test_text
    })
    assert res_m.status_code == 200
    mimic_data = res_m.get_json()
    assert mimic_data["mimicry_result"]["text_preserved"] is True
    assert mimic_data["mimicry_result"]["reassembled_text"] == test_text


# 6. Persistence & Export Verification
def test_deployment_persistence_and_export(client):
    res = client.get("/api/experiments")
    assert res.status_code == 200
    data = res.get_json()
    assert "experiments" in data
    assert isinstance(data["experiments"], list)
    assert len(data["experiments"]) > 0

    exp_id = data["experiments"][0]["id"]

    res_json = client.get(f"/api/export/{exp_id}?format=json")
    assert res_json.status_code == 200
    assert "application/json" in res_json.content_type

    res_csv = client.get(f"/api/export/{exp_id}?format=csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.content_type

    res_html = client.get(f"/api/export/{exp_id}?format=html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.content_type
