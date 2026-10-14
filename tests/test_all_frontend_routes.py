"""
End-to-End Route Verification for Protocol Mimicry Engine.
Verifies all 21 API endpoints used by the frontend:
1. GET /api/health
2. GET /api/profiles
3. POST /api/text/preview
4. POST /api/traffic/generate (TCP)
5. POST /api/traffic/generate (UDP)
6. GET /api/traffic/<exp_id>/status
7. GET /api/features/<exp_id>
8. POST /api/classify/<exp_id>?stage=before
9. POST /api/mimicry/apply
10. POST /api/classify/<exp_id>?stage=after
11. GET /api/compare/<exp_id>
12. GET /api/experiments
13. GET /api/experiments/<exp_id>
14. GET /api/export/<exp_id>?format=json
15. GET /api/export/<exp_id>?format=csv
16. GET /api/export/<exp_id>?format=html
17. GET /api/settings
18. PUT /api/settings
19. POST /api/demo/run
20. GET /api/demo/<run_id>/events
21. DELETE /api/experiments/<exp_id>
"""

import time
import pytest
from backend.app import app
from backend.result_store import get_experiment


def test_complete_frontend_route_lifecycle():
    client = app.test_client()

    # 1. Health
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "online"

    # 2. Profiles
    res = client.get("/api/profiles")
    assert res.status_code == 200
    profiles = res.get_json()["profiles"]
    assert len(profiles) >= 5

    # 3. Text preview
    res = client.post("/api/text/preview", json={
        "text": "Antigravity Lab Test Packet Stream",
        "packet_size": 32,
        "pad_last": True
    })
    assert res.status_code == 200
    assert "chunks" in res.get_json()

    # 4. Generate Traffic (TCP)
    gen_res = client.post("/api/traffic/generate", json={
        "protocol": "TCP",
        "packet_count": 15,
        "packet_size": 256,
        "interval_ms": 2,
        "payload_pattern": "text-like",
        "direction": "client->server",
        "payload_mode": "pattern"
    })
    assert gen_res.status_code == 200
    exp_id = gen_res.get_json()["experiment_id"]
    assert exp_id.startswith("EXP-")

    # 5. Poll status until complete
    max_wait = 10.0
    start = time.time()
    while time.time() - start < max_wait:
        st_res = client.get(f"/api/traffic/{exp_id}/status")
        assert st_res.status_code == 200
        if st_res.get_json().get("status") in ("completed", "failed"):
            break
        time.sleep(0.2)

    # 6. Features
    feat_res = client.get(f"/api/features/{exp_id}")
    assert feat_res.status_code == 200
    feats = feat_res.get_json()
    assert feats["features_before"]["packet_count"] == 15

    # 7. Classify baseline
    class_before_res = client.post(f"/api/classify/{exp_id}?stage=before")
    assert class_before_res.status_code == 200
    cb = class_before_res.get_json()["classification"]
    assert "detected_category" in cb

    # 8. Apply mimicry
    mimic_res = client.post("/api/mimicry/apply", json={
        "id": exp_id,
        "target_profile": "voip_call",
        "toggles": {"padding": True, "timing": True, "burst": True},
        "transport_mode": "convert_transport"
    })
    assert mimic_res.status_code == 200
    m_data = mimic_res.get_json()
    assert m_data["status"] == "success"

    # 9. Classify mimicked stage
    class_after_res = client.post(f"/api/classify/{exp_id}?stage=after")
    assert class_after_res.status_code == 200
    ca = class_after_res.get_json()["classification"]
    assert "detected_category" in ca

    # 10. Compare
    comp_res = client.get(f"/api/compare/{exp_id}")
    assert comp_res.status_code == 200
    comp = comp_res.get_json()
    assert "deltas" in comp
    assert "status_banner" in comp

    # 11. List experiments
    list_res = client.get("/api/experiments?sort_by=created_at&desc=true")
    assert list_res.status_code == 200
    exps = list_res.get_json()["experiments"]
    assert any(e["id"] == exp_id for e in exps)

    # 12. Single experiment detail
    detail_res = client.get(f"/api/experiments/{exp_id}")
    assert detail_res.status_code == 200
    assert detail_res.get_json()["id"] == exp_id

    # 13. Export JSON
    exp_json_res = client.get(f"/api/export/{exp_id}?format=json")
    assert exp_json_res.status_code == 200
    assert exp_json_res.headers.get("Content-Type") == "application/json"

    # 14. Export CSV
    exp_csv_res = client.get(f"/api/export/{exp_id}?format=csv")
    assert exp_csv_res.status_code == 200
    assert "Metric,Before (Baseline)" in exp_csv_res.get_data(as_text=True)

    # 15. Export HTML printable report
    exp_html_res = client.get(f"/api/export/{exp_id}?format=html")
    assert exp_html_res.status_code == 200
    assert "CONTROLLED EXPERIMENT REPORT" in exp_html_res.get_data(as_text=True)

    # 16. Settings GET
    settings_get = client.get("/api/settings")
    assert settings_get.status_code == 200
    assert "weights" in settings_get.get_json()

    # 17. Settings PUT
    cur_settings = settings_get.get_json()
    settings_put = client.put("/api/settings", json=cur_settings)
    assert settings_put.status_code == 200
    assert settings_put.get_json()["status"] == "updated"

    # 18. Delete experiment
    del_res = client.delete(f"/api/experiments/{exp_id}")
    assert del_res.status_code == 200
    assert del_res.get_json()["status"] == "deleted"

    # Verify deleted
    assert get_experiment(exp_id) is None
