import sys
import time
import json
import threading
from pathlib import Path

# Add project root to sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests
from backend.app import app

BASE = "http://127.0.0.1:5000"


def ensure_server_running():
    """Ensure a server is listening on port 5000, launching one in a daemon thread if needed."""
    try:
        r = requests.get(f"{BASE}/api/health", timeout=0.8)
        if r.status_code == 200:
            return
    except Exception:
        pass

    # Launch server in background thread
    print("[*] Starting local Flask engine on 127.0.0.1:5000 for scenario verification...")
    t = threading.Thread(target=lambda: app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False), daemon=True)
    t.start()
    for _ in range(30):
        time.sleep(0.1)
        try:
            r = requests.get(f"{BASE}/api/health", timeout=0.5)
            if r.status_code == 200:
                print("[*] Engine server listening and ready.")
                return
        except Exception:
            pass


def test_pipeline():
    ensure_server_running()

    print("[1] Testing Health Endpoint:")
    h = requests.get(f"{BASE}/api/health").json()
    print(f"    Status: {h['status']} | Loopback Only: {h['loopback_only']}")
    assert h["status"] == "online"

    print("\n[2] Testing Scenario 1 (Successful Deception: Bulk-Transfer -> VoIP-like Stream):")
    r1 = requests.post(f"{BASE}/api/demo/run", json={
        "source_type": "random",
        "target_profile": "voip_call",
        "transport_mode": "convert_transport",
        "speed": 10.0
    }).json()
    run_id1 = r1["run_id"]
    while True:
        st = requests.get(f"{BASE}/api/demo/{run_id1}/events").json()
        if st.get("status") in ("completed", "failed"):
            break
        time.sleep(0.3)

    comp1 = st["data"]["comparison"]
    cb = st["data"]["classification_before"]
    ca = st["data"]["classification_after"]
    print(f"    Baseline Category:    {cb['category_name']} ({cb['confidence']}%)")
    print(f"    Transformed Category: {ca['category_name']} ({ca['confidence']}%)")
    print(f"    Status Banner:        {comp1['status_banner']}")
    print(f"    Verdict:               {comp1['verdict']}")
    assert comp1["status_banner"] == "CLASSIFIER FOOLED", f"Expected CLASSIFIER FOOLED, got {comp1['status_banner']}"

    print("\n[3] Testing Scenario 2 (Honest Limitation: TCP Source -> UDP VoIP mismatch):")
    r2 = requests.post(f"{BASE}/api/demo/run", json={
        "source_type": "random",
        "target_profile": "voip_call",
        "transport_mode": "keep_original",
        "speed": 10.0
    }).json()
    run_id2 = r2["run_id"]
    while True:
        st2 = requests.get(f"{BASE}/api/demo/{run_id2}/events").json()
        if st2.get("status") in ("completed", "failed"):
            break
        time.sleep(0.3)

    comp2 = st2["data"]["comparison"]
    cb2 = st2["data"]["classification_before"]
    ca2 = st2["data"]["classification_after"]
    print(f"    Baseline Category:    {cb2['category_name']}")
    print(f"    Transformed Category: {ca2['category_name']}")
    print(f"    Status Banner:        {comp2['status_banner']}")
    print(f"    Verdict:               {comp2['verdict']}")
    assert comp2["status_banner"] == "CLASSIFIER NOT FOOLED", f"Expected CLASSIFIER NOT FOOLED, got {comp2['status_banner']}"

    print("\n[4] Testing Experiment Archiving & Exports:")
    exp_id = st["data"]["experiment_id"]
    exp_detail = requests.get(f"{BASE}/api/experiments/{exp_id}").json()
    print(f"    Loaded Experiment:    {exp_detail['id']}")

    html_exp = requests.get(f"{BASE}/api/export/{exp_id}?format=html")
    assert html_exp.status_code == 200 and "CONTROLLED EXPERIMENT REPORT" in html_exp.text
    print(f"    HTML Printable Report Exported ({len(html_exp.text)} bytes)")

    csv_exp = requests.get(f"{BASE}/api/export/{exp_id}?format=csv")
    assert csv_exp.status_code == 200 and "Metric,Before (Baseline)" in csv_exp.text
    print("    CSV Deltas Exported")

    json_exp = requests.get(f"{BASE}/api/export/{exp_id}?format=json")
    assert json_exp.status_code == 200
    print("    JSON Record Exported")

    print("\n[SUCCESS] ALL LABORATORY CRITERIA VERIFIED 100% WORKING!\n")


if __name__ == "__main__":
    test_pipeline()
