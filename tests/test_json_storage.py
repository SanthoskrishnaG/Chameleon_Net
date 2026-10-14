"""
Unit & Integration Test Suite for Persistent JSON Storage Engine.
Tests all 5 core structured datasets:
1. transferred_files.json
2. analysis_results.json
3. experiments.json
4. lab_details.json
5. transfer_logs.json
Plus file upload, SHA-256 verification, atomic writes, and path traversal protection.
"""

import os
import io
import time
import json
import pytest
from pathlib import Path

from backend.config import (
    STORAGE_DIR, UPLOADS_DIR,
    TRANSFERRED_FILES_PATH, ANALYSIS_RESULTS_PATH, EXPERIMENTS_PATH,
    LAB_DETAILS_PATH, TRANSFER_LOGS_PATH, ensure_directories
)
from backend.json_storage import (
    save_transferred_file, get_transferred_file, list_transferred_files,
    delete_transferred_file, store_binary_file, compute_sha256, sanitize_filename,
    save_analysis_result, get_analysis_result, list_analysis_results,
    save_experiment, get_experiment, list_experiments, delete_experiment,
    get_lab_details, update_lab_details, reset_lab_details,
    log_transfer_event, list_transfer_logs, _atomic_write_json, _read_json
)
from backend.app import app


# --------------------------------------------------------------------------
# 1. Dataset Initialization & Atomic Writes
# --------------------------------------------------------------------------
def test_json_datasets_initialization():
    ensure_directories()
    # All 5 files should exist or safely initialize
    details = get_lab_details()
    assert details["version"] == "1.0.0"
    assert "datasets" in details

    files = list_transferred_files()
    assert "items" in files
    assert "total" in files

    analyses = list_analysis_results()
    assert "items" in analyses

    experiments = list_experiments()
    assert isinstance(experiments, list)

    logs = list_transfer_logs()
    assert "items" in logs


def test_atomic_write_and_recovery(tmp_path):
    test_file = tmp_path / "test_atomic.json"
    data = {"test_key": "atomic_value", "number": 42}
    _atomic_write_json(test_file, data)
    assert test_file.exists()

    loaded = _read_json(test_file, dict)
    assert loaded["test_key"] == "atomic_value"

    # Corrupt file on purpose
    with open(test_file, "w") as f:
        f.write("{invalid json content missing bracket")

    # Read should gracefully back up corrupted file and return default
    recovered = _read_json(test_file, lambda: {"recovered": True})
    assert recovered.get("recovered") is True


# --------------------------------------------------------------------------
# 2. File Upload, SHA-256, & Binary Storage
# --------------------------------------------------------------------------
def test_store_binary_file_and_checksum():
    sample_content = b"Antigravity Network Laboratory Test Binary Payload\x00\x01\x02\xFF"
    expected_sha = compute_sha256(sample_content)

    file_id = "FILE-TEST-001"
    stored_path, calc_sha = store_binary_file(file_id, "test_file.bin", sample_content)

    assert stored_path.exists()
    assert calc_sha == expected_sha
    with open(stored_path, "rb") as f:
        read_bytes = f.read()
    assert read_bytes == sample_content

    # Clean up
    if stored_path.exists():
        stored_path.unlink()


def test_path_traversal_prevention_on_store():
    # Attempt storing outside UPLOADS_DIR using relative navigation
    with pytest.raises(ValueError):
        store_binary_file("FILE-EVIL", "../../evil.sh", b"malicious content")


# --------------------------------------------------------------------------
# 3. Transferred Files Dataset CRUD & Filtering
# --------------------------------------------------------------------------
def test_transferred_files_crud():
    file_id = f"FILE-TEST-CRUD-{int(time.time()*1000)}"
    content = b"Sample payload for CRUD testing"
    sha = compute_sha256(content)

    record = {
        "file_id": file_id,
        "original_filename": "crud_test.txt",
        "sanitized_filename": "crud_test.txt",
        "extension": ".txt",
        "mime_type": "text/plain",
        "size_bytes": len(content),
        "sha256": sha,
        "transfer_protocol": "TCP",
        "source_label": "Client (127.0.0.1)",
        "dest_label": "Server (127.0.0.1)",
        "status": "completed",
        "integrity_verified": True
    }
    saved = save_transferred_file(record)
    assert saved["file_id"] == file_id

    # Retrieve
    loaded = get_transferred_file(file_id)
    assert loaded is not None
    assert loaded["sha256"] == sha
    assert loaded["transfer_protocol"] == "TCP"

    # Search & Filter
    listing = list_transferred_files(search="crud_test", protocol="TCP")
    assert any(f["file_id"] == file_id for f in listing["items"])

    # Delete
    assert delete_transferred_file(file_id) is True
    assert get_transferred_file(file_id) is None


# --------------------------------------------------------------------------
# 4. Analysis Results Dataset CRUD
# --------------------------------------------------------------------------
def test_analysis_results_crud():
    analysis_id = f"ANALYSIS-TEST-{int(time.time()*1000)}"
    exp_id = "EXP-LINKED-1234"
    record = {
        "analysis_id": analysis_id,
        "experiment_id": exp_id,
        "stage": "before",
        "transport_protocol": "TCP",
        "packet_count": 50,
        "mean_size": 512.0,
        "mean_ipt_ms": 20.0,
        "jitter_ms": 1.5,
        "classifier_result": {
            "detected_category": "bulk_transfer",
            "category_name": "Bulk-Transfer",
            "confidence": 88.0
        }
    }
    save_analysis_result(record)

    loaded = get_analysis_result(analysis_id)
    assert loaded is not None
    assert loaded["mean_size"] == 512.0
    assert loaded["classifier_result"]["confidence"] == 88.0

    listing = list_analysis_results(experiment_id=exp_id)
    assert any(a["analysis_id"] == analysis_id for a in listing["items"])


# --------------------------------------------------------------------------
# 5. Laboratory Configuration & Transfer Logs
# --------------------------------------------------------------------------
def test_lab_details_and_logs():
    details = get_lab_details()
    assert "supported_transports" in details
    assert "TCP" in details["supported_transports"]

    updated = update_lab_details({"operator": "Antigravity Network Engineer"})
    assert updated.get("operator") == "Antigravity Network Engineer"

    # Transfer logs
    log_entry = log_transfer_event(
        event_type="test_event",
        status="success",
        message="Test event for verification suite.",
        details={"sample_key": "sample_val"}
    )
    assert log_entry["event_id"].startswith("LOG-")

    logs = list_transfer_logs(event_type="test_event")
    assert any(l["event_id"] == log_entry["event_id"] for l in logs["items"])


# --------------------------------------------------------------------------
# 6. Real Socket File Transfer API Endpoint (TCP & UDP)
# --------------------------------------------------------------------------
def test_api_file_transfer_multipart_tcp():
    client = app.test_client()
    sample_text = "Antigravity Protocol Laboratory: Real File Transfer over Sockets.\nLine 2 with UTF-8: äöü!"
    data = {
        "file": (io.BytesIO(sample_text.encode("utf-8")), "sample_report.txt"),
        "protocol": "TCP",
        "packet_size": "64",
        "interval_ms": "1.0"
    }

    res = client.post("/api/files/transfer", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    res_data = res.get_json()

    assert res_data["status"] == "success"
    assert res_data["file_id"].startswith("FILE-")
    assert res_data["experiment_id"].startswith("EXP-")
    assert res_data["integrity_verified"] is True
    assert res_data["sha256"] == compute_sha256(sample_text.encode("utf-8"))

    # Verify retrieval
    file_id = res_data["file_id"]
    get_res = client.get(f"/api/files/{file_id}")
    assert get_res.status_code == 200
    assert get_res.get_json()["file_id"] == file_id

    # Verify download
    dl_res = client.get(f"/api/files/{file_id}/download")
    assert dl_res.status_code == 200
    assert dl_res.data == sample_text.encode("utf-8")

    # Clean up
    del_res = client.delete(f"/api/files/{file_id}")
    assert del_res.status_code == 200


def test_api_file_transfer_json_udp():
    client = app.test_client()
    sample_payload = b"UDP binary packet data transfer integrity check."
    encoded = io.BytesIO(sample_payload).getvalue().decode("latin1")

    res = client.post("/api/files/transfer", json={
        "filename": "udp_stream.bin",
        "content_text": "UDP binary packet data transfer integrity check.",
        "protocol": "UDP",
        "packet_size": 48,
        "interval_ms": 1.0
    })
    assert res.status_code == 200
    res_data = res.get_json()
    assert res_data["status"] == "success"
    assert res_data["protocol"] == "UDP"

    file_id = res_data["file_id"]
    client.delete(f"/api/files/{file_id}")


# --------------------------------------------------------------------------
# 7. Persistence Across Mock Restarts
# --------------------------------------------------------------------------
def test_persistence_across_restart():
    file_id = f"FILE-RESTART-{int(time.time()*1000)}"
    save_transferred_file({
        "file_id": file_id,
        "original_filename": "persistent_test.json",
        "transfer_protocol": "TCP",
        "size_bytes": 1024,
        "status": "completed"
    })

    # Simulate fresh lookup from raw disk
    with open(TRANSFERRED_FILES_PATH, "r", encoding="utf-8") as f:
        disk_data = json.load(f)
    assert any(item["file_id"] == file_id for item in disk_data)

    delete_transferred_file(file_id)
