"""
Comprehensive Test Suite for File Transfer Logging Bug Fix
Validates all 6 core requirements from Task 10:
1. Successful transfer appears in transfer_logs.json immediately.
2. Failed and incomplete transfers are recorded accurately with error detail.
3. The exact same IDs link transferred_files.json, experiments.json, and transfer_logs.json.
4. Deleting a file preserves its transfer history and logs a file_delete audit event.
5. New records remain available after a simulated backend restart (raw file inspection).
6. Transfer logs endpoint and records are strictly sorted newest events first (timestamp descending).
"""

import io
import os
import json
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import pytest

from backend.app import app
from backend.config import (
    TRANSFER_LOGS_PATH, TRANSFERRED_FILES_PATH, EXPERIMENTS_PATH, UPLOADS_DIR
)
from backend.json_storage import (
    log_transfer_event, list_transfer_logs, get_transferred_file,
    save_transferred_file, delete_transferred_file, get_experiment,
    compute_sha256, _read_json
)


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestFileTransferLoggingRequirements:
    """Validates the file transfer logging bug fix end-to-end."""

    def test_successful_transfer_appears_in_logs_immediately(self, client):
        """1. A successful transfer appears in the logs immediately with all required fields."""
        payload_text = "Antigravity Immediate Logging Test: UTF-8 Verification ⚡️"
        payload_bytes = payload_text.encode("utf-8")
        expected_sha = compute_sha256(payload_bytes)

        # Execute transfer via API
        res = client.post("/api/files/transfer", data={
            "file": (io.BytesIO(payload_bytes), "immediate_log_test.txt"),
            "protocol": "TCP",
            "packet_size": "64",
            "interval_ms": "1.0"
        }, content_type="multipart/form-data")

        assert res.status_code == 200, res.data.decode("utf-8")
        res_data = res.get_json()
        assert res_data["status"] == "success"
        file_id = res_data["file_id"]
        exp_id = res_data["experiment_id"]

        # Immediately query /api/logs
        logs_res = client.get("/api/logs?per_page=50")
        assert logs_res.status_code == 200
        logs_data = logs_res.get_json()
        logs = logs_data.get("logs") or logs_data.get("items") or []

        # Find log entries for this file_id
        file_logs = [l for l in logs if l.get("file_id") == file_id]
        assert len(file_logs) >= 2, f"Expected started and completed events for {file_id}, found: {file_logs}"

        statuses = [l.get("status") for l in file_logs]
        assert "started" in statuses
        assert "completed" in statuses

        # Verify completed event has all required fields
        completed_event = next(l for l in file_logs if l.get("status") == "completed")
        assert completed_event["event_type"] == "file_transfer"
        assert completed_event["file_id"] == file_id
        assert completed_event["experiment_id"] == exp_id
        assert completed_event["original_filename"] == "immediate_log_test.txt"
        assert completed_event["size_bytes"] == len(payload_bytes)
        assert completed_event["protocol"] == "TCP"
        assert completed_event["integrity_verified"] is True
        assert completed_event.get("error") is None
        assert "timestamp" in completed_event

        # Clean up
        client.delete(f"/api/files/{file_id}")

    def test_failed_and_incomplete_transfers_recorded_accurately(self, client):
        """2. Failed and incomplete transfers are recorded accurately with error details."""
        # A) Explicit failed event logging
        fail_file_id = f"FILE-FAIL-{int(time.time()*1000)}"
        fail_exp_id = f"EXP-FAIL-{int(time.time()*1000)}"
        err_msg = "Checksum mismatch: calculated sha does not match transmission manifest"

        log_transfer_event(
            event_type="file_transfer",
            status="failed",
            message=f"Transmission failed for {fail_file_id}",
            details={"original_filename": "corrupted_payload.bin", "size_bytes": 4096, "protocol": "UDP"},
            file_id=fail_file_id,
            experiment_id=fail_exp_id,
            original_filename="corrupted_payload.bin",
            size_bytes=4096,
            protocol="UDP",
            integrity_verified=False,
            error=err_msg
        )

        # Verify through API
        logs_res = client.get(f"/api/logs?search={fail_file_id}")
        assert logs_res.status_code == 200
        logs = logs_res.get_json().get("logs", [])
        assert len(logs) >= 1
        fail_entry = logs[0]
        assert fail_entry["status"] == "failed"
        assert fail_entry["event_type"] == "file_transfer"
        assert fail_entry["file_id"] == fail_file_id
        assert fail_entry["experiment_id"] == fail_exp_id
        assert fail_entry["integrity_verified"] is False
        assert fail_entry["error"] == err_msg
        assert fail_entry["protocol"] == "UDP"

        # B) Incomplete transfer logging
        incomp_file_id = f"FILE-INCOMP-{int(time.time()*1000)}"
        log_transfer_event(
            event_type="file_transfer",
            status="incomplete",
            message=f"UDP packet loss detected for {incomp_file_id}: missing packets 3, 7",
            details={"original_filename": "stream_loss.bin", "size_bytes": 2048, "protocol": "UDP"},
            file_id=incomp_file_id,
            original_filename="stream_loss.bin",
            size_bytes=2048,
            protocol="UDP",
            integrity_verified=False,
            error="Missing expected fragments: 2 packets lost in transit"
        )

        incomp_res = client.get(f"/api/logs?search={incomp_file_id}")
        assert incomp_res.status_code == 200
        incomp_logs = incomp_res.get_json().get("logs", [])
        assert len(incomp_logs) >= 1
        assert incomp_logs[0]["status"] == "incomplete"
        assert "packets lost" in incomp_logs[0]["error"]

    def test_same_ids_link_file_experiment_and_logs(self, client):
        """3. The exact same IDs link transferred_files.json, experiments.json, and transfer_logs.json."""
        payload = b"Synchronized ID Verification Payload Data 1234567890"

        res = client.post("/api/files/transfer", data={
            "file": (io.BytesIO(payload), "id_linkage_test.bin"),
            "protocol": "TCP",
            "packet_size": "128",
            "interval_ms": "1.0"
        }, content_type="multipart/form-data")

        assert res.status_code == 200
        res_json = res.get_json()
        primary_file_id = res_json["file_id"]
        primary_exp_id = res_json["experiment_id"]

        assert primary_file_id.startswith("FILE-")
        assert primary_exp_id.startswith("EXP-")

        # 1. Inspect transferred_files
        file_rec = get_transferred_file(primary_file_id)
        assert file_rec is not None
        assert file_rec["file_id"] == primary_file_id
        assert file_rec["experiment_id"] == primary_exp_id

        # 2. Inspect experiments
        exp_rec = get_experiment(primary_exp_id)
        assert exp_rec is not None
        assert exp_rec["experiment_id"] == primary_exp_id
        assert exp_rec.get("file_id") == primary_file_id

        # 3. Inspect transfer_logs
        logs_res = client.get(f"/api/logs?search={primary_file_id}")
        logs_data = logs_res.get_json()
        matching_logs = logs_data.get("logs", [])
        assert len(matching_logs) >= 2  # started + completed

        for log in matching_logs:
            assert log["file_id"] == primary_file_id
            assert log["experiment_id"] == primary_exp_id

        # Clean up
        client.delete(f"/api/files/{primary_file_id}")

    def test_deleting_file_preserves_transfer_history(self, client):
        """4. Deleting a file preserves its transfer history and appends file_delete event."""
        payload = b"Audit History Preservation Test on File Deletion"

        res = client.post("/api/files/transfer", data={
            "file": (io.BytesIO(payload), "audit_delete_test.txt"),
            "protocol": "TCP",
            "packet_size": "64",
            "interval_ms": "1.0"
        }, content_type="multipart/form-data")

        assert res.status_code == 200
        file_id = res.get_json()["file_id"]

        # Confirm transfer events exist before deletion
        logs_before = client.get(f"/api/logs?search={file_id}").get_json().get("logs", [])
        transfer_events_before = [l for l in logs_before if l.get("event_type") == "file_transfer"]
        assert len(transfer_events_before) >= 2

        # Delete the file
        del_res = client.delete(f"/api/files/{file_id}")
        assert del_res.status_code == 200

        # Verify file is deleted from transferred_files
        assert get_transferred_file(file_id) is None

        # Verify logs STILL contain the original file_transfer records PLUS a new file_delete event
        logs_after = client.get(f"/api/logs?search={file_id}").get_json().get("logs", [])
        event_types = [l.get("event_type") for l in logs_after]

        # Audit history MUST be preserved
        assert "file_transfer" in event_types
        assert "file_delete" in event_types

        # Verify file_delete event contents
        delete_event = next(l for l in logs_after if l.get("event_type") == "file_delete")
        assert delete_event["file_id"] == file_id
        assert delete_event["status"] in ("completed", "success")
        assert "deleted" in delete_event["message"].lower()

    def test_new_records_remain_available_after_backend_restart(self, client):
        """5. New records remain available after a backend restart (direct disk JSON read)."""
        test_file_id = f"FILE-RESTART-{int(time.time()*1000)}"
        test_exp_id = f"EXP-RESTART-{int(time.time()*1000)}"

        # Save record directly to storage
        save_transferred_file({
            "file_id": test_file_id,
            "experiment_id": test_exp_id,
            "original_filename": "restart_validation.bin",
            "transfer_protocol": "TCP",
            "size_bytes": 1024,
            "status": "completed",
            "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "integrity_verified": True
        }, auto_log=False)

        log_transfer_event(
            event_type="file_transfer",
            status="completed",
            message=f"Transfer completed for {test_file_id}",
            file_id=test_file_id,
            experiment_id=test_exp_id,
            original_filename="restart_validation.bin",
            size_bytes=1024,
            protocol="TCP",
            integrity_verified=True
        )

        # Simulate complete restart by reading raw JSON files directly from filesystem
        assert os.path.exists(TRANSFERRED_FILES_PATH)
        assert os.path.exists(TRANSFER_LOGS_PATH)

        with open(TRANSFERRED_FILES_PATH, "r", encoding="utf-8") as f:
            disk_files = json.load(f)
        with open(TRANSFER_LOGS_PATH, "r", encoding="utf-8") as f:
            disk_logs = json.load(f)

        found_file = next((f for f in disk_files if f.get("file_id") == test_file_id), None)
        assert found_file is not None, f"File {test_file_id} missing from raw disk storage"
        assert found_file["experiment_id"] == test_exp_id

        found_log = next((l for l in disk_logs if l.get("file_id") == test_file_id), None)
        assert found_log is not None, f"Log {test_file_id} missing from raw disk storage"
        assert found_log["event_type"] == "file_transfer"
        assert found_log["status"] == "completed"

        # Also query via a fresh test client instance
        fresh_client = app.test_client()
        api_log_res = fresh_client.get(f"/api/logs?search={test_file_id}")
        assert api_log_res.status_code == 200
        assert len(api_log_res.get_json().get("logs", [])) >= 1

        delete_transferred_file(test_file_id)

    def test_logs_displayed_newest_events_first(self, client):
        """6. The API returns and displays the newest events first (sorted by timestamp descending)."""
        now = time.time()

        # Log 3 events with explicit timestamps in the past
        t1 = datetime.fromtimestamp(now - 300, tz=timezone.utc).isoformat()
        t2 = datetime.fromtimestamp(now - 150, tz=timezone.utc).isoformat()
        t3 = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()

        f_id = f"FILE-SORT-{int(now)}"
        log_transfer_event(
            event_type="file_transfer",
            status="started",
            message="Oldest event",
            file_id=f_id,
            timestamp=t1
        )
        log_transfer_event(
            event_type="file_transfer",
            status="completed",
            message="Middle event",
            file_id=f_id,
            timestamp=t2
        )
        log_transfer_event(
            event_type="file_delete",
            status="completed",
            message="Newest event",
            file_id=f_id,
            timestamp=t3
        )

        # Retrieve through API
        res = client.get(f"/api/logs?search={f_id}")
        assert res.status_code == 200
        logs = res.get_json().get("logs", [])
        assert len(logs) == 3

        # Must be in descending order: t3 > t2 > t1
        timestamps = [l["timestamp"] for l in logs]
        assert timestamps[0] == t3
        assert timestamps[1] == t2
        assert timestamps[2] == t1

        # Also verify global list_transfer_logs returns all logs in descending order
        all_logs_res = client.get("/api/logs?per_page=50")
        all_logs = all_logs_res.get_json().get("logs", [])
        for i in range(len(all_logs) - 1):
            assert all_logs[i]["timestamp"] >= all_logs[i + 1]["timestamp"], (
                f"Log order violation at index {i}: {all_logs[i]['timestamp']} < {all_logs[i+1]['timestamp']}"
            )
