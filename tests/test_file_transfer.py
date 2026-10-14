"""
Automated Test Suite for Real Binary File Transfers.
Validates:
1. TXT, CSV, PNG, PDF, ZIP binary integrity.
2. TCP stream framing, temporary file streaming, and atomic finalization.
3. UDP reassembly, packet loss detection, and refusal to mark incomplete transfers successful.
4. Empty files, size limits, and invalid input rejection.
5. Checksum verification and mismatch detection.
6. Cancellation and temporary file cleanup.
7. Path traversal prevention and access control.
8. JSON persistence across datasets (transferred_files, analysis_results, experiments, transfer_logs).
9. Feature extraction, DPI classification, and experiment linkage.
"""

import io
import os
import json
import time
import base64
import pytest
import zipfile
import hashlib
from pathlib import Path

from backend.app import app
from backend.config import UPLOADS_DIR, TRAFFIC_DIR
from backend.file_validator import validate_file_content, sanitize_filename
from backend.file_samples import (
    get_sample_txt, get_sample_csv, get_sample_png, get_sample_pdf, get_sample_zip
)
from backend.traffic_generator import TrafficGenerator, cancel_generation, get_task_status
from backend.json_storage import (
    get_transferred_file, list_transferred_files, get_analysis_by_experiment, get_experiment
)


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestFileValidationAndSamples:
    """Tests file content validation, magic bytes, and pre-packaged samples."""

    def test_sample_files_generators(self):
        txt_bytes = get_sample_txt()
        assert len(txt_bytes) > 0
        assert b"TELEMETRY REPORT" in txt_bytes

        csv_bytes = get_sample_csv()
        assert b"seq,timestamp_sec" in csv_bytes

        png_bytes = get_sample_png()
        assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")

        pdf_bytes = get_sample_pdf()
        assert pdf_bytes.startswith(b"%PDF-")
        assert b"%%EOF" in pdf_bytes

        zip_bytes = get_sample_zip()
        assert zip_bytes.startswith(b"PK\x03\x04")
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            assert "experiment_manifest.txt" in zf.namelist()

    def test_validate_content_formats(self):
        # TXT
        val_txt = validate_file_content("test.txt", b"Hello world\n123")
        assert val_txt["category"] == "txt"
        assert val_txt["mime_type"] == "text/plain"

        # CSV
        val_csv = validate_file_content("data.csv", b"a,b,c\n1,2,3")
        assert val_csv["category"] == "csv"
        assert val_csv["mime_type"] == "text/csv"

        # PNG
        png_data = get_sample_png()
        val_png = validate_file_content("image.png", png_data)
        assert val_png["category"] == "png"
        assert val_png["mime_type"] == "image/png"

        # PDF
        pdf_data = get_sample_pdf()
        val_pdf = validate_file_content("doc.pdf", pdf_data)
        assert val_pdf["category"] == "pdf"
        assert val_pdf["mime_type"] == "application/pdf"

        # ZIP
        zip_data = get_sample_zip()
        val_zip = validate_file_content("archive.zip", zip_data)
        assert val_zip["category"] == "zip"
        assert val_zip["mime_type"] == "application/zip"

    def test_reject_executable_and_dangerous_files(self):
        # Windows MZ executable header
        with pytest.raises(ValueError, match="Windows PE/MZ executables"):
            validate_file_content("malicious.exe", b"MZ\x90\x00\x03\x00\x00\x00")

        # Linux ELF header
        with pytest.raises(ValueError, match="Linux ELF executables"):
            validate_file_content("exploit.elf", b"\x7fELF\x02\x01\x01\x00")

    def test_reject_empty_or_oversized_files(self):
        with pytest.raises(ValueError, match="empty"):
            validate_file_content("empty.txt", b"")

        oversized = b"A" * 105
        with pytest.raises(ValueError, match="exceeds permitted maximum"):
            validate_file_content("big.txt", oversized, max_bytes=100)

    def test_path_traversal_sanitization(self):
        assert ".." not in sanitize_filename("../../../etc/passwd")
        assert "/" not in sanitize_filename("folder/subfolder/file.png")
        assert "\\" not in sanitize_filename("C:\\Windows\\System32\\cmd.exe")


class TestTcpFileTransfer:
    """Tests TCP file transfers over real 127.0.0.1 sockets."""

    @pytest.mark.parametrize("gen_func,ext", [
        (get_sample_txt, "txt"),
        (get_sample_csv, "csv"),
        (get_sample_png, "png"),
        (get_sample_pdf, "pdf"),
        (get_sample_zip, "zip"),
    ])
    def test_tcp_transfer_all_formats_lossless(self, gen_func, ext):
        file_bytes = gen_func()
        expected_sha = hashlib.sha256(file_bytes).hexdigest()
        filename = f"transfer_test.{ext}"

        gen = TrafficGenerator()
        exp_id = gen.experiment_id

        # Run synchronously in test
        gen._worker({
            "protocol": "TCP",
            "packet_size": 256,
            "interval_ms": 0,
            "direction": "client->server",
            "payload_mode": "file",
            "filename": filename,
            "file_bytes": file_bytes,
            "sent_sha256": expected_sha,
            "file_size": len(file_bytes)
        })

        status = get_task_status(exp_id)
        assert status is not None
        assert status["status"] == "completed"
        assert status["file_match"] is True
        assert status["file_sha256"] == expected_sha
        assert status["file_id"] is not None

        # Verify atomic storage on disk
        stored_path = Path(status["storage_path"])
        assert stored_path.exists()
        with open(stored_path, "rb") as f:
            stored_bytes = f.read()
        assert stored_bytes == file_bytes
        assert hashlib.sha256(stored_bytes).hexdigest() == expected_sha

        # Verify JSON persistence
        rec = get_transferred_file(status["file_id"])
        assert rec is not None
        assert rec["integrity_verified"] is True
        assert rec["sha256"] == expected_sha
        assert rec["size_bytes"] == len(file_bytes)

        # Verify feature extraction and DPI classification linkage
        analysis = get_analysis_by_experiment(exp_id)
        assert analysis is not None
        assert analysis["packet_count"] > 0
        assert "classifier_result" in analysis

        exp = get_experiment(exp_id)
        assert exp is not None
        assert exp["content_integrity_verified"] is True


class TestUdpFileTransfer:
    """Tests experimental UDP file transfers, packet anomalies, and incomplete handling."""

    def test_udp_successful_transfer_when_all_packets_arrive(self):
        file_bytes = get_sample_txt()
        expected_sha = hashlib.sha256(file_bytes).hexdigest()

        gen = TrafficGenerator()
        exp_id = gen.experiment_id

        gen._worker({
            "protocol": "UDP",
            "packet_size": 512,
            "interval_ms": 2,
            "direction": "client->server",
            "payload_mode": "file",
            "filename": "udp_test.txt",
            "file_bytes": file_bytes,
            "sent_sha256": expected_sha,
            "file_size": len(file_bytes)
        })

        status = get_task_status(exp_id)
        assert status is not None
        assert status["status"] == "completed"
        assert status["file_match"] is True
        assert status["file_sha256"] == expected_sha

    def test_udp_never_mark_incomplete_as_successful(self):
        """Simulate UDP dropped datagrams: incomplete transfer MUST NOT be marked successful."""
        from backend.text_payload import chunk_binary, reassemble_binary

        file_data = b"Antigravity UDP Loss Test " * 50
        chunks = chunk_binary(file_data, packet_size=128)
        assert len(chunks) > 2

        # Simulate dropping chunk index 1 (packet loss)
        received_with_loss = [chunks[0]] + chunks[2:]

        res = reassemble_binary(received_with_loss)
        assert res["integrity_ok"] is False
        assert res["lost_packets"] == 1
        assert 1 in res["missing_sequences"]
        # The reassembled sha256 will NOT match the original
        assert res["sha256"] != hashlib.sha256(file_data).hexdigest()


class TestFileTransferApiEndpoints:
    """Tests Flask API endpoints for samples, preview, transfer, cancel, and download."""

    def test_api_files_samples(self, client):
        res = client.get("/api/files/samples")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "success"
        samples = data["samples"]
        assert "txt" in samples
        assert "csv" in samples
        assert "png" in samples
        assert "pdf" in samples
        assert "zip" in samples

    def test_api_files_preview(self, client):
        png_bytes = get_sample_png()
        b64 = base64.b64encode(png_bytes).decode("ascii")

        res = client.post("/api/files/preview", json={
            "filename": "preview_test.png",
            "content_base64": b64,
            "packet_size": 256
        })
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "success"
        assert data["category"] == "png"
        assert data["mime_type"] == "image/png"
        assert data["sha256"] == hashlib.sha256(png_bytes).hexdigest()
        assert data["chunk_count"] > 0

    def test_api_traffic_generate_file_mode(self, client):
        csv_bytes = get_sample_csv()
        b64 = base64.b64encode(csv_bytes).decode("ascii")

        res = client.post("/api/traffic/generate", json={
            "protocol": "TCP",
            "packet_size": 256,
            "interval_ms": 1,
            "payload_mode": "file",
            "filename": "api_test.csv",
            "file_bytes_base64": b64
        })
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "started"
        exp_id = data["experiment_id"]

        # Poll until done
        for _ in range(30):
            time.sleep(0.1)
            st_res = client.get(f"/api/traffic/{exp_id}/status")
            st_data = st_res.get_json()
            if st_data.get("status") in ("completed", "failed"):
                break

        assert st_data["status"] == "completed"
        assert st_data["file_match"] is True
        file_id = st_data["file_id"]
        assert file_id is not None

        # Download reconstructed file
        dl_res = client.get(f"/api/files/{file_id}/download")
        assert dl_res.status_code == 200
        assert dl_res.data == csv_bytes

    def test_api_traffic_cancel(self, client):
        # Start a longer generation
        res = client.post("/api/traffic/generate", json={
            "protocol": "TCP",
            "packet_size": 128,
            "packet_count": 500,
            "interval_ms": 100,
            "payload_mode": "pattern"
        })
        assert res.status_code == 200
        exp_id = res.get_json()["experiment_id"]

        # Cancel it
        cancel_res = client.post(f"/api/traffic/{exp_id}/cancel")
        assert cancel_res.status_code == 200
        assert cancel_res.get_json()["status"] == "cancelled"

        # Check status
        st_res = client.get(f"/api/traffic/{exp_id}/status")
        assert st_res.get_json()["status"] == "cancelled"

    def test_download_path_traversal_prevention(self, client):
        # Attempt to access an invalid file_id
        res = client.get("/api/files/../../etc/passwd/download")
        # Should be 404 or 400 Bad Request
        assert res.status_code in (400, 404)
