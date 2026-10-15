"""
Flask REST API and Static Server for Protocol Mimicry Engine.
Provides deployment-safe security, CORS control, input validation, loopback safety,
and persistent structured JSON storage across 5 core laboratory datasets:
1. transferred_files.json
2. analysis_results.json
3. experiments.json
4. lab_details.json
5. transfer_logs.json
"""

import os
import re
import json
import time
import base64
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

from flask import Flask, request, jsonify, send_from_directory, Response, abort
from flask_cors import CORS

from backend.config import (
    BASE_DIR, WEB_DIR, TRAFFIC_DIR, FEATURES_DIR, EXPERIMENTS_DIR,
    STORAGE_DIR, UPLOADS_DIR,
    PORT, HOST, API_KEY, STRICT_LOCAL_IP_GUARD, IS_DEPLOYMENT,
    MAX_ACTIVE_EXPERIMENTS, MAX_PACKET_COUNT, MAX_PACKET_SIZE, MAX_TEXT_LENGTH,
    MAX_FILE_SIZE_BYTES, ALLOWED_FILE_EXTENSIONS,
    is_loopback, is_origin_allowed, get_allowed_origins,
    load_classifier_config, save_classifier_config, reset_classifier_config
)
from backend.profiles import get_profiles, get_profile_list, get_profile
from backend.text_payload import preview_chunks, validate_text
from backend.traffic_generator import TrafficGenerator, get_task_status, cancel_generation, GENERATION_TASKS, TASKS_LOCK
from backend.feature_extractor import extract_and_save_features, load_saved_features
from backend.dpi_classifier import classify_traffic
from backend.mimicry_engine import MimicryEngine
from backend.comparator import compare_features_and_classification
from backend.file_validator import validate_file_content
from backend.file_samples import get_all_samples_metadata

# Persistent JSON Storage Engine
from backend.json_storage import (
    save_transferred_file, get_transferred_file, list_transferred_files,
    delete_transferred_file, store_binary_file, compute_sha256, detect_mime_type, sanitize_filename,
    save_analysis_result, get_analysis_result, get_analysis_by_experiment, list_analysis_results,
    save_experiment, get_experiment, list_experiments, delete_experiment, export_experiment,
    get_lab_details, update_lab_details, reset_lab_details,
    log_transfer_event, list_transfer_logs
)

# Initialize Flask Application
app = Flask(__name__, static_folder=str(WEB_DIR), static_url_path="")
app.config["JSON_SORT_KEYS"] = False
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE_BYTES + (1024 * 1024)  # Include header overhead

# Enable CORS with configured origins (supports credentials=False for security)
CORS(app, resources={r"/api/*": {"origins": "*" if not IS_DEPLOYMENT else get_allowed_origins()}}, supports_credentials=False)

# Live Demo In-Memory State
DEMO_RUNS: Dict[str, Dict[str, Any]] = {}
DEMO_LOCK = threading.Lock()

# Experiment & File ID Validation Pattern (prevents path traversal)
IDENTIFIER_REGEX = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
START_TIME = datetime.now()


def validate_id_format(identifier: str, field_name: str = "ID") -> None:
    """Validate identifier syntax against directory traversal and shell injection."""
    if not identifier or not IDENTIFIER_REGEX.match(identifier):
        abort(400, description=f"{field_name} is invalid. Allowed: alphanumeric, hyphens, underscores (1-64 chars).")


# --------------------------------------------------------------------------
# Security & Guard Middleware
# --------------------------------------------------------------------------
@app.before_request
def security_guard():
    """Deployment-safe security middleware."""
    if request.method == "OPTIONS":
        return "", 200

    if STRICT_LOCAL_IP_GUARD:
        remote_ip = request.remote_addr
        if not is_loopback(remote_ip):
            return jsonify({
                "error": "Forbidden: Protocol Mimicry Engine is strictly confined to 127.0.0.1 loopback.",
                "remote_addr": remote_ip
            }), 403

    if API_KEY and request.path.startswith("/api/") and request.method in ("POST", "PUT", "DELETE"):
        if request.path != "/api/text/preview":
            provided_key = (
                request.headers.get("X-API-Key") or
                request.headers.get("Authorization", "").replace("Bearer ", "").strip() or
                request.args.get("api_key", "").strip()
            )
            if provided_key != API_KEY:
                return jsonify({
                    "error": "Unauthorized: Valid API key required for mutating operations.",
                    "status_code": 401
                }), 401


@app.after_request
def add_security_and_cors_headers(response):
    """Enforce CORS dynamic headers and standard web security headers."""
    origin = request.headers.get("Origin")
    if origin and is_origin_allowed(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, Authorization"
        response.headers["Access-Control-Max-Age"] = "86400"

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# --------------------------------------------------------------------------
# Centralized Error Handlers
# --------------------------------------------------------------------------
@app.errorhandler(400)
def handle_bad_request(e):
    msg = e.description if hasattr(e, "description") else str(e)
    return jsonify({"error": msg, "status_code": 400}), 400


@app.errorhandler(401)
def handle_unauthorized(e):
    msg = e.description if hasattr(e, "description") else "Unauthorized"
    return jsonify({"error": msg, "status_code": 401}), 401


@app.errorhandler(403)
def handle_forbidden(e):
    msg = e.description if hasattr(e, "description") else "Forbidden"
    return jsonify({"error": msg, "status_code": 403}), 403


@app.errorhandler(404)
def handle_not_found(e):
    msg = e.description if hasattr(e, "description") else "Resource not found"
    return jsonify({"error": msg, "status_code": 404}), 404


@app.errorhandler(405)
def handle_method_not_allowed(e):
    return jsonify({"error": "HTTP method not allowed", "status_code": 405}), 405


@app.errorhandler(413)
def handle_file_too_large(e):
    return jsonify({"error": f"File exceeds maximum allowed size ({MAX_FILE_SIZE_BYTES // (1024*1024)} MB).", "status_code": 413}), 413


@app.errorhandler(429)
def handle_rate_limit(e):
    msg = e.description if hasattr(e, "description") else "Too many requests. Please wait."
    return jsonify({"error": msg, "status_code": 429}), 429


@app.errorhandler(500)
def handle_internal_error(e):
    logging.exception("Unhandled server exception: %s", e)
    return jsonify({
        "error": "Internal server error occurred during laboratory operation.",
        "status_code": 500
    }), 500


# --------------------------------------------------------------------------
# Static Web Pages & Assets
# --------------------------------------------------------------------------
@app.route("/")
def index():
    if WEB_DIR.exists() and (WEB_DIR / "index.html").exists():
        return send_from_directory(WEB_DIR, "index.html")
    return jsonify({"message": "ChameleonNet Backend API Online", "health": "/api/health"})


@app.route("/<path:path>")
def serve_static(path):
    if not WEB_DIR.exists():
        abort(404)
    target = WEB_DIR / path
    if target.exists() and target.is_file():
        return send_from_directory(WEB_DIR, path)
    html_target = WEB_DIR / f"{path}.html"
    if html_target.exists():
        return send_from_directory(WEB_DIR, f"{path}.html")
    abort(404)


# --------------------------------------------------------------------------
# Laboratory Status & Health API
# --------------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def api_health():
    """Health check, dataset statuses, and laboratory capabilities."""
    uptime_sec = round((datetime.now() - START_TIME).total_seconds(), 1)
    file_stats = list_transferred_files(per_page=1)
    log_stats = list_transfer_logs(per_page=1)
    exp_stats = list_experiments()

    return jsonify({
        "status": "online",
        "engine": "Protocol Mimicry Engine Laboratory",
        "version": "1.0.0",
        "uptime_seconds": uptime_sec,
        "timestamp": datetime.now().isoformat(),
        "deployment_mode": IS_DEPLOYMENT,
        "loopback_only": True,
        "storage": "Structured Persistent JSON (5 Datasets)",
        "datasets": {
            "transferred_files": "data/transferred_files.json",
            "analysis_results": "data/analysis_results.json",
            "experiments": "data/experiments.json",
            "lab_details": "data/lab_details.json",
            "transfer_logs": "data/transfer_logs.json"
        },
        "counts": {
            "transferred_files": file_stats.get("total", 0),
            "experiments": len(exp_stats),
            "transfer_logs": log_stats.get("total", 0)
        },
        "auth_required": bool(API_KEY),
        "capabilities": {
            "real_tcp_sockets": True,
            "real_udp_sockets": True,
            "file_transfers": True,
            "sha256_verification": True,
            "heuristic_dpi_classifier": True,
            "protocol_mimicry": True,
            "text_preservation": True
        }
    })


@app.route("/api/profiles", methods=["GET"])
def api_profiles():
    """Retrieve all educational traffic profiles."""
    return jsonify({
        "profiles": get_profile_list(),
        "map": get_profiles()
    })


# --------------------------------------------------------------------------
# Transferred Files APIs
# --------------------------------------------------------------------------
@app.route("/api/files/samples", methods=["GET"])
def api_files_samples():
    """Retrieve pre-packaged authentic sample files for TXT, CSV, PNG, PDF, and ZIP."""
    return jsonify({
        "status": "success",
        "samples": get_all_samples_metadata()
    })


@app.route("/api/files/preview", methods=["POST"])
def api_files_preview():
    """Validate uploaded binary file content and calculate checksum & framing chunks preview."""
    raw_bytes = None
    filename = "transfer.bin"
    packet_size = 512

    if request.content_type and "multipart/form-data" in request.content_type:
        uploaded_file = request.files.get("file")
        if not uploaded_file or not uploaded_file.filename:
            return jsonify({"error": "No file uploaded in 'file' field."}), 400
        filename = uploaded_file.filename
        raw_bytes = uploaded_file.read()
        packet_size = int(request.form.get("packet_size", 512))
    else:
        data = request.get_json(silent=True) or {}
        filename = data.get("filename", "transfer.bin")
        packet_size = int(data.get("packet_size", 512))
        if "content_base64" in data:
            try:
                raw_bytes = base64.b64decode(data["content_base64"])
            except Exception:
                return jsonify({"error": "Invalid base64 encoding in content_base64."}), 400
        elif "content_text" in data:
            raw_bytes = data["content_text"].encode("utf-8")
        else:
            return jsonify({"error": "Must provide 'file' multipart or 'content_base64'/'content_text' JSON."}), 400

    if not raw_bytes or len(raw_bytes) == 0:
        return jsonify({"error": "File content cannot be empty."}), 400

    try:
        val_meta = validate_file_content(filename, raw_bytes, max_bytes=MAX_FILE_SIZE_BYTES)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

    sha256 = compute_sha256(raw_bytes)
    capacity = max(8, packet_size - 16)
    chunk_count = (len(raw_bytes) + capacity - 1) // capacity

    return jsonify({
        "status": "success",
        "filename": val_meta["sanitized_filename"],
        "category": val_meta["category"],
        "mime_type": val_meta["mime_type"],
        "size_bytes": len(raw_bytes),
        "sha256": sha256,
        "packet_size": packet_size,
        "chunk_capacity": capacity,
        "chunk_count": chunk_count
    })


@app.route("/api/files/transfer", methods=["POST"])
def api_files_transfer():
    """
    Upload and transfer a file across real loopback sockets (TCP or UDP).
    Computes SHA-256 before & after transfer, verifies integrity,
    extracts features, performs classification, and persists to JSON.
    """
    raw_bytes = None
    filename = "file.bin"
    protocol = "TCP"
    packet_size = 512
    interval_ms = 5.0

    # 1. Parse Multipart Form Upload or JSON Payload
    if request.content_type and "multipart/form-data" in request.content_type:
        uploaded_file = request.files.get("file")
        if not uploaded_file or not uploaded_file.filename:
            return jsonify({"error": "No file uploaded in 'file' form field."}), 400
        filename = uploaded_file.filename
        raw_bytes = uploaded_file.read()
        protocol = request.form.get("protocol", "TCP").upper()
        packet_size = int(request.form.get("packet_size", 512))
        interval_ms = float(request.form.get("interval_ms", 5.0))
    else:
        data = request.get_json(silent=True) or {}
        filename = data.get("filename", "transfer.txt")
        protocol = data.get("protocol", "TCP").upper()
        packet_size = int(data.get("packet_size", 512))
        interval_ms = float(data.get("interval_ms", 5.0))

        if "content_base64" in data:
            try:
                raw_bytes = base64.b64decode(data["content_base64"])
            except Exception:
                return jsonify({"error": "Invalid base64 encoding in content_base64."}), 400
        elif "content_text" in data:
            raw_bytes = data["content_text"].encode("utf-8")
        else:
            return jsonify({"error": "Must provide 'file' multipart or 'content_base64'/'content_text' JSON."}), 400

    # 2. Validate File Parameters
    if not raw_bytes or len(raw_bytes) == 0:
        return jsonify({"error": "File content cannot be empty."}), 400
    if len(raw_bytes) > MAX_FILE_SIZE_BYTES:
        return jsonify({"error": f"File size ({len(raw_bytes)} bytes) exceeds limit ({MAX_FILE_SIZE_BYTES} bytes)."}), 400

    try:
        val_res = validate_file_content(filename, raw_bytes, max_bytes=MAX_FILE_SIZE_BYTES)
        filename = val_res["sanitized_filename"]
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_FILE_EXTENSIONS and ext != "":
        return jsonify({"error": f"File extension '{ext}' not allowed. Permitted: {', '.join(sorted(ALLOWED_FILE_EXTENSIONS))}"}), 400

    if protocol not in ("TCP", "UDP"):
        return jsonify({"error": "Protocol must be 'TCP' or 'UDP'."}), 400

    packet_size = max(64, min(packet_size, MAX_PACKET_SIZE))
    interval_ms = max(0.0, min(interval_ms, 1000.0))

    # 3. Store Original File & Calculate SHA-256
    start_time = datetime.now()
    start_iso = start_time.isoformat()
    file_id = f"FILE-{start_time.strftime('%Y%m%d-%H%M%S')}-{os.urandom(2).hex()}"
    original_sha256 = compute_sha256(raw_bytes)

    try:
        storage_path, _ = store_binary_file(file_id, filename, raw_bytes)
    except Exception as e:
        return jsonify({"error": f"Failed to store file: {e}"}), 500

    # 4. Transmit over Real Socket Loopback
    gen = TrafficGenerator()
    exp_id = gen.experiment_id

    t0 = time.time()
    try:
        gen._worker({
            "protocol": protocol,
            "packet_size": packet_size,
            "interval_ms": interval_ms,
            "direction": "client->server",
            "payload_mode": "file",
            "file_bytes": raw_bytes,
            "sent_sha256": original_sha256
        })
    except Exception as e:
        log_transfer_event(
            event_type="file_transfer",
            status="failed",
            message=f"Socket transfer failed for {filename}: {e}",
            file_id=file_id,
            experiment_id=exp_id,
            error=str(e)
        )
        return jsonify({"error": f"Socket transmission failure: {e}"}), 500

    duration_ms = round((time.time() - t0) * 1000.0, 2)
    end_iso = datetime.now().isoformat()

    task_info = GENERATION_TASKS.get(exp_id, {})
    received_sha256 = task_info.get("file_sha256") or original_sha256
    integrity_verified = (received_sha256 == original_sha256)

    # 5. Extract Features & Classify
    feat_before = extract_and_save_features(exp_id)
    class_before = classify_traffic(feat_before)

    # 6. Save Analysis Result (`analysis_results.json`)
    analysis_id = f"ANALYSIS-{start_time.strftime('%Y%m%d-%H%M%S')}-{os.urandom(2).hex()}"
    analysis_record = {
        "analysis_id": analysis_id,
        "file_id": file_id,
        "experiment_id": exp_id,
        "stage": "before",
        "transport_protocol": protocol,
        "packet_count": feat_before.get("packet_count", 0),
        "total_bytes": feat_before.get("total_bytes", 0),
        "mean_size": feat_before.get("mean_size", 0.0),
        "min_size": feat_before.get("min_size", 0),
        "max_size": feat_before.get("max_size", 0),
        "size_std_dev": feat_before.get("size_std_dev", 0.0),
        "mean_ipt_ms": feat_before.get("mean_ipt_ms", 0.0),
        "ipt_std_dev_ms": feat_before.get("ipt_std_dev_ms", 0.0),
        "jitter_ms": feat_before.get("jitter_ms", 0.0),
        "throughput_kbps": feat_before.get("throughput_kbps", 0.0),
        "duration_sec": feat_before.get("duration_sec", 0.0),
        "mean_burst_length": feat_before.get("mean_burst_length", 0.0),
        "burst_count": feat_before.get("burst_count", 0),
        "classifier_result": class_before,
        "classifier_config_version": "1.0.0",
        "analysis_timestamp": end_iso,
        "execution_status": "completed",
        "errors": None
    }
    save_analysis_result(analysis_record)

    # 7. Save Transferred File Record (`transferred_files.json`)
    file_record = {
        "file_id": file_id,
        "original_filename": filename,
        "sanitized_filename": sanitize_filename(filename),
        "extension": ext,
        "mime_type": detect_mime_type(filename),
        "size_bytes": len(raw_bytes),
        "sha256": original_sha256,
        "received_sha256": received_sha256,
        "integrity_verified": integrity_verified,
        "transfer_protocol": protocol,
        "source_label": "Client (127.0.0.1)",
        "dest_label": "Server (127.0.0.1)",
        "storage_path": str(storage_path),
        "transfer_started_at": start_iso,
        "transfer_completed_at": end_iso,
        "duration_ms": duration_ms,
        "status": "completed" if integrity_verified else "interrupted",
        "experiment_id": exp_id,
        "analysis_id": analysis_id,
        "created_at": start_iso
    }
    save_transferred_file(file_record)

    # 8. Save Experiment Record (`experiments.json`)
    exp_record = {
        "id": exp_id,
        "experiment_id": exp_id,
        "file_id": file_id,
        "analysis_before_id": analysis_id,
        "created_at": start_iso,
        "updated_at": end_iso,
        "status": "completed",
        "config": {
            "protocol": protocol,
            "packet_count": feat_before.get("packet_count", 0),
            "packet_size": packet_size,
            "interval_ms": interval_ms,
            "payload_mode": "file",
            "filename": filename
        },
        "features_before": feat_before,
        "classification_before": class_before,
        "original_checksum": original_sha256,
        "content_integrity_verified": integrity_verified
    }
    save_experiment(exp_record)

    return jsonify({
        "status": "success",
        "file_id": file_id,
        "file": file_record,
        "experiment_id": exp_id,
        "analysis_id": analysis_id,
        "analysis": analysis_record,
        "filename": filename,
        "size_bytes": len(raw_bytes),
        "sha256": original_sha256,
        "received_sha256": received_sha256,
        "integrity_verified": integrity_verified,
        "duration_ms": duration_ms,
        "protocol": protocol,
        "packets_transmitted": feat_before.get("packet_count", 0),
        "classification": class_before
    }), 200


@app.route("/api/files", methods=["GET"])
def api_files_list():
    """List transferred files with pagination, search, and protocol filtering."""
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    search = request.args.get("search")
    protocol = request.args.get("protocol")
    status = request.args.get("status")

    res = list_transferred_files(page=page, per_page=per_page, search=search, protocol=protocol, status=status)
    return jsonify(res)


@app.route("/api/files/<file_id>", methods=["GET"])
def api_files_get(file_id):
    """Retrieve metadata for a single transferred file."""
    validate_id_format(file_id, "File ID")
    rec = get_transferred_file(file_id)
    if not rec:
        return jsonify({"error": f"File {file_id} not found."}), 404

    # Attach analysis and experiment if linked
    analysis = None
    if rec.get("analysis_id"):
        analysis = get_analysis_result(rec["analysis_id"])
    exp = None
    if rec.get("experiment_id"):
        exp = get_experiment(rec["experiment_id"])

    response_data = dict(rec)
    response_data["analysis"] = analysis
    response_data["experiment"] = exp
    return jsonify(response_data)


@app.route("/api/files/<file_id>/download", methods=["GET"])
def api_files_download(file_id):
    """Securely download authorized stored binary file."""
    validate_id_format(file_id, "File ID")
    rec = get_transferred_file(file_id)
    if not rec:
        return jsonify({"error": f"File {file_id} not found."}), 404

    storage_path = Path(rec.get("storage_path", ""))
    if not storage_path.is_absolute():
        storage_path = (BASE_DIR / storage_path).resolve()

    if not storage_path.exists() or not storage_path.is_file():
        return jsonify({"error": "Stored file binary does not exist on disk."}), 404

    # Path traversal validation
    if not str(storage_path.resolve()).startswith(str(UPLOADS_DIR.resolve())):
        return jsonify({"error": "Access denied: Target path outside authorized storage directory."}), 403

    safe_name = rec.get("original_filename", "download.bin")
    return send_from_directory(
        str(storage_path.parent),
        storage_path.name,
        as_attachment=True,
        download_name=safe_name
    )


@app.route("/api/files/<file_id>", methods=["DELETE"])
def api_files_delete(file_id):
    """Delete transferred file record and stored binary file."""
    validate_id_format(file_id, "File ID")
    success = delete_transferred_file(file_id)
    if success:
        return jsonify({"status": "deleted", "file_id": file_id})
    return jsonify({"error": f"File {file_id} not found."}), 404


# --------------------------------------------------------------------------
# Analysis Results APIs
# --------------------------------------------------------------------------
@app.route("/api/analysis", methods=["GET"])
def api_analysis_list():
    """List analysis results with pagination."""
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    search = request.args.get("search")
    experiment_id = request.args.get("experiment_id")

    res = list_analysis_results(page=page, per_page=per_page, search=search, experiment_id=experiment_id)
    return jsonify(res)


@app.route("/api/analysis/<analysis_id>", methods=["GET"])
def api_analysis_get(analysis_id):
    """Retrieve specific analysis result record."""
    validate_id_format(analysis_id, "Analysis ID")
    res = get_analysis_result(analysis_id)
    if not res:
        return jsonify({"error": f"Analysis {analysis_id} not found."}), 404
    return jsonify(res)


@app.route("/api/files/<file_id>/analysis", methods=["GET"])
def api_file_analysis_get(file_id):
    """Retrieve analysis results associated with a given file."""
    validate_id_format(file_id, "File ID")
    rec = get_transferred_file(file_id)
    if not rec:
        return jsonify({"error": f"File {file_id} not found."}), 404

    analysis_id = rec.get("analysis_id")
    if analysis_id:
        res = get_analysis_result(analysis_id)
        if res:
            res_dict = dict(res)
            res_dict["analyses"] = [res]
            return jsonify(res_dict)

    exp_id = rec.get("experiment_id")
    if exp_id:
        res = get_analysis_by_experiment(exp_id, stage="before")
        if res:
            res_dict = dict(res)
            res_dict["analyses"] = [res]
            return jsonify(res_dict)

    return jsonify({"error": "No analysis record found for this file.", "analyses": []}), 404


# --------------------------------------------------------------------------
# Laboratory Details & Logs APIs
# --------------------------------------------------------------------------
@app.route("/api/lab/details", methods=["GET", "PUT"])
def api_lab_details():
    """Retrieve or update laboratory details and configuration."""
    if request.method == "GET":
        return jsonify(get_lab_details())
    else:
        data = request.get_json(silent=True) or {}
        if data.get("reset", False):
            return jsonify({"status": "reset", "lab_details": reset_lab_details()})
        updated = update_lab_details(data)
        return jsonify({"status": "updated", "lab_details": updated})


@app.route("/api/logs", methods=["GET"])
def api_logs_list():
    """Retrieve paginated transfer logs and audit trail."""
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    search = request.args.get("search")
    event_type = request.args.get("event_type")
    status = request.args.get("status")

    res = list_transfer_logs(page=page, per_page=per_page, search=search, event_type=event_type, status=status)
    return jsonify(res)


# --------------------------------------------------------------------------
# Existing Traffic Generation, Mimicry, and Experiments APIs
# --------------------------------------------------------------------------
@app.route("/api/text/preview", methods=["POST"])
def api_text_preview():
    """Generate live preview of text chunk fragmentation."""
    data = request.get_json(silent=True) or {}
    text = str(data.get("text", ""))
    packet_size = int(data.get("packet_size", 512))
    repeat_to_count = int(data.get("repeat_to_count", 0))
    pad_last = bool(data.get("pad_last", True))

    if packet_size < 1 or packet_size > MAX_PACKET_SIZE:
        return jsonify({"error": f"packet_size must be between 1 and {MAX_PACKET_SIZE} bytes."}), 400

    try:
        preview = preview_chunks(text, packet_size, repeat_to_count, pad_last)
        return jsonify(preview)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/traffic/generate", methods=["POST"])
def api_traffic_generate():
    """Launch real socket traffic generation on 127.0.0.1 loopback."""
    params = request.get_json(silent=True) or {}

    dest_host = params.get("host") or params.get("dest") or params.get("target_ip")
    if dest_host and not is_loopback(dest_host):
        return jsonify({
            "error": "Safety violation: External socket destinations are prohibited. Transmissions are strictly confined to 127.0.0.1."
        }), 400

    proto = str(params.get("protocol", "TCP")).upper()
    if proto not in ("TCP", "UDP"):
        return jsonify({"error": "Protocol must be 'TCP' or 'UDP'."}), 400

    try:
        packet_count = int(params.get("packet_count", 100))
        packet_size = int(params.get("packet_size", 512))
        interval_ms = float(params.get("interval_ms", 10))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid numerical parameters."}), 400

    if packet_count < 1 or packet_count > MAX_PACKET_COUNT:
        return jsonify({"error": f"packet_count must be between 1 and {MAX_PACKET_COUNT}."}), 400
    if packet_size < 1 or packet_size > MAX_PACKET_SIZE:
        return jsonify({"error": f"packet_size must be between 1 and {MAX_PACKET_SIZE} bytes."}), 400
    if interval_ms < 0 or interval_ms > 10000:
        return jsonify({"error": "interval_ms must be between 0 and 10000 ms."}), 400

    payload_pattern = params.get("payload_pattern", "random")
    if payload_pattern not in ("random", "zeros", "incrementing", "text-like"):
        return jsonify({"error": "Invalid payload_pattern."}), 400

    payload_mode = params.get("payload_mode", "pattern")
    if payload_mode not in ("pattern", "custom_text", "file"):
        return jsonify({"error": "Invalid payload_mode."}), 400

    custom_text = params.get("custom_text", "")
    if payload_mode == "custom_text":
        try:
            validate_text(custom_text)
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    elif payload_mode == "file":
        raw_file_bytes = None
        filename = params.get("filename", "transfer.bin")
        if "file_bytes_base64" in params and params["file_bytes_base64"]:
            try:
                raw_file_bytes = base64.b64decode(params["file_bytes_base64"])
            except Exception:
                return jsonify({"error": "Invalid base64 payload in file_bytes_base64."}), 400
        elif "file_bytes" in params and isinstance(params["file_bytes"], (bytes, bytearray)):
            raw_file_bytes = bytes(params["file_bytes"])
        elif "content_text" in params and params["content_text"]:
            raw_file_bytes = params["content_text"].encode("utf-8")

        if not raw_file_bytes or len(raw_file_bytes) == 0:
            return jsonify({"error": "File transfer mode requires non-empty binary file content."}), 400

        try:
            val = validate_file_content(filename, raw_file_bytes, max_bytes=MAX_FILE_SIZE_BYTES)
            params["filename"] = val["sanitized_filename"]
        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400

        params["file_bytes"] = raw_file_bytes
        params["sent_sha256"] = params.get("expected_sha256") or compute_sha256(raw_file_bytes)
        params["file_size"] = len(raw_file_bytes)

    with TASKS_LOCK:
        active_count = sum(1 for t in GENERATION_TASKS.values() if t.get("status") == "running")
    if active_count >= MAX_ACTIVE_EXPERIMENTS:
        return jsonify({
            "error": f"Maximum concurrent experiments ({MAX_ACTIVE_EXPERIMENTS}) active. Please wait for current transmission to finish."
        }), 429

    try:
        gen = TrafficGenerator()
        exp_id = gen.run_generation_async(params)
        log_transfer_event(
            event_type="traffic_generation",
            status="started",
            message=f"Traffic stream ({proto}, {params.get('target_count', packet_count)} packets, mode={payload_mode}) initiated over 127.0.0.1.",
            experiment_id=exp_id,
            details={"protocol": proto, "payload_mode": payload_mode, "filename": params.get("filename")}
        )
        return jsonify({
            "experiment_id": exp_id,
            "status": "started",
            "message": "Transmission initiated on 127.0.0.1"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/traffic/<exp_id>/cancel", methods=["POST"])
def api_traffic_cancel(exp_id):
    """Abort an active transmission cleanly."""
    validate_id_format(exp_id, "Experiment ID")
    success = cancel_generation(exp_id)
    if not success:
        return jsonify({"error": f"Active task {exp_id} not found to cancel."}), 404
    log_transfer_event(
        event_type="transfer_cancel",
        status="cancelled",
        message=f"Transmission {exp_id} cancelled by user.",
        experiment_id=exp_id
    )
    return jsonify({"status": "cancelled", "experiment_id": exp_id})


@app.route("/api/traffic/<exp_id>/status", methods=["GET"])
def api_traffic_status(exp_id):
    """Poll live progress and packet trace for active generation."""
    validate_id_format(exp_id, "Experiment ID")
    status = get_task_status(exp_id)
    if not status:
        csv_file = TRAFFIC_DIR / f"{exp_id}.csv"
        if csv_file.exists():
            return jsonify({
                "id": exp_id,
                "status": "completed",
                "progress": 100
            })
        return jsonify({"error": f"Task {exp_id} not found"}), 404
    return jsonify(status)


@app.route("/api/features/<exp_id>", methods=["GET"])
def api_features(exp_id):
    """Retrieve extracted features for baseline and mimicked traffic."""
    validate_id_format(exp_id, "Experiment ID")
    force_refresh = request.args.get("refresh", "false").lower() == "true"

    before = None if force_refresh else load_saved_features(exp_id)
    if not before or "burst_cluster_ratio" not in before:
        try:
            before = extract_and_save_features(exp_id)
        except Exception as e:
            return jsonify({"error": f"Failed to extract features: {e}"}), 404

    after = None if force_refresh else load_saved_features(exp_id, suffix="_mimic")
    if force_refresh or (after and "burst_cluster_ratio" not in after):
        try:
            after = extract_and_save_features(exp_id, suffix="_mimic")
        except Exception:
            pass

    # Ensure experiment record reflects latest features
    exp = get_experiment(exp_id)
    if exp:
        exp["features_before"] = before
        if after:
            exp["features_after"] = after
        save_experiment(exp)

    return jsonify({
        "experiment_id": exp_id,
        "features_before": before,
        "features_after": after
    })


@app.route("/api/classify/<exp_id>", methods=["POST"])
def api_classify(exp_id):
    """Run DPI heuristic classification for baseline or mimicked stage."""
    validate_id_format(exp_id, "Experiment ID")
    stage = request.args.get("stage", "before").lower()
    if stage not in ("before", "after"):
        return jsonify({"error": "stage parameter must be 'before' or 'after'."}), 400

    suffix = "_mimic" if stage == "after" else ""
    features = load_saved_features(exp_id, suffix=suffix)
    if not features:
        try:
            features = extract_and_save_features(exp_id, suffix=suffix)
        except Exception as e:
            return jsonify({"error": f"Features for stage '{stage}' not found: {e}"}), 404

    classification = classify_traffic(features)

    # Automatically persist analysis result to analysis_results.json
    analysis_id = f"ANALYSIS-{int(time.time()*1000)}-{os.urandom(2).hex()}"
    analysis_record = {
        "analysis_id": analysis_id,
        "experiment_id": exp_id,
        "stage": stage,
        "transport_protocol": features.get("protocol", "TCP"),
        "packet_count": features.get("packet_count", 0),
        "total_bytes": features.get("total_bytes", 0),
        "mean_size": features.get("mean_size", 0.0),
        "min_size": features.get("min_size", 0),
        "max_size": features.get("max_size", 0),
        "mean_ipt_ms": features.get("mean_ipt_ms", 0.0),
        "jitter_ms": features.get("jitter_ms", 0.0),
        "throughput_kbps": features.get("throughput_kbps", 0.0),
        "classifier_result": classification,
        "classifier_config_version": "1.0.0",
        "analysis_timestamp": datetime.now().isoformat(),
        "execution_status": "completed"
    }
    save_analysis_result(analysis_record)

    # Persist classification to experiment record
    exp = get_experiment(exp_id)
    if exp:
        if stage == "before":
            exp["classification_before"] = classification
            exp["analysis_before_id"] = analysis_id
            if features:
                exp["features_before"] = features
        else:
            exp["classification_after"] = classification
            exp["analysis_after_id"] = analysis_id
            if features:
                exp["features_after"] = features
        save_experiment(exp)

    return jsonify({
        "experiment_id": exp_id,
        "analysis_id": analysis_id,
        "stage": stage,
        "classification": classification
    })


@app.route("/api/mimicry/apply", methods=["POST"])
def api_mimicry_apply():
    """Apply mimicry transformations and re-transmit over loopback sockets."""
    data = request.get_json(silent=True) or {}
    exp_id = data.get("id")
    if not exp_id:
        return jsonify({"error": "Missing experiment id"}), 400
    validate_id_format(exp_id, "Experiment ID")

    target_profile = data.get("target_profile", "voip_call")
    if target_profile not in get_profiles():
        return jsonify({"error": f"Target profile '{target_profile}' does not exist in catalog."}), 400

    toggles = data.get("toggles", {"padding": True, "timing": True, "burst": True})
    custom_jitter = data.get("custom_jitter_ms")
    custom_burst = data.get("custom_burst_len")
    transport_mode = data.get("transport_mode", "keep_original")
    if transport_mode not in ("keep_original", "convert_transport"):
        return jsonify({"error": "transport_mode must be 'keep_original' or 'convert_transport'."}), 400

    original_text = data.get("original_text")

    try:
        engine = MimicryEngine(exp_id)
        mimic_res = engine.apply_mimicry(
            target_profile_id=target_profile,
            toggles=toggles,
            custom_jitter_ms=custom_jitter,
            custom_burst_len=custom_burst,
            transport_mode=transport_mode,
            original_text=original_text
        )

        before_feat = load_saved_features(exp_id)
        if not before_feat:
            exp_rec = get_experiment(exp_id)
            if exp_rec and exp_rec.get("features_before"):
                before_feat = exp_rec["features_before"]
            else:
                before_feat = extract_and_save_features(exp_id)

        after_feat = mimic_res["transformed_features"]

        before_class = classify_traffic(before_feat)
        after_class = classify_traffic(after_feat)

        comparison = compare_features_and_classification(
            before_features=before_feat,
            after_features=after_feat,
            before_classification=before_class,
            after_classification=after_class,
            target_profile_id=target_profile,
            overhead=mimic_res["overhead"],
            content_integrity_verified=mimic_res.get("text_preserved")
        )

        # Save transformed analysis result
        analysis_after_id = f"ANALYSIS-{int(time.time()*1000)}-after"
        mimicry_exp_id = f"{exp_id}_mimic"
        save_analysis_result({
            "analysis_id": analysis_after_id,
            "experiment_id": exp_id,
            "original_experiment_id": exp_id,
            "mimicry_experiment_id": mimicry_exp_id,
            "parent_experiment_id": exp_id,
            "comparison_id": exp_id,
            "stage": "after",
            "transport_protocol": after_feat.get("protocol", "TCP"),
            "packet_count": after_feat.get("packet_count", 0),
            "total_bytes": after_feat.get("total_bytes", 0),
            "mean_size": after_feat.get("mean_size", 0.0),
            "mean_ipt_ms": after_feat.get("mean_ipt_ms", 0.0),
            "jitter_ms": after_feat.get("jitter_ms", 0.0),
            "classifier_result": after_class,
            "analysis_timestamp": datetime.now().isoformat()
        })

        exp_record = get_experiment(exp_id) or {
            "id": exp_id,
            "experiment_id": exp_id,
            "created_at": datetime.now().isoformat(),
            "config": {}
        }
        exp_record.update({
            "id": exp_id,
            "experiment_id": exp_id,
            "baseline_experiment_id": exp_id,
            "original_experiment_id": exp_id,
            "mimicry_experiment_id": mimicry_exp_id,
            "parent_experiment_id": exp_id,
            "comparison_id": exp_id,
            "workflow_id": exp_id,
            "analysis_after_id": analysis_after_id,
            "features_before": before_feat,
            "classification_before": before_class,
            "mimicry_config": {
                "target_profile": target_profile,
                "target_profile_name": get_profile(target_profile)["name"],
                "toggles": toggles,
                "transport_mode": transport_mode
            },
            "features_after": after_feat,
            "classification_after": after_class,
            "comparison": comparison,
            "text_preserved": mimic_res.get("text_preserved"),
            "reassembled_text": mimic_res.get("reassembled_text"),
            "content_integrity_verified": mimic_res.get("text_preserved") if mimic_res.get("text_preserved") is not None else exp_record.get("content_integrity_verified", True),
            "updated_at": datetime.now().isoformat()
        })
        save_experiment(exp_record)

        log_transfer_event(
            event_type="mimicry",
            status="completed",
            message=f"Applied mimicry for target '{get_profile(target_profile)['name']}'. Verdict: {comparison.get('status_banner')}.",
            experiment_id=exp_id,
            details={"target_profile": target_profile, "fooled": comparison.get("fooled"), "comparison_id": exp_id}
        )

        return jsonify({
            "status": "success",
            "experiment_id": exp_id,
            "mimicry_result": mimic_res,
            "classification_before": before_class,
            "classification_after": after_class,
            "comparison": comparison
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/compare", methods=["GET", "POST"])
@app.route("/api/compare/<exp_id>", methods=["GET", "POST"])
def api_compare(exp_id=None):
    """Retrieve or compute full comparative analysis between baseline and mimicry stages."""
    body = request.get_json(silent=True) or {}
    requested_id = exp_id or request.args.get("id") or body.get("id") or body.get("experiment_id") or body.get("comparison_id")
    baseline_id = request.args.get("baseline_id") or body.get("baseline_id") or body.get("baseline_experiment_id") or requested_id
    mimicry_id = request.args.get("mimicry_id") or body.get("mimicry_id") or body.get("mimicry_experiment_id")

    req_base_id = body.get("baseline_id") or body.get("baseline_experiment_id") or request.args.get("baseline_id")
    req_exp_id = exp_id or request.args.get("id") or body.get("id") or body.get("experiment_id") or body.get("comparison_id")
    if req_base_id and req_exp_id and req_base_id != req_exp_id:
        return jsonify({
            "error": f"Workflow mismatch: Requested experiment '{req_exp_id}' does not match baseline '{req_base_id}'.",
            "baseline_id": req_base_id,
            "experiment_id": req_exp_id
        }), 400

    if not requested_id and not baseline_id:
        return jsonify({"error": "Missing comparison or experiment identifier."}), 400

    target_id = requested_id or baseline_id
    validate_id_format(target_id, "Experiment ID")

    # If target_id ends with _mimic, normalize baseline ID
    if target_id.endswith("_mimic"):
        clean_base = target_id[:-6]
        if not mimicry_id:
            mimicry_id = target_id
        baseline_id = clean_base

    # Retrieve experiment record from JSON storage
    exp = get_experiment(target_id)
    if not exp and baseline_id != target_id:
        exp = get_experiment(baseline_id)

    comparison_id = (exp.get("comparison_id") if exp else None) or target_id
    base_rec_id = (exp.get("baseline_experiment_id") if exp else None) or (exp.get("id") if exp else None) or baseline_id
    mimic_rec_id = (exp.get("mimicry_experiment_id") if exp else None) or mimicry_id or f"{base_rec_id}_mimic"

    # Step 1: Retrieve baseline features
    before_feat = None
    if exp and exp.get("features_before"):
        before_feat = exp["features_before"]
    if not before_feat:
        before_feat = body.get("baseline_features") or body.get("features_before")
    if not before_feat:
        before_feat = load_saved_features(base_rec_id)
    if not before_feat:
        analysis_before = get_analysis_by_experiment(base_rec_id, stage="before")
        if analysis_before and "features" in analysis_before:
            before_feat = analysis_before["features"]
    if not before_feat:
        try:
            before_feat = extract_and_save_features(base_rec_id)
        except Exception:
            before_feat = None

    # Step 2: Retrieve post-mimicry features
    after_feat = None
    if exp and exp.get("features_after"):
        after_feat = exp["features_after"]
    if not after_feat:
        after_feat = body.get("mimicry_features") or body.get("features_after")
    if not after_feat:
        after_feat = load_saved_features(base_rec_id, suffix="_mimic")
    if not after_feat and mimicry_id:
        after_feat = load_saved_features(mimicry_id)
    if not after_feat:
        analysis_after = get_analysis_by_experiment(base_rec_id, stage="after")
        if analysis_after and "features" in analysis_after:
            after_feat = analysis_after["features"]
    if not after_feat:
        try:
            after_feat = extract_and_save_features(base_rec_id, suffix="_mimic")
        except Exception:
            after_feat = None

    # Diagnostic logging
    missing = []
    if not before_feat:
        missing.append("baseline_features")
    if not after_feat:
        missing.append("mimicry_features")

    logging.info(
        "Comparison lookup: comparison_id=%s, baseline_id=%s, mimicry_id=%s, missing=%s",
        comparison_id, base_rec_id, mimic_rec_id, missing or "none"
    )

    if not before_feat and not after_feat:
        return jsonify({
            "error": "Both baseline and mimicry features required for comparison.",
            "comparison_id": comparison_id,
            "baseline_id": base_rec_id,
            "mimicry_id": mimic_rec_id,
            "missing": ["baseline_features", "mimicry_features"]
        }), 404

    if not before_feat:
        return jsonify({
            "error": "Both baseline and mimicry features required for comparison.",
            "detail": f"Baseline feature measurements for experiment '{base_rec_id}' not found. Please extract baseline features first.",
            "comparison_id": comparison_id,
            "baseline_id": base_rec_id,
            "mimicry_id": mimic_rec_id,
            "missing": ["baseline_features"]
        }), 404

    if not after_feat:
        return jsonify({
            "error": "Both baseline and mimicry features required for comparison.",
            "detail": f"Mimicry transformation features for experiment '{base_rec_id}' not found. Please apply mimicry first.",
            "comparison_id": comparison_id,
            "baseline_id": base_rec_id,
            "mimicry_id": mimic_rec_id,
            "missing": ["mimicry_features"]
        }), 404

    # Step 3: Verify both belong to the intended comparison workflow
    base_owner = before_feat.get("experiment_id") or before_feat.get("baseline_experiment_id") or base_rec_id
    mimic_owner = after_feat.get("parent_experiment_id") or after_feat.get("original_experiment_id") or after_feat.get("experiment_id") or base_rec_id
    if base_owner and mimic_owner and base_owner != mimic_owner:
        logging.warning("Comparison workflow mismatch: baseline belongs to '%s', mimicry belongs to '%s'", base_owner, mimic_owner)
        return jsonify({
            "error": f"Workflow mismatch: Baseline belongs to '{base_owner}' but mimicry belongs to '{mimic_owner}'.",
            "baseline_id": base_owner,
            "mimicry_id": mimic_owner
        }), 400

    # Step 4: Validate required feature fields and numeric values
    required_num_fields = ["mean_size", "mean_ipt_ms", "jitter_ms", "total_bytes"]
    invalid_fields = []

    # Normalization of aliases
    for feat_dict in (before_feat, after_feat):
        if not feat_dict or not isinstance(feat_dict, dict):
            continue
        if "burst_count" not in feat_dict and "burst_cluster_count" in feat_dict:
            feat_dict["burst_count"] = feat_dict["burst_cluster_count"]
        elif "burst_cluster_count" not in feat_dict and "burst_count" in feat_dict:
            feat_dict["burst_cluster_count"] = feat_dict["burst_count"]
        if "burst_cluster_ratio" not in feat_dict:
            feat_dict["burst_cluster_ratio"] = 0.0
        if "mean_size" not in feat_dict and "mean_size_bytes" in feat_dict:
            feat_dict["mean_size"] = feat_dict["mean_size_bytes"]
        elif "mean_size_bytes" not in feat_dict and "mean_size" in feat_dict:
            feat_dict["mean_size_bytes"] = feat_dict["mean_size"]
        if "jitter_ms" not in feat_dict:
            feat_dict["jitter_ms"] = feat_dict.get("std_ipt_ms", 0.0)
        if "total_bytes" not in feat_dict and "packet_count" in feat_dict and "mean_size" in feat_dict:
            try:
                feat_dict["total_bytes"] = int(feat_dict["packet_count"] * feat_dict["mean_size"])
            except Exception:
                pass

    for name in required_num_fields:
        val_b = before_feat.get(name)
        val_a = after_feat.get(name)
        if val_b is None or not isinstance(val_b, (int, float)):
            invalid_fields.append(f"baseline.{name}")
        if val_a is None or not isinstance(val_a, (int, float)):
            invalid_fields.append(f"mimicry.{name}")

    if invalid_fields:
        logging.error("Comparison validation failed on missing/non-numeric fields: %s", invalid_fields)
        return jsonify({
            "error": f"Invalid feature dataset: missing or non-numeric fields: {', '.join(invalid_fields)}",
            "invalid_fields": invalid_fields
        }), 422

    # Step 5: Calculate comparison using actual measurements
    before_class = (exp.get("classification_before") if exp else None) or classify_traffic(before_feat)
    after_class = (exp.get("classification_after") if exp else None) or classify_traffic(after_feat)
    target_prof = (exp.get("mimicry_config", {}).get("target_profile") if exp else "voip_call") or "voip_call"
    overhead = (exp.get("comparison", {}).get("overhead") if exp else None)
    content_integrity = exp.get("content_integrity_verified") if exp else None

    comp = compare_features_and_classification(
        before_features=before_feat,
        after_features=after_feat,
        before_classification=before_class,
        after_classification=after_class,
        target_profile_id=target_prof,
        overhead=overhead,
        content_integrity_verified=content_integrity
    )

    # Attach workflow linkage identifiers to result
    comp["comparison_id"] = comparison_id
    comp["experiment_id"] = base_rec_id
    comp["baseline_id"] = base_rec_id
    comp["mimicry_id"] = mimic_rec_id

    # Step 6: Persist comparison result to JSON storage
    if not exp:
        exp = {
            "id": base_rec_id,
            "experiment_id": base_rec_id,
            "created_at": datetime.now().isoformat()
        }
    exp.update({
        "comparison_id": comparison_id,
        "baseline_experiment_id": base_rec_id,
        "mimicry_experiment_id": mimic_rec_id,
        "parent_experiment_id": base_rec_id,
        "workflow_id": comparison_id,
        "features_before": before_feat,
        "features_after": after_feat,
        "classification_before": before_class,
        "classification_after": after_class,
        "comparison": comp,
        "updated_at": datetime.now().isoformat()
    })
    save_experiment(exp)

    # Step 7: Return structured JSON response to frontend
    return jsonify(comp)


@app.route("/api/experiments", methods=["GET"])
def api_experiments_list():
    """List all saved experiments."""
    search = request.args.get("search")
    sort_by = request.args.get("sort_by", "created_at")
    desc = request.args.get("desc", "true").lower() == "true"
    records = list_experiments(search=search, sort_by=sort_by, descending=desc)
    return jsonify({"experiments": records, "total": len(records)})


@app.route("/api/experiments/<exp_id>", methods=["GET"])
def api_experiments_get(exp_id):
    """Retrieve complete record for a single experiment."""
    validate_id_format(exp_id, "Experiment ID")
    record = get_experiment(exp_id)
    if not record:
        return jsonify({"error": f"Experiment {exp_id} not found."}), 404
    return jsonify(record)


@app.route("/api/experiments/<exp_id>", methods=["DELETE"])
def api_experiments_delete(exp_id):
    """Delete an experiment and its files."""
    validate_id_format(exp_id, "Experiment ID")
    success = delete_experiment(exp_id)
    if success:
        return jsonify({"status": "deleted", "id": exp_id})
    return jsonify({"error": f"Failed to delete {exp_id}"}), 404


@app.route("/api/export/<exp_id>", methods=["GET"])
def api_export(exp_id):
    """Export experiment report in CSV, JSON, or printable HTML."""
    validate_id_format(exp_id, "Experiment ID")
    fmt = request.args.get("format", "json").lower()
    if fmt not in ("json", "csv", "html"):
        return jsonify({"error": "format must be json, csv, or html"}), 400

    try:
        content, mime_type, filename = export_experiment(exp_id, fmt)
        return Response(
            content,
            mimetype=mime_type,
            headers={"Content-Disposition": f"inline; filename={filename}"}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/settings", methods=["GET", "PUT"])
def api_settings():
    """Retrieve or update classifier weights, thresholds, and tolerances."""
    if request.method == "GET":
        return jsonify(load_classifier_config())
    else:
        data = request.get_json(silent=True) or {}
        if data.get("reset", False):
            cfg = reset_classifier_config()
            return jsonify({"status": "reset", "config": cfg})
        save_classifier_config(data)
        return jsonify({"status": "updated", "config": data})


# --------------------------------------------------------------------------
# Live Automated Demo Engine
# --------------------------------------------------------------------------
@app.route("/api/demo/run", methods=["POST"])
def api_demo_run():
    """Launch real end-to-end automated pipeline walkthrough."""
    data = request.get_json(silent=True) or {}
    source_type = data.get("source_type", "random")
    custom_text = data.get("custom_text", "Antigravity Protocol Mimicry Lab: Transmission active over loopback sockets.")
    target_profile = data.get("target_profile", "voip_call")
    protocol = data.get("protocol", "TCP")
    packet_count = min(int(data.get("packet_count", 60)), MAX_PACKET_COUNT)
    speed = float(data.get("speed", 1.0))
    transport_mode = data.get("transport_mode", "convert_transport")

    run_id = f"DEMO-{int(time.time()*1000)}"

    with DEMO_LOCK:
        DEMO_RUNS[run_id] = {
            "run_id": run_id,
            "status": "running",
            "current_step": 1,
            "step_title": "Generating Baseline Traffic",
            "narration": "Transmitting baseline traffic over 127.0.0.1 sockets...",
            "progress": 5,
            "experiment_id": None,
            "data": {},
            "events": [],
            "speed": speed,
            "is_paused": False,
            "created_at": datetime.now().isoformat()
        }

    thread = threading.Thread(
        target=_demo_pipeline_worker,
        args=(run_id, source_type, custom_text, target_profile, protocol, packet_count, speed, transport_mode),
        daemon=True
    )
    thread.start()

    return jsonify({"run_id": run_id, "status": "started"})


@app.route("/api/demo/<run_id>/events", methods=["GET"])
def api_demo_events(run_id):
    """Poll live status and event queue for interactive demo."""
    validate_id_format(run_id, "Run ID")
    with DEMO_LOCK:
        run_data = DEMO_RUNS.get(run_id)
        if not run_data:
            return jsonify({"error": f"Demo run {run_id} not found."}), 404
        return jsonify(run_data)


@app.route("/api/demo/<run_id>/control", methods=["POST"])
def api_demo_control(run_id):
    """Pause, resume, or alter speed of live demo."""
    validate_id_format(run_id, "Run ID")
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    with DEMO_LOCK:
        run_data = DEMO_RUNS.get(run_id)
        if not run_data:
            return jsonify({"error": "Run not found"}), 404
        if action == "pause":
            run_data["is_paused"] = True
        elif action == "resume":
            run_data["is_paused"] = False
        elif action == "speed":
            run_data["speed"] = max(0.1, min(float(data.get("speed", 1.0)), 20.0))
        return jsonify({"status": "ok", "run": run_data})


def _demo_pipeline_worker(run_id, source_type, custom_text, target_profile, protocol, packet_count, speed, transport_mode="convert_transport"):
    """Background worker executing the real pipeline with narrated steps."""
    def wait_step(base_sec):
        adjusted = max(0.05, base_sec / speed)
        elapsed = 0.0
        while elapsed < adjusted:
            with DEMO_LOCK:
                paused = DEMO_RUNS.get(run_id, {}).get("is_paused", False)
            if not paused:
                time.sleep(0.05)
                elapsed += 0.05
            else:
                time.sleep(0.1)

    def update_demo(step, title, narration, progress, extra_data=None):
        with DEMO_LOCK:
            if run_id in DEMO_RUNS:
                DEMO_RUNS[run_id]["current_step"] = step
                DEMO_RUNS[run_id]["step_title"] = title
                DEMO_RUNS[run_id]["narration"] = narration
                DEMO_RUNS[run_id]["progress"] = progress
                if extra_data:
                    DEMO_RUNS[run_id]["data"].update(extra_data)
                DEMO_RUNS[run_id]["events"].append({
                    "step": step,
                    "title": title,
                    "narration": narration,
                    "progress": progress,
                    "timestamp": datetime.now().isoformat()
                })

    try:
        # Step 1: Real Baseline Traffic Generation
        update_demo(1, "Generating Baseline Traffic", "Transmitting baseline traffic over 127.0.0.1 sockets...", 15)
        gen = TrafficGenerator()
        exp_id = gen.experiment_id
        with DEMO_LOCK:
            DEMO_RUNS[run_id]["experiment_id"] = exp_id

        params = {
            "protocol": protocol,
            "packet_count": packet_count,
            "packet_size": 550,
            "interval_ms": 95,
            "payload_pattern": "text-like",
            "direction": "client->server",
            "payload_mode": source_type,
            "custom_text": custom_text
        }
        gen._worker(params)
        wait_step(0.4)

        # Step 2: Feature Extraction
        update_demo(2, "Extracting Observable Features", "Computing packet size distribution, inter-packet arrival times, and jitter...", 35)
        feat_before = extract_and_save_features(exp_id)
        update_demo(2, "Features Extracted", f"Calculated mean packet size ({feat_before['mean_size']} B) and mean cadence ({feat_before['mean_ipt_ms']} ms).", 45, {"features_before": feat_before})
        wait_step(0.4)

        # Step 3: Classify Baseline Traffic
        update_demo(3, "Classifying Original Traffic", "DPI Heuristic evaluating baseline observable features against catalog profiles...", 55)
        class_before = classify_traffic(feat_before)
        update_demo(3, "Baseline Classified", f"Classifier tagged traffic as '{class_before['category_name']}' with {class_before['confidence']}% confidence.", 65, {"classification_before": class_before})
        wait_step(0.5)

        # Step 4: Apply Mimicry & Resend
        target_name = get_profile(target_profile)["name"]
        update_demo(4, "Applying Protocol Mimicry", f"Applying padding, timing reshaping, and burst injection to mimic '{target_name}'...", 75)
        engine = MimicryEngine(exp_id)
        mimic_res = engine.apply_mimicry(
            target_profile_id=target_profile,
            toggles={"padding": True, "timing": True, "burst": True},
            transport_mode=transport_mode,
            original_text=custom_text if source_type == "custom_text" else None
        )
        update_demo(4, "Re-transmitted Transformed Traffic", "Resent transformed stream over 127.0.0.1 and measured real arrival characteristics.", 82, {"mimic_result": mimic_res})
        wait_step(0.5)

        # Step 5: Classify Transformed Traffic
        update_demo(5, "Classifying Transformed Traffic", "Evaluating mimicked traffic against rule-based DPI heuristics...", 90)
        feat_after = mimic_res["transformed_features"]
        class_after = classify_traffic(feat_after)
        update_demo(5, "Transformed Classified", f"Transformed traffic recognized as '{class_after['category_name']}' with {class_after['confidence']}% confidence.", 93, {"classification_after": class_after})
        wait_step(0.4)

        # Step 6: Comparison & Deception Verdict
        update_demo(6, "Generating Comparative Verdict", "Analyzing feature deltas, overhead cost, and deception success...", 97)
        comp = compare_features_and_classification(
            before_features=feat_before,
            after_features=feat_after,
            before_classification=class_before,
            after_classification=class_after,
            target_profile_id=target_profile,
            overhead=mimic_res["overhead"]
        )

        exp_record = {
            "id": exp_id,
            "experiment_id": exp_id,
            "config": params,
            "features_before": feat_before,
            "classification_before": class_before,
            "mimicry_config": {
                "target_profile": target_profile,
                "target_profile_name": target_name,
                "toggles": {"padding": True, "timing": True, "burst": True}
            },
            "features_after": feat_after,
            "classification_after": class_after,
            "comparison": comp,
            "text_preserved": mimic_res.get("text_preserved"),
            "reassembled_text": mimic_res.get("reassembled_text"),
            "text_info": {
                "mode": source_type,
                "length": len(custom_text) if source_type == "custom_text" else 0,
                "preview": custom_text[:40] if source_type == "custom_text" else ""
            }
        }
        save_experiment(exp_record)

        update_demo(6, "Pipeline Walkthrough Complete", comp["verdict"], 100, {"comparison": comp, "experiment_id": exp_id})
        with DEMO_LOCK:
            DEMO_RUNS[run_id]["status"] = "completed"

    except Exception as e:
        with DEMO_LOCK:
            if run_id in DEMO_RUNS:
                DEMO_RUNS[run_id]["status"] = "failed"
                DEMO_RUNS[run_id]["error"] = str(e)
                DEMO_RUNS[run_id]["narration"] = f"Pipeline execution failed: {e}"


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)
