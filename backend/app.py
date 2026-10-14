"""
Flask REST API and Static Server for Protocol Mimicry Engine.
Provides deployment-safe security, CORS control, input validation, and loopback safety.
Compatible with Vercel frontend and persistent Python hosting (Render, Railway, VPS).
"""

import os
import re
import json
import time
import uuid
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from flask import Flask, request, jsonify, send_from_directory, Response, abort
from flask_cors import CORS

from backend.config import (
    BASE_DIR, WEB_DIR, TRAFFIC_DIR, FEATURES_DIR, EXPERIMENTS_DIR,
    PORT, HOST, API_KEY, STRICT_LOCAL_IP_GUARD, IS_DEPLOYMENT,
    MAX_ACTIVE_EXPERIMENTS, MAX_PACKET_COUNT, MAX_PACKET_SIZE, MAX_TEXT_LENGTH,
    is_loopback, is_origin_allowed, get_allowed_origins,
    load_classifier_config, save_classifier_config, reset_classifier_config
)
from backend.profiles import get_profiles, get_profile_list, get_profile
from backend.text_payload import preview_chunks, validate_text
from backend.traffic_generator import TrafficGenerator, get_task_status, GENERATION_TASKS, TASKS_LOCK
from backend.feature_extractor import extract_and_save_features, load_saved_features
from backend.dpi_classifier import classify_traffic
from backend.mimicry_engine import MimicryEngine
from backend.comparator import compare_features_and_classification
from backend.result_store import (
    save_experiment, get_experiment, list_experiments, delete_experiment, export_experiment
)

# Initialize Flask Application
app = Flask(__name__, static_folder=str(WEB_DIR), static_url_path="")
app.config["JSON_SORT_KEYS"] = False

# Enable CORS with configured origins (supports credentials=False for security)
CORS(app, resources={r"/api/*": {"origins": "*" if not IS_DEPLOYMENT else get_allowed_origins()}}, supports_credentials=False)

# Live Demo In-Memory State
DEMO_RUNS: Dict[str, Dict[str, Any]] = {}
DEMO_LOCK = threading.Lock()

# Experiment ID Validation Pattern (alphanumeric, hyphens, underscores; prevents path traversal)
EXP_ID_REGEX = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
START_TIME = datetime.now()


def validate_id_format(identifier: str, field_name: str = "Experiment ID") -> None:
    """Validate identifier syntax against directory traversal and shell injection."""
    if not identifier or not EXP_ID_REGEX.match(identifier):
        abort(400, description=f"{field_name} is invalid. Allowed: alphanumeric, hyphens, underscores (1-64 chars).")


# --------------------------------------------------------------------------
# Security & Guard Middleware
# --------------------------------------------------------------------------
@app.before_request
def security_guard():
    """Deployment-safe security middleware."""
    # 1. Fast path for CORS preflight
    if request.method == "OPTIONS":
        return "", 200

    # 2. Strict Local IP Guard (enabled in standalone offline mode or via STRICT_LOCAL_IP_GUARD=true)
    if STRICT_LOCAL_IP_GUARD:
        remote_ip = request.remote_addr
        if not is_loopback(remote_ip):
            return jsonify({
                "error": "Forbidden: Protocol Mimicry Engine is strictly confined to 127.0.0.1 loopback.",
                "remote_addr": remote_ip
            }), 403

    # 3. Authentication for mutating endpoints when API_KEY is configured
    if API_KEY and request.path.startswith("/api/") and request.method in ("POST", "PUT", "DELETE"):
        # Exclude read-only preview from mandatory auth
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
# Centralized Error Handlers (Clean JSON, never leak stack traces)
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
# Static Web Pages & Assets (For standalone / local development)
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
# API Routes
# --------------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def api_health():
    """Health check, deployment state, and laboratory status."""
    uptime_sec = round((datetime.now() - START_TIME).total_seconds(), 1)
    return jsonify({
        "status": "online",
        "engine": "Protocol Mimicry Engine Laboratory",
        "version": "1.0.0",
        "uptime_seconds": uptime_sec,
        "timestamp": datetime.now().isoformat(),
        "deployment_mode": IS_DEPLOYMENT,
        "loopback_only": True,
        "storage": "sqlite+filesystem",
        "auth_required": bool(API_KEY),
        "capabilities": {
            "real_tcp_sockets": True,
            "real_udp_sockets": True,
            "feature_extraction": True,
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

    # Destination Safety Guard: Reject any attempt to target external or remote networks
    dest_host = params.get("host") or params.get("dest") or params.get("target_ip")
    if dest_host and not is_loopback(dest_host):
        return jsonify({
            "error": "Safety violation: External socket destinations are prohibited. Transmissions are strictly confined to 127.0.0.1."
        }), 400

    # Validate parameters
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
    if payload_mode not in ("pattern", "custom_text"):
        return jsonify({"error": "Invalid payload_mode."}), 400

    custom_text = params.get("custom_text", "")
    if payload_mode == "custom_text":
        try:
            validate_text(custom_text)
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    # Concurrency limit check
    with TASKS_LOCK:
        active_count = sum(1 for t in GENERATION_TASKS.values() if t.get("status") == "running")
    if active_count >= MAX_ACTIVE_EXPERIMENTS:
        return jsonify({
            "error": f"Maximum concurrent experiments ({MAX_ACTIVE_EXPERIMENTS}) active. Please wait for current transmission to finish."
        }), 429

    try:
        gen = TrafficGenerator()
        exp_id = gen.run_generation_async(params)
        return jsonify({
            "experiment_id": exp_id,
            "status": "started",
            "message": "Transmission initiated on 127.0.0.1"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/traffic/<exp_id>/status", methods=["GET"])
def api_traffic_status(exp_id):
    """Poll live progress and packet trace for active generation."""
    validate_id_format(exp_id)
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
    validate_id_format(exp_id)
    before = load_saved_features(exp_id)
    if not before:
        try:
            before = extract_and_save_features(exp_id)
        except Exception as e:
            return jsonify({"error": f"Failed to extract features: {e}"}), 404

    after = load_saved_features(exp_id, suffix="_mimic")
    return jsonify({
        "experiment_id": exp_id,
        "features_before": before,
        "features_after": after
    })


@app.route("/api/classify/<exp_id>", methods=["POST"])
def api_classify(exp_id):
    """Run DPI heuristic classification for baseline or mimicked stage."""
    validate_id_format(exp_id)
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
    return jsonify({
        "experiment_id": exp_id,
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
    validate_id_format(exp_id)

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
        after_feat = mimic_res["transformed_features"]

        before_class = classify_traffic(before_feat)
        after_class = classify_traffic(after_feat)

        comparison = compare_features_and_classification(
            before_features=before_feat,
            after_features=after_feat,
            before_classification=before_class,
            after_classification=after_class,
            target_profile_id=target_profile,
            overhead=mimic_res["overhead"]
        )

        exp_record = get_experiment(exp_id) or {"id": exp_id, "config": {}}
        exp_record.update({
            "id": exp_id,
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
            "reassembled_text": mimic_res.get("reassembled_text")
        })
        save_experiment(exp_record)

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


@app.route("/api/compare/<exp_id>", methods=["GET"])
def api_compare(exp_id):
    """Retrieve full comparative analysis between before and after."""
    validate_id_format(exp_id)
    exp = get_experiment(exp_id)
    if exp and "comparison" in exp:
        return jsonify(exp["comparison"])

    before_feat = load_saved_features(exp_id)
    after_feat = load_saved_features(exp_id, suffix="_mimic")
    if not before_feat or not after_feat:
        return jsonify({"error": "Both baseline and mimicry features required for comparison."}), 404

    before_class = classify_traffic(before_feat)
    after_class = classify_traffic(after_feat)
    target_prof = (exp.get("mimicry_config", {}).get("target_profile") if exp else "voip_call") or "voip_call"

    comp = compare_features_and_classification(
        before_feat, after_feat, before_class, after_class, target_prof
    )
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
    validate_id_format(exp_id)
    record = get_experiment(exp_id)
    if not record:
        return jsonify({"error": f"Experiment {exp_id} not found."}), 404
    return jsonify(record)


@app.route("/api/experiments/<exp_id>", methods=["DELETE"])
def api_experiments_delete(exp_id):
    """Delete an experiment and its files."""
    validate_id_format(exp_id)
    success = delete_experiment(exp_id)
    if success:
        return jsonify({"status": "deleted", "id": exp_id})
    return jsonify({"error": f"Failed to delete {exp_id}"}), 404


@app.route("/api/export/<exp_id>", methods=["GET"])
def api_export(exp_id):
    """Export experiment report in CSV, JSON, or printable HTML."""
    validate_id_format(exp_id)
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

        # Persist full experiment
        exp_record = {
            "id": exp_id,
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
