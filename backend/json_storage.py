"""
Persistent JSON Storage Engine for Protocol Mimicry Engine.
Maintains 5 structured JSON datasets:
1. transferred_files.json - Transferred file records with SHA-256 checksums and storage refs.
2. analysis_results.json  - Statistical features and DPI classification scores.
3. experiments.json       - Complete experimental runs with baseline & mimicked comparisons.
4. lab_details.json       - Versioned laboratory configuration, profiles, and parameters.
5. transfer_logs.json     - Timestamped event logs and audit trails.

Features:
- Thread-safe RLock single-writer coordination.
- Atomic filesystem replacement (NamedTemporaryFile + os.replace + fsync).
- Safe initialization of missing or malformed datasets with automatic backup.
- Pagination, search, and protocol filtering.
- Pure JSON (zero SQL or external database dependencies).
"""

import os
import re
import csv
import io
import json
import time
import hashlib
import mimetypes
import tempfile
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Union

from backend.config import (
    DATA_DIR, STORAGE_DIR, UPLOADS_DIR,
    TRANSFERRED_FILES_PATH, ANALYSIS_RESULTS_PATH, EXPERIMENTS_PATH,
    LAB_DETAILS_PATH, TRANSFER_LOGS_PATH,
    DEFAULT_CLASSIFIER_CONFIG, ensure_directories
)

# Thread synchronization locks per dataset
LOCKS: Dict[str, threading.RLock] = {
    "files": threading.RLock(),
    "analysis": threading.RLock(),
    "experiments": threading.RLock(),
    "lab": threading.RLock(),
    "logs": threading.RLock()
}


# --------------------------------------------------------------------------
# Atomic I/O Helpers
# --------------------------------------------------------------------------
def _atomic_write_json(target_path: Path, data: Any) -> None:
    """Atomically write JSON data to target_path using tempfile and os.replace."""
    ensure_directories()
    parent_dir = target_path.parent
    parent_dir.mkdir(parents=True, exist_ok=True)

    fd, tmp_file_path = tempfile.mkstemp(
        dir=str(parent_dir),
        prefix=f".tmp_{target_path.stem}_",
        suffix=".json"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file_path, str(target_path))
    except Exception as e:
        if os.path.exists(tmp_file_path):
            try:
                os.unlink(tmp_file_path)
            except Exception:
                pass
        raise IOError(f"Failed atomic write to {target_path}: {e}") from e


def _read_json(target_path: Path, default_factory) -> Any:
    """Safely read JSON data, backing up corrupted files if necessary."""
    ensure_directories()
    if not target_path.exists():
        data = default_factory()
        _atomic_write_json(target_path, data)
        return data

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                data = default_factory()
                _atomic_write_json(target_path, data)
                return data
            return json.loads(content)
    except Exception as e:
        # Create corrupted file backup
        backup_name = target_path.with_name(f"{target_path.stem}_corrupt_{int(time.time()*1000)}.bak")
        try:
            target_path.rename(backup_name)
        except Exception:
            pass
        data = default_factory()
        _atomic_write_json(target_path, data)
        return data


# --------------------------------------------------------------------------
# 1. Transferred Files Dataset (`transferred_files.json`)
# --------------------------------------------------------------------------
def save_transferred_file(record: Dict[str, Any]) -> Dict[str, Any]:
    """Insert or update a transferred file record."""
    if "file_id" not in record:
        record["file_id"] = f"FILE-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{os.urandom(2).hex()}"

    now_iso = datetime.now().isoformat()
    record["updated_at"] = now_iso
    if "created_at" not in record:
        record["created_at"] = now_iso

    with LOCKS["files"]:
        files = _read_json(TRANSFERRED_FILES_PATH, list)
        idx = next((i for i, f in enumerate(files) if f.get("file_id") == record["file_id"]), -1)
        if idx >= 0:
            files[idx] = record
        else:
            files.insert(0, record)
        _atomic_write_json(TRANSFERRED_FILES_PATH, files)

    # Automatically generate an audit log entry
    log_transfer_event(
        event_type="file_transfer",
        status=record.get("status", "completed"),
        message=f"File '{record.get('original_filename')}' ({record.get('size_bytes', 0)} B) logged with status {record.get('status')}.",
        file_id=record["file_id"],
        experiment_id=record.get("experiment_id"),
        details={
            "protocol": record.get("transfer_protocol"),
            "sha256": record.get("sha256"),
            "integrity_verified": record.get("integrity_verified", False)
        }
    )
    return record


def get_transferred_file(file_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve metadata record for a single transferred file."""
    with LOCKS["files"]:
        files = _read_json(TRANSFERRED_FILES_PATH, list)
        return next((f for f in files if f.get("file_id") == file_id), None)


def list_transferred_files(
    page: int = 1,
    per_page: int = 20,
    search: Optional[str] = None,
    protocol: Optional[str] = None,
    status: Optional[str] = None
) -> Dict[str, Any]:
    """Retrieve paginated, filtered list of transferred files."""
    with LOCKS["files"]:
        files = _read_json(TRANSFERRED_FILES_PATH, list)

    filtered = files
    if protocol:
        p_clean = protocol.strip().upper()
        filtered = [f for f in filtered if f.get("transfer_protocol", "").upper() == p_clean]
    if status:
        s_clean = status.strip().lower()
        filtered = [f for f in filtered if f.get("status", "").lower() == s_clean]
    if search:
        q = search.strip().lower()
        filtered = [
            f for f in filtered
            if q in f.get("file_id", "").lower() or
               q in f.get("original_filename", "").lower() or
               q in f.get("sha256", "").lower() or
               q in f.get("experiment_id", "").lower()
        ]

    total = len(filtered)
    page = max(1, page)
    per_page = max(1, min(per_page, 100))
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    items = filtered[start_idx:end_idx]

    return {
        "items": items,
        "files": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total > 0 else 1
    }


def delete_transferred_file(file_id: str) -> bool:
    """Delete transferred file metadata and underlying binary file."""
    with LOCKS["files"]:
        files = _read_json(TRANSFERRED_FILES_PATH, list)
        target = next((f for f in files if f.get("file_id") == file_id), None)
        if not target:
            return False

        # Remove record
        files = [f for f in files if f.get("file_id") != file_id]
        _atomic_write_json(TRANSFERRED_FILES_PATH, files)

    # Remove binary storage file if exists
    storage_path = target.get("storage_path")
    if storage_path:
        p = Path(storage_path)
        if not p.is_absolute():
            p = (BASE_DIR / p).resolve()
        try:
            if p.exists() and p.is_file():
                p.unlink()
        except Exception:
            pass

    log_transfer_event(
        event_type="file_delete",
        status="success",
        message=f"File {file_id} ({target.get('original_filename')}) was deleted from laboratory storage.",
        file_id=file_id,
        experiment_id=target.get("experiment_id")
    )
    return True


# --------------------------------------------------------------------------
# 2. Analysis Results Dataset (`analysis_results.json`)
# --------------------------------------------------------------------------
def save_analysis_result(record: Dict[str, Any]) -> Dict[str, Any]:
    """Save feature extraction and classification analysis results."""
    if "analysis_id" not in record:
        record["analysis_id"] = f"ANALYSIS-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{os.urandom(2).hex()}"

    now_iso = datetime.now().isoformat()
    record["analysis_timestamp"] = record.get("analysis_timestamp", now_iso)
    record["execution_status"] = record.get("execution_status", "completed")

    with LOCKS["analysis"]:
        analyses = _read_json(ANALYSIS_RESULTS_PATH, list)
        idx = next((i for i, a in enumerate(analyses) if a.get("analysis_id") == record["analysis_id"]), -1)
        if idx >= 0:
            analyses[idx] = record
        else:
            analyses.insert(0, record)
        _atomic_write_json(ANALYSIS_RESULTS_PATH, analyses)

    return record


def get_analysis_result(analysis_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve single analysis result record by ID."""
    with LOCKS["analysis"]:
        analyses = _read_json(ANALYSIS_RESULTS_PATH, list)
        return next((a for a in analyses if a.get("analysis_id") == analysis_id), None)


def get_analysis_by_experiment(experiment_id: str, stage: str = "before") -> Optional[Dict[str, Any]]:
    """Retrieve analysis record for a given experiment and stage ('before' or 'after')."""
    with LOCKS["analysis"]:
        analyses = _read_json(ANALYSIS_RESULTS_PATH, list)
        for a in analyses:
            if a.get("experiment_id") == experiment_id and a.get("stage", "before") == stage:
                return a
    return None


def list_analysis_results(
    page: int = 1,
    per_page: int = 20,
    search: Optional[str] = None,
    experiment_id: Optional[str] = None
) -> Dict[str, Any]:
    """List paginated analysis records."""
    with LOCKS["analysis"]:
        analyses = _read_json(ANALYSIS_RESULTS_PATH, list)

    filtered = analyses
    if experiment_id:
        filtered = [a for a in filtered if a.get("experiment_id") == experiment_id]
    if search:
        q = search.strip().lower()
        filtered = [
            a for a in filtered
            if q in a.get("analysis_id", "").lower() or
               q in a.get("experiment_id", "").lower() or
               q in str(a.get("classifier_result", {}).get("category_name", "")).lower()
        ]

    total = len(filtered)
    page = max(1, page)
    per_page = max(1, min(per_page, 100))
    start_idx = (page - 1) * per_page
    items = filtered[start_idx:start_idx + per_page]

    return {
        "items": items,
        "analyses": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total > 0 else 1
    }


# --------------------------------------------------------------------------
# 3. Experiments Dataset (`experiments.json`)
# --------------------------------------------------------------------------
def save_experiment(record: Dict[str, Any]) -> Dict[str, Any]:
    """Insert or update a complete experimental record in experiments.json."""
    exp_id = record.get("id") or record.get("experiment_id")
    if not exp_id:
        exp_id = f"EXP-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{os.urandom(2).hex()}"
        record["id"] = exp_id
    record["experiment_id"] = exp_id

    now_iso = datetime.now().isoformat()
    record["updated_at"] = now_iso
    if "created_at" not in record:
        record["created_at"] = now_iso

    with LOCKS["experiments"]:
        experiments = _read_json(EXPERIMENTS_PATH, list)
        idx = next((i for i, e in enumerate(experiments) if e.get("id") == exp_id or e.get("experiment_id") == exp_id), -1)
        if idx >= 0:
            experiments[idx] = record
        else:
            experiments.insert(0, record)
        _atomic_write_json(EXPERIMENTS_PATH, experiments)

    # Mirror to individual JSON file inside data/experiments/ for backward compatibility
    try:
        indiv_path = DATA_DIR / "experiments" / f"{exp_id}.json"
        indiv_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(indiv_path, record)
    except Exception:
        pass

    return record


def get_experiment(exp_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve complete experiment by ID or linked workflow/mimicry ID."""
    with LOCKS["experiments"]:
        experiments = _read_json(EXPERIMENTS_PATH, list)
        record = next((
            e for e in experiments
            if e.get("id") == exp_id or
               e.get("experiment_id") == exp_id or
               e.get("comparison_id") == exp_id or
               e.get("workflow_id") == exp_id or
               e.get("mimicry_experiment_id") == exp_id or
               e.get("baseline_experiment_id") == exp_id or
               e.get("parent_experiment_id") == exp_id
        ), None)
        if record:
            return record

    # Fallback to individual file if present in DATA_DIR / experiments
    candidates = [
        DATA_DIR / "experiments" / f"{exp_id}.json",
        EXPERIMENTS_PATH.parent / "experiments" / f"{exp_id}.json"
    ]
    if exp_id.endswith("_mimic"):
        clean_id = exp_id[:-6]
        candidates.append(DATA_DIR / "experiments" / f"{clean_id}.json")

    for indiv_path in candidates:
        if indiv_path.exists():
            try:
                with open(indiv_path, "r", encoding="utf-8") as f:
                    rec = json.load(f)
                    save_experiment(rec)
                    return rec
            except Exception:
                continue
    return None


def list_experiments(
    page: int = 1,
    per_page: int = 50,
    search: Optional[str] = None,
    sort_by: str = "created_at",
    descending: bool = True
) -> List[Dict[str, Any]]:
    """List experiment summaries (preserves return structure expected by existing frontend)."""
    with LOCKS["experiments"]:
        experiments = _read_json(EXPERIMENTS_PATH, list)

    summaries = []
    for data in experiments:
        exp_id = data.get("id") or data.get("experiment_id", "")
        config = data.get("config") or {}
        feat_before = data.get("features_before") or {}
        class_before = data.get("classification_before") or {}
        mimic_cfg = data.get("mimicry_config") or {}
        class_after = data.get("classification_after") or {}
        comparison = data.get("comparison") or {}
        text_info = data.get("text_info") or {}

        summary = {
            "id": exp_id,
            "created_at": data.get("created_at", ""),
            "protocol": config.get("protocol", "TCP"),
            "payload_mode": config.get("payload_mode", "pattern"),
            "packet_count": feat_before.get("packet_count", 0),
            "category_before": class_before.get("category_name", "Unknown"),
            "confidence_before": class_before.get("confidence", 0.0),
            "target_profile": mimic_cfg.get("target_profile_name", "-"),
            "category_after": class_after.get("category_name", "-"),
            "confidence_after": class_after.get("confidence", 0.0),
            "fooled": comparison.get("fooled", False),
            "status_banner": comparison.get("status_banner", "BASELINE"),
            "text_preview": text_info.get("preview", ""),
            "file_id": data.get("file_id"),
            "comparison_id": data.get("comparison_id", exp_id),
            "baseline_experiment_id": data.get("baseline_experiment_id", exp_id),
            "mimicry_experiment_id": data.get("mimicry_experiment_id"),
            "has_comparison": bool(comparison),
            "has_mimicry": bool(data.get("features_after"))
        }
        if search:
            q = search.lower()
            if (q in summary["id"].lower() or
                q in summary["category_before"].lower() or
                q in summary["category_after"].lower() or
                q in summary["target_profile"].lower() or
                q in summary["protocol"].lower()):
                summaries.append(summary)
        else:
            summaries.append(summary)

    def sort_key(item):
        return item.get(sort_by, "")

    summaries.sort(key=sort_key, reverse=descending)
    return summaries


def delete_experiment(exp_id: str) -> bool:
    """Delete an experiment from experiments.json and related feature/trace files."""
    deleted = False
    with LOCKS["experiments"]:
        experiments = _read_json(EXPERIMENTS_PATH, list)
        before_len = len(experiments)
        experiments = [e for e in experiments if e.get("id") != exp_id and e.get("experiment_id") != exp_id]
        if len(experiments) < before_len:
            _atomic_write_json(EXPERIMENTS_PATH, experiments)
            deleted = True

    # Delete individual mirror file
    indiv_path = DATA_DIR / "experiments" / f"{exp_id}.json"
    if indiv_path.exists():
        try:
            indiv_path.unlink()
            deleted = True
        except Exception:
            pass

    # Clean associated traffic CSV files
    traffic_dir = DATA_DIR / "traffic"
    if traffic_dir.exists():
        for p in traffic_dir.glob(f"{exp_id}*.csv"):
            try:
                p.unlink()
            except Exception:
                pass

    log_transfer_event(
        event_type="experiment_delete",
        status="success",
        message=f"Experiment {exp_id} and associated traces deleted.",
        experiment_id=exp_id
    )
    return deleted


def export_experiment(exp_id: str, fmt: str = "json") -> Tuple[str, str, str]:
    """
    Export experiment into JSON, CSV, or printable HTML format.
    Returns (content_string, mime_type, filename).
    """
    exp = get_experiment(exp_id)
    if not exp:
        raise FileNotFoundError(f"Experiment {exp_id} not found.")

    fmt_clean = fmt.lower()

    if fmt_clean == "json":
        return json.dumps(exp, indent=2), "application/json", f"{exp_id}.json"

    elif fmt_clean == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Metric", "Before (Baseline)", "After (Mimicked)", "Delta", "Percent Change"])

        deltas = exp.get("comparison", {}).get("deltas", {})
        for metric_key, val in deltas.items():
            writer.writerow([
                val.get("label", metric_key),
                val.get("before", 0),
                val.get("after", 0),
                val.get("delta", 0),
                f"{val.get('percent_change', 0)}%"
            ])

        writer.writerow([])
        writer.writerow(["Classification Stage", "Category", "Confidence", "Label"])
        c_before = exp.get("classification_before", {})
        c_after = exp.get("classification_after", {})
        writer.writerow(["Before", c_before.get("category_name", "-"), f"{c_before.get('confidence', 0)}%", c_before.get("label", "-")])
        if c_after:
            writer.writerow(["After", c_after.get("category_name", "-"), f"{c_after.get('confidence', 0)}%", c_after.get("label", "-")])

        return output.getvalue(), "text/csv", f"{exp_id}_comparison.csv"

    elif fmt_clean == "html":
        c_b = exp.get("classification_before", {})
        c_a = exp.get("classification_after", {})
        cmp = exp.get("comparison", {})
        ovh = exp.get("comparison", {}).get("overhead", {})
        deltas = cmp.get("deltas", {})

        delta_rows = ""
        for m_key, d in deltas.items():
            delta_rows += f"""
            <tr>
                <td style="padding:8px 12px;border-bottom:1px solid #E2E8F0;">{d.get('label', m_key)}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #E2E8F0;text-align:right;">{d.get('before', 0)}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #E2E8F0;text-align:right;">{d.get('after', 0)}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #E2E8F0;text-align:right;font-weight:600;">{d.get('delta', 0)}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #E2E8F0;text-align:right;">{d.get('percent_change', 0)}%</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Laboratory Report - {exp_id}</title>
<style>
  body {{ font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #FFFFFF; color: #0F172A; margin: 40px; line-height: 1.5; }}
  .header {{ border-bottom: 2px solid #2563EB; padding-bottom: 16px; margin-bottom: 24px; }}
  .badge {{ display: inline-block; padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 700; background: #EAF1FF; color: #2563EB; }}
  .success-banner {{ background: #DCFCE7; color: #16A34A; padding: 12px 16px; border-radius: 8px; font-weight: 700; margin: 16px 0; }}
  .warning-banner {{ background: #FEF3C7; color: #D97706; padding: 12px 16px; border-radius: 8px; font-weight: 700; margin: 16px 0; }}
  .card {{ border: 1px solid #E2E8F0; border-radius: 8px; padding: 16px; margin-bottom: 20px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 14px; }}
  th {{ background: #F8FAFC; text-align: left; padding: 8px 12px; border-bottom: 2px solid #E2E8F0; }}
  @media print {{ body {{ margin: 0; }} }}
</style>
</head>
<body>
  <div class="header">
    <div class="badge">CONTROLLED EXPERIMENT REPORT</div>
    <h1 style="margin: 8px 0 4px 0; font-size: 24px;">Protocol Mimicry Engine - Laboratory Result</h1>
    <p style="margin: 0; color: #64748B; font-size: 14px;">ID: <strong>{exp_id}</strong> | Generated: {exp.get('created_at', '')}</p>
  </div>

  <div class="card">
    <h3 style="margin-top:0;">1. Executive Verdict</h3>
    <div class="{'success-banner' if cmp.get('fooled_target') else 'warning-banner'}">
      {cmp.get('status_banner', 'BASELINE')} - {cmp.get('verdict', 'No comparison recorded.')}
    </div>
    <p><strong>Baseline Classification:</strong> {c_b.get('category_name', '-')} ({c_b.get('confidence', 0)}% - {c_b.get('label', '-')})</p>
    <p><strong>Target Profile:</strong> {exp.get('mimicry_config', {}).get('target_profile_name', '-')}</p>
    <p><strong>Transformed Classification:</strong> {c_a.get('category_name', '-')} ({c_a.get('confidence', 0)}% - {c_a.get('label', '-')})</p>
  </div>

  <div class="card">
    <h3 style="margin-top:0;">2. Observable Feature Transformations</h3>
    <table>
      <thead>
        <tr>
          <th>Feature</th>
          <th style="text-align:right;">Baseline</th>
          <th style="text-align:right;">Transformed</th>
          <th style="text-align:right;">Delta</th>
          <th style="text-align:right;">Shift %</th>
        </tr>
      </thead>
      <tbody>
        {delta_rows}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3 style="margin-top:0;">3. Network Overhead & Cost Analysis</h3>
    <p><strong>Extra Transmitted Volume:</strong> {ovh.get('extra_bytes_percent', 0)}%</p>
    <p><strong>Added Latency Delay:</strong> {ovh.get('added_delay_percent', 0)}%</p>
    <p><strong>Throughput Change:</strong> {ovh.get('throughput_change_percent', 0)}%</p>
  </div>

  <div style="font-size: 11px; color: #94A3B8; text-align: center; margin-top: 30px; border-top: 1px solid #E2E8F0; padding-top: 12px;">
    Educational Computer Networks Laboratory | Strictly bound to 127.0.0.1 | Rule-based Heuristic DPI Engine
  </div>
</body>
</html>"""
        return html_content, "text/html", f"{exp_id}_report.html"

    else:
        raise ValueError(f"Unsupported export format: {fmt}")



# --------------------------------------------------------------------------
# 4. Laboratory Details Dataset (`lab_details.json`)
# --------------------------------------------------------------------------
DEFAULT_LAB_DETAILS: Dict[str, Any] = {
    "lab_name": "Protocol Mimicry Engine — Controlled Traffic Analysis Laboratory",
    "version": "1.0.0",
    "description": "Educational computer-networks laboratory demonstrating heuristic DPI traffic classification and controlled protocol mimicry.",
    "status": "online",
    "safety_guard": "127.0.0.1 Loopback Only (No packet injection, no external proxying)",
    "supported_transports": ["TCP", "UDP"],
    "storage_engine": "Structured Atomic JSON Persistence",
    "datasets": {
        "transferred_files": "data/transferred_files.json",
        "analysis_results": "data/analysis_results.json",
        "experiments": "data/experiments.json",
        "lab_details": "data/lab_details.json",
        "transfer_logs": "data/transfer_logs.json"
    },
    "classifier_profiles": [
        "bulk_transfer", "voip_call", "dns_lookup", "video_stream", "interactive_shell"
    ],
    "classifier_config": DEFAULT_CLASSIFIER_CONFIG,
    "limits": {
        "max_packet_count": 1000,
        "max_packet_size": 1500,
        "max_file_size_bytes": 10 * 1024 * 1024
    },
    "created_at": datetime.now().isoformat(),
    "updated_at": datetime.now().isoformat()
}


def get_lab_details() -> Dict[str, Any]:
    """Retrieve current laboratory configuration."""
    with LOCKS["lab"]:
        return _read_json(LAB_DETAILS_PATH, lambda: DEFAULT_LAB_DETAILS.copy())


def update_lab_details(updates: Dict[str, Any]) -> Dict[str, Any]:
    """Update authorized laboratory configuration fields."""
    with LOCKS["lab"]:
        current = _read_json(LAB_DETAILS_PATH, lambda: DEFAULT_LAB_DETAILS.copy())
        # Safe updates only (protect system keys)
        for k, v in updates.items():
            if k not in ("created_at", "datasets", "storage_engine"):
                current[k] = v
        current["updated_at"] = datetime.now().isoformat()
        _atomic_write_json(LAB_DETAILS_PATH, current)

    log_transfer_event(
        event_type="system_config",
        status="updated",
        message="Laboratory configuration updated.",
        details={"updated_keys": list(updates.keys())}
    )
    return current


def reset_lab_details() -> Dict[str, Any]:
    """Reset laboratory configuration to factory default."""
    with LOCKS["lab"]:
        defaults = DEFAULT_LAB_DETAILS.copy()
        defaults["updated_at"] = datetime.now().isoformat()
        _atomic_write_json(LAB_DETAILS_PATH, defaults)
    return defaults


# --------------------------------------------------------------------------
# 5. Transfer Logs Dataset (`transfer_logs.json`)
# --------------------------------------------------------------------------
def log_transfer_event(
    event_type: str,
    status: str,
    message: str,
    file_id: Optional[str] = None,
    experiment_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None
) -> Dict[str, Any]:
    """Append a structured, sanitized event record to transfer_logs.json."""
    event_id = f"LOG-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{os.urandom(2).hex()}"
    log_entry = {
        "event_id": event_id,
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "status": status,
        "message": message,
        "file_id": file_id,
        "experiment_id": experiment_id,
        "details": details or {},
        "error": error
    }

    with LOCKS["logs"]:
        logs = _read_json(TRANSFER_LOGS_PATH, list)
        logs.insert(0, log_entry)
        # Cap log history to latest 500 entries to prevent unbounded disk growth
        if len(logs) > 500:
            logs = logs[:500]
        _atomic_write_json(TRANSFER_LOGS_PATH, logs)

    return log_entry


def list_transfer_logs(
    page: int = 1,
    per_page: int = 50,
    search: Optional[str] = None,
    event_type: Optional[str] = None,
    status: Optional[str] = None
) -> Dict[str, Any]:
    """Retrieve paginated, filtered transfer log entries."""
    with LOCKS["logs"]:
        logs = _read_json(TRANSFER_LOGS_PATH, list)

    filtered = logs
    if event_type:
        e_clean = event_type.strip().lower()
        filtered = [l for l in filtered if l.get("event_type", "").lower() == e_clean]
    if status:
        s_clean = status.strip().lower()
        filtered = [l for l in filtered if l.get("status", "").lower() == s_clean]
    if search:
        q = search.strip().lower()
        filtered = [
            l for l in filtered
            if q in l.get("event_id", "").lower() or
               q in l.get("message", "").lower() or
               q in str(l.get("file_id", "")).lower() or
               q in str(l.get("experiment_id", "")).lower()
        ]

    total = len(filtered)
    page = max(1, page)
    per_page = max(1, min(per_page, 200))
    start_idx = (page - 1) * per_page
    items = filtered[start_idx:start_idx + per_page]

    return {
        "items": items,
        "logs": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total > 0 else 1
    }


# --------------------------------------------------------------------------
# File Storage & Integrity Helpers
# --------------------------------------------------------------------------
def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal or shell exploits."""
    if not filename:
        return "unnamed_transfer.bin"
    base = os.path.basename(filename)
    # Strip illegal characters
    cleaned = re.sub(r'[^a-zA-Z0-9_.-]', '_', base)
    if not cleaned or cleaned.startswith('.'):
        cleaned = f"file_{cleaned}"
    return cleaned[:120]


def compute_sha256(data: bytes) -> str:
    """Calculate hex SHA-256 checksum from bytes."""
    return hashlib.sha256(data).hexdigest()


def detect_mime_type(filename: str) -> str:
    """Detect MIME type from filename extension."""
    mime, _ = mimetypes.guess_type(filename)
    return mime or "application/octet-stream"


def store_binary_file(file_id: str, filename: str, data: bytes) -> Tuple[Path, str]:
    """
    Store binary uploaded file in configured persistent UPLOADS_DIR.
    Returns (Path, sha256_checksum).
    """
    ensure_directories()
    if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
        raise ValueError("Invalid destination path: Path traversal detected.")

    safe_name = sanitize_filename(filename)
    dest_path = UPLOADS_DIR / f"{file_id}_{safe_name}"

    # Prevent path traversal
    dest_path = dest_path.resolve()
    if not str(dest_path).startswith(str(UPLOADS_DIR.resolve())):
        raise ValueError("Invalid destination path: Path traversal detected.")

    with open(dest_path, "wb") as f:
        f.write(data)

    checksum = compute_sha256(data)
    return dest_path, checksum


# Safely initialize datasets on module load
ensure_directories()
get_lab_details()
