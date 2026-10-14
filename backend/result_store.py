"""
Result Store & Persistence Engine for Protocol Mimicry Engine.
Provides dual persistence:
1. SQLite Database (experiments.db) for reliable, crash-resilient production storage.
2. JSON/CSV file mirror for backward compatibility and laboratory inspectability.
Supports listing, filtering, search, deletion, and exports in JSON, CSV, and HTML formats.
"""

import os
import json
import csv
import io
import sqlite3
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from backend.config import EXPERIMENTS_DIR, TRAFFIC_DIR, FEATURES_DIR, SQLITE_DB_PATH, ensure_directories

DB_LOCK = threading.Lock()


def _get_db_connection() -> sqlite3.Connection:
    """Create or return an SQLite connection with WAL mode enabled."""
    ensure_directories()
    conn = sqlite3.connect(str(SQLITE_DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS experiments (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                protocol TEXT,
                payload_mode TEXT,
                category_before TEXT,
                confidence_before REAL,
                target_profile TEXT,
                category_after TEXT,
                confidence_after REAL,
                fooled INTEGER DEFAULT 0,
                status_banner TEXT,
                text_preview TEXT,
                data TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_exp_created ON experiments(created_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_exp_proto ON experiments(protocol);")
    return conn


# Initialize table on module load
try:
    _conn = _get_db_connection()
    _conn.close()
except Exception as e:
    print(f"[Warning] Failed to initialize SQLite store: {e}")


def save_experiment(record: Dict[str, Any]) -> Path:
    """
    Save or update an experiment in both SQLite and JSON file format.
    Returns the path to the JSON file.
    """
    exp_id = record.get("id")
    if not exp_id:
        raise ValueError("Experiment record must include an 'id' field.")

    now_iso = datetime.now().isoformat()
    record["updated_at"] = now_iso
    if "created_at" not in record:
        record["created_at"] = now_iso

    # Extract indexed summary columns
    protocol = record.get("config", {}).get("protocol", "TCP")
    payload_mode = record.get("config", {}).get("payload_mode", "pattern")
    cat_before = record.get("classification_before", {}).get("category_name", "Unknown")
    conf_before = float(record.get("classification_before", {}).get("confidence", 0.0))
    target_prof = record.get("mimicry_config", {}).get("target_profile_name", "-")
    cat_after = record.get("classification_after", {}).get("category_name", "-")
    conf_after = float(record.get("classification_after", {}).get("confidence", 0.0))
    fooled = 1 if record.get("comparison", {}).get("fooled", False) else 0
    status_banner = record.get("comparison", {}).get("status_banner", "BASELINE")
    text_preview = record.get("text_info", {}).get("preview", "")

    json_str = json.dumps(record, indent=2)

    # 1. Persist to SQLite
    with DB_LOCK:
        try:
            conn = sqlite3.connect(str(SQLITE_DB_PATH), check_same_thread=False)
            with conn:
                conn.execute("""
                    INSERT INTO experiments (
                        id, created_at, updated_at, protocol, payload_mode,
                        category_before, confidence_before, target_profile,
                        category_after, confidence_after, fooled, status_banner,
                        text_preview, data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        updated_at = excluded.updated_at,
                        protocol = excluded.protocol,
                        payload_mode = excluded.payload_mode,
                        category_before = excluded.category_before,
                        confidence_before = excluded.confidence_before,
                        target_profile = excluded.target_profile,
                        category_after = excluded.category_after,
                        confidence_after = excluded.confidence_after,
                        fooled = excluded.fooled,
                        status_banner = excluded.status_banner,
                        text_preview = excluded.text_preview,
                        data = excluded.data;
                """, (
                    exp_id, record["created_at"], record["updated_at"], protocol, payload_mode,
                    cat_before, conf_before, target_prof, cat_after, conf_after, fooled,
                    status_banner, text_preview, json_str
                ))
            conn.close()
        except Exception as e:
            print(f"[Warning] Failed writing experiment to SQLite: {e}")

    # 2. Persist to JSON file mirror
    ensure_directories()
    target_path = EXPERIMENTS_DIR / f"{exp_id}.json"
    try:
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(json_str)
    except Exception as e:
        print(f"[Warning] Failed writing experiment JSON file: {e}")

    return target_path


def get_experiment(exp_id: str) -> Optional[Dict[str, Any]]:
    """Load single experiment record by ID (checks SQLite first, falls back to disk)."""
    # 1. Check SQLite
    with DB_LOCK:
        try:
            conn = sqlite3.connect(str(SQLITE_DB_PATH), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT data FROM experiments WHERE id = ?", (exp_id,)).fetchone()
            conn.close()
            if row and row["data"]:
                return json.loads(row["data"])
        except Exception:
            pass

    # 2. Check JSON file
    path = EXPERIMENTS_DIR / f"{exp_id}.json"
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def list_experiments(
    search: Optional[str] = None,
    sort_by: str = "created_at",
    descending: bool = True
) -> List[Dict[str, Any]]:
    """List all saved experiments with summary fields from SQLite or JSON."""
    records_map: Dict[str, Dict[str, Any]] = {}

    # 1. Fetch from SQLite
    with DB_LOCK:
        try:
            conn = sqlite3.connect(str(SQLITE_DB_PATH), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM experiments").fetchall()
            conn.close()
            for r in rows:
                rec_id = r["id"]
                # Parse packet count from data if available
                packet_count = 0
                try:
                    p_data = json.loads(r["data"])
                    packet_count = p_data.get("features_before", {}).get("packet_count", 0)
                except Exception:
                    pass

                summary = {
                    "id": rec_id,
                    "created_at": r["created_at"],
                    "protocol": r["protocol"] or "TCP",
                    "payload_mode": r["payload_mode"] or "pattern",
                    "packet_count": packet_count,
                    "category_before": r["category_before"] or "Unknown",
                    "confidence_before": float(r["confidence_before"] or 0.0),
                    "target_profile": r["target_profile"] or "-",
                    "category_after": r["category_after"] or "-",
                    "confidence_after": float(r["confidence_after"] or 0.0),
                    "fooled": bool(r["fooled"]),
                    "status_banner": r["status_banner"] or "BASELINE",
                    "text_preview": r["text_preview"] or ""
                }
                records_map[rec_id] = summary
        except Exception as e:
            print(f"[Warning] SQLite list_experiments error: {e}")

    # 2. Reconcile with any JSON files on disk not yet in SQLite
    if EXPERIMENTS_DIR.exists():
        for p in EXPERIMENTS_DIR.glob("*.json"):
            rec_id = p.stem
            if rec_id not in records_map:
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        records_map[rec_id] = {
                            "id": data.get("id", rec_id),
                            "created_at": data.get("created_at", ""),
                            "protocol": data.get("config", {}).get("protocol", "TCP"),
                            "payload_mode": data.get("config", {}).get("payload_mode", "pattern"),
                            "packet_count": data.get("features_before", {}).get("packet_count", 0),
                            "category_before": data.get("classification_before", {}).get("category_name", "Unknown"),
                            "confidence_before": data.get("classification_before", {}).get("confidence", 0.0),
                            "target_profile": data.get("mimicry_config", {}).get("target_profile_name", "-"),
                            "category_after": data.get("classification_after", {}).get("category_name", "-"),
                            "confidence_after": data.get("classification_after", {}).get("confidence", 0.0),
                            "fooled": data.get("comparison", {}).get("fooled", False),
                            "status_banner": data.get("comparison", {}).get("status_banner", "BASELINE"),
                            "text_preview": data.get("text_info", {}).get("preview", "")
                        }
                except Exception:
                    continue

    records = list(records_map.values())

    # Apply search filter
    if search:
        q = search.lower()
        records = [
            r for r in records
            if (q in r["id"].lower() or
                q in r["category_before"].lower() or
                q in r["category_after"].lower() or
                q in r["target_profile"].lower() or
                q in r["protocol"].lower())
        ]

    def sort_key(item):
        return item.get(sort_by, "")

    records.sort(key=sort_key, reverse=descending)
    return records


def delete_experiment(exp_id: str) -> bool:
    """Delete an experiment from SQLite, JSON records, and associated traffic files."""
    deleted = False

    # 1. Delete from SQLite
    with DB_LOCK:
        try:
            conn = sqlite3.connect(str(SQLITE_DB_PATH), check_same_thread=False)
            with conn:
                cur = conn.execute("DELETE FROM experiments WHERE id = ?", (exp_id,))
                if cur.rowcount > 0:
                    deleted = True
            conn.close()
        except Exception:
            pass

    # 2. Delete JSON file
    exp_path = EXPERIMENTS_DIR / f"{exp_id}.json"
    if exp_path.exists():
        try:
            exp_path.unlink()
            deleted = True
        except Exception:
            pass

    # 3. Clean up associated traffic CSVs
    if TRAFFIC_DIR.exists():
        for p in TRAFFIC_DIR.glob(f"{exp_id}*.csv"):
            try:
                p.unlink()
            except Exception:
                pass

    # 4. Clean up associated feature JSONs
    if FEATURES_DIR.exists():
        for p in FEATURES_DIR.glob(f"{exp_id}*.json"):
            try:
                p.unlink()
            except Exception:
                pass

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
