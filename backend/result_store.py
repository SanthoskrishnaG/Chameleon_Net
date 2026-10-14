"""
Result Store & Persistence Engine.
Persists complete experimental runs to data/experiments/<id>.json.
Provides listing, filtering, deletion, and exports in JSON, CSV, and printable HTML formats.
"""

import json
import csv
import io
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from backend.config import EXPERIMENTS_DIR, TRAFFIC_DIR, FEATURES_DIR


def save_experiment(record: Dict[str, Any]) -> Path:
    """Save or update an experiment JSON file."""
    exp_id = record.get("id")
    if not exp_id:
        raise ValueError("Experiment record must include an 'id' field.")

    record["updated_at"] = datetime.now().isoformat()
    if "created_at" not in record:
        record["created_at"] = record["updated_at"]

    target_path = EXPERIMENTS_DIR / f"{exp_id}.json"
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    return target_path


def get_experiment(exp_id: str) -> Optional[Dict[str, Any]]:
    """Load single experiment record by ID."""
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
    """List all saved experiments with summary fields."""
    records: List[Dict[str, Any]] = []

    for p in EXPERIMENTS_DIR.glob("*.json"):
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                summary = {
                    "id": data.get("id", p.stem),
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
                if search:
                    q = search.lower()
                    if (q in summary["id"].lower() or
                        q in summary["category_before"].lower() or
                        q in summary["category_after"].lower() or
                        q in summary["target_profile"].lower()):
                        records.append(summary)
                else:
                    records.append(summary)
        except Exception:
            continue

    def sort_key(item):
        return item.get(sort_by, "")

    records.sort(key=sort_key, reverse=descending)
    return records


def delete_experiment(exp_id: str) -> bool:
    """Delete an experiment and its associated traffic/feature files."""
    deleted = False
    exp_path = EXPERIMENTS_DIR / f"{exp_id}.json"
    if exp_path.exists():
        exp_path.unlink()
        deleted = True

    for p in TRAFFIC_DIR.glob(f"{exp_id}*.csv"):
        try:
            p.unlink()
        except Exception:
            pass

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
        # Professional printable report in light theme
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
