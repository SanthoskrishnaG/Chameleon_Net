"""
Feature Extraction Engine.
Extracts deep statistical features from raw packet traces for DPI analysis.
Computes size statistics, inter-packet timing (IPT), jitter, burst patterns, and rates.
"""

import csv
import json
import statistics
from pathlib import Path
from typing import Dict, Any, List, Optional

from backend.config import FEATURES_DIR, TRAFFIC_DIR, load_classifier_config


def extract_features_from_packets(
    packets: List[Dict[str, Any]],
    burst_threshold_ms: Optional[float] = None
) -> Dict[str, Any]:
    """
    Extract comprehensive statistical features from a packet list.
    Handles microsecond-precision timestamps and safe division guards.
    """
    if not packets:
        raise ValueError("Cannot extract features from an empty packet list.")

    cfg = load_classifier_config()
    if burst_threshold_ms is None:
        burst_threshold_ms = float(cfg.get("burst_ipt_threshold_ms", 20.0))

    packet_count = len(packets)
    sizes = [int(p.get("size", 0)) for p in packets]
    total_bytes = sum(sizes)

    # Durations and timestamps
    t_start = float(packets[0].get("timestamp", 0.0))
    t_end = float(packets[-1].get("timestamp", 0.0))
    duration = max(0.0001, t_end - t_start)

    # Size statistics
    mean_size = float(statistics.mean(sizes))
    median_size = float(statistics.median(sizes))
    min_size = int(min(sizes))
    max_size = int(max(sizes))
    std_size = float(statistics.stdev(sizes)) if packet_count > 1 else 0.0

    # Size histogram buckets: 0-150, 151-300, 301-600, 601-1000, >1000
    hist_buckets = {
        "0-150": 0,
        "151-300": 0,
        "301-600": 0,
        "601-1000": 0,
        "1001-1500": 0
    }
    for s in sizes:
        if s <= 150:
            hist_buckets["0-150"] += 1
        elif s <= 300:
            hist_buckets["151-300"] += 1
        elif s <= 600:
            hist_buckets["301-600"] += 1
        elif s <= 1000:
            hist_buckets["601-1000"] += 1
        else:
            hist_buckets["1001-1500"] += 1

    # Inter-packet time (IPT) series in milliseconds
    ipt_list_ms: List[float] = []
    for i in range(1, packet_count):
        dt = float(packets[i].get("timestamp", 0.0)) - float(packets[i - 1].get("timestamp", 0.0))
        ipt_list_ms.append(max(0.0, dt * 1000.0))

    if ipt_list_ms:
        mean_ipt_ms = float(statistics.mean(ipt_list_ms))
        median_ipt_ms = float(statistics.median(ipt_list_ms))
        std_ipt_ms = float(statistics.stdev(ipt_list_ms)) if len(ipt_list_ms) > 1 else 0.0
    else:
        mean_ipt_ms = 0.0
        median_ipt_ms = 0.0
        std_ipt_ms = 0.0

    # Jitter: mean absolute difference of consecutive IPTs
    if len(ipt_list_ms) > 1:
        diffs = [abs(ipt_list_ms[i] - ipt_list_ms[i - 1]) for i in range(1, len(ipt_list_ms))]
        jitter_ms = float(statistics.mean(diffs))
    else:
        jitter_ms = 0.0

    # Burst calculation: packets with IPT < burst_threshold_ms grouped
    burst_lengths: List[int] = []
    if ipt_list_ms:
        current_burst = 1
        for dt_ms in ipt_list_ms:
            if dt_ms < burst_threshold_ms:
                current_burst += 1
            else:
                burst_lengths.append(current_burst)
                current_burst = 1
        burst_lengths.append(current_burst)
    else:
        burst_lengths = [1]

    burst_count = len(burst_lengths)
    mean_burst_length = float(statistics.mean(burst_lengths)) if burst_lengths else 1.0

    # Rate and ratios
    packets_per_sec = float(packet_count / duration)
    bytes_per_sec = float(total_bytes / duration)

    fwd_count = sum(1 for p in packets if p.get("direction", "C->S") == "C->S")
    rev_count = sum(1 for p in packets if p.get("direction") == "S->C")
    fwd_rev_ratio = float(fwd_count / max(1, rev_count)) if rev_count > 0 else float(fwd_count)

    proto = packets[0].get("proto", "TCP").upper()

    # Time series sample for UI plotting (max 120 points)
    sampled_ipt = ipt_list_ms[:120] if len(ipt_list_ms) > 120 else ipt_list_ms

    return {
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "duration": round(duration, 4),
        "mean_size": round(mean_size, 2),
        "median_size": round(median_size, 2),
        "min_size": min_size,
        "max_size": max_size,
        "std_size": round(std_size, 2),
        "size_histogram": hist_buckets,
        "mean_ipt_ms": round(mean_ipt_ms, 2),
        "median_ipt_ms": round(median_ipt_ms, 2),
        "std_ipt_ms": round(std_ipt_ms, 2),
        "jitter_ms": round(jitter_ms, 2),
        "burst_count": burst_count,
        "mean_burst_length": round(mean_burst_length, 2),
        "packets_per_sec": round(packets_per_sec, 2),
        "bytes_per_sec": round(bytes_per_sec, 2),
        "forward_count": fwd_count,
        "reverse_count": rev_count,
        "forward_reverse_ratio": round(fwd_rev_ratio, 2),
        "protocol": proto,
        "ipt_series_sample": [round(v, 2) for v in sampled_ipt]
    }


def load_packets_from_csv(csv_path: Path) -> List[Dict[str, Any]]:
    """Parse CSV trace file into packet records."""
    if not csv_path.exists():
        raise FileNotFoundError(f"Trace CSV not found: {csv_path}")

    packets: List[Dict[str, Any]] = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            packets.append({
                "seq": int(row["seq"]),
                "timestamp": float(row["timestamp"]),
                "proto": row["proto"],
                "direction": row["direction"],
                "size": int(row["size"]),
                "crc32": row["crc32"],
                "src_port": int(row.get("src_port", 0)),
                "dst_port": int(row.get("dst_port", 0)),
                "preview": row.get("preview", "")
            })
    return packets


def extract_and_save_features(exp_id: str, suffix: str = "") -> Dict[str, Any]:
    """Load trace CSV, extract features, and save to JSON."""
    file_name = f"{exp_id}{suffix}.csv"
    csv_path = TRAFFIC_DIR / file_name
    packets = load_packets_from_csv(csv_path)

    features = extract_features_from_packets(packets)
    features["experiment_id"] = exp_id
    features["trace_file"] = file_name

    json_path = FEATURES_DIR / f"{exp_id}{suffix}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(features, f, indent=2)

    return features


def load_saved_features(exp_id: str, suffix: str = "") -> Optional[Dict[str, Any]]:
    """Retrieve existing extracted features from disk."""
    json_path = FEATURES_DIR / f"{exp_id}{suffix}.json"
    if json_path.exists():
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None
