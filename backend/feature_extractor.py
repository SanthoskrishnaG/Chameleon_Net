"""
Feature Extraction Engine.
Extracts deep statistical features from raw packet traces for DPI analysis.
Computes size statistics, inter-packet timing (IPT), jitter, burst patterns, and rates.
Implements robust burst cluster detection and isolated transmission ratios.
"""

import csv
import json
import statistics
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from backend.config import FEATURES_DIR, TRAFFIC_DIR, load_classifier_config


def detect_burst_clusters(
    timestamps_sec: List[float],
    burst_threshold_ms: float = 20.0
) -> Dict[str, Any]:
    """
    Detect burst clusters and isolated transmissions from arrival timestamps.

    Algorithm:
    1. Filter out invalid/None timestamps, convert to float, sort chronologically.
    2. Consecutive arrivals separated by strictly less than burst_threshold_ms
       belong to the same burst cluster.
    3. A burst cluster must contain at least 2 consecutive arrivals connected by intervals < threshold.
    4. An isolated transmission is not part of any burst cluster.
    5. burst_cluster_ratio = transmissions_in_bursts / total_transmissions
       isolated_transmission_ratio = isolated_transmissions / total_transmissions
       burst_cluster_ratio + isolated_transmission_ratio == 1.0 (for non-empty trace).
    """
    # 1. Filter and sort valid timestamps
    valid_ts: List[float] = []
    for ts in timestamps_sec:
        if ts is not None:
            try:
                val = float(ts)
                valid_ts.append(val)
            except (ValueError, TypeError):
                continue

    valid_ts.sort()
    total_transmissions = len(valid_ts)

    # Empty trace guard
    if total_transmissions == 0:
        return {
            "burst_cluster_count": 0,
            "transmissions_in_bursts": 0,
            "isolated_transmission_count": 0,
            "burst_cluster_ratio": 0.0,
            "isolated_transmission_ratio": 0.0,
            "burst_threshold_ms": float(burst_threshold_ms),
            "total_transmissions": 0,
            "clusters": [],
            "mean_burst_length": 0.0,
            "empty_data": True
        }

    # Single transmission guard
    if total_transmissions == 1:
        return {
            "burst_cluster_count": 0,
            "transmissions_in_bursts": 0,
            "isolated_transmission_count": 1,
            "burst_cluster_ratio": 0.0,
            "isolated_transmission_ratio": 1.0,
            "burst_threshold_ms": float(burst_threshold_ms),
            "total_transmissions": 1,
            "clusters": [],
            "mean_burst_length": 1.0,
            "empty_data": False
        }

    # Group consecutive arrivals with interval < burst_threshold_ms
    clusters: List[int] = []
    transmissions_in_bursts = 0
    isolated_transmissions = 0

    i = 0
    while i < total_transmissions:
        j = i
        while j < total_transmissions - 1:
            # Microsecond timestamp difference converted to milliseconds
            interval_ms = (valid_ts[j + 1] - valid_ts[j]) * 1000.0
            if interval_ms < burst_threshold_ms:
                j += 1
            else:
                break

        cluster_size = j - i + 1
        if cluster_size >= 2:
            clusters.append(cluster_size)
            transmissions_in_bursts += cluster_size
        else:
            isolated_transmissions += 1

        i = j + 1

    burst_cluster_count = len(clusters)
    burst_cluster_ratio = round(transmissions_in_bursts / total_transmissions, 4)
    isolated_transmission_ratio = round(isolated_transmissions / total_transmissions, 4)
    mean_burst_len = round(float(statistics.mean(clusters)), 2) if clusters else 1.0

    return {
        "burst_cluster_count": burst_cluster_count,
        "transmissions_in_bursts": transmissions_in_bursts,
        "isolated_transmission_count": isolated_transmissions,
        "burst_cluster_ratio": burst_cluster_ratio,
        "isolated_transmission_ratio": isolated_transmission_ratio,
        "burst_threshold_ms": float(burst_threshold_ms),
        "total_transmissions": total_transmissions,
        "clusters": clusters,
        "mean_burst_length": mean_burst_len,
        "empty_data": False
    }


def extract_features_from_packets(
    packets: List[Dict[str, Any]],
    burst_threshold_ms: Optional[float] = None
) -> Dict[str, Any]:
    """
    Extract comprehensive statistical features from a packet list.
    Handles microsecond-precision timestamps and safe division guards.
    Safely handles empty traces, single packets, and malformed entries.
    """
    cfg = load_classifier_config()
    if burst_threshold_ms is None:
        burst_threshold_ms = float(cfg.get("burst_ipt_threshold_ms", 20.0))
    else:
        burst_threshold_ms = float(burst_threshold_ms)

    # Empty packet list handling
    if not packets:
        burst_info = detect_burst_clusters([], burst_threshold_ms=burst_threshold_ms)
        return {
            "status": "empty",
            "empty_data": True,
            "packet_count": 0,
            "total_transmissions": 0,
            "total_bytes": 0,
            "duration": 0.0,
            "mean_size": 0.0,
            "median_size": 0.0,
            "min_size": 0,
            "max_size": 0,
            "std_size": 0.0,
            "size_histogram": {"0-150": 0, "151-300": 0, "301-600": 0, "601-1000": 0, "1001-1500": 0},
            "mean_ipt_ms": 0.0,
            "median_ipt_ms": 0.0,
            "std_ipt_ms": 0.0,
            "jitter_ms": 0.0,
            "burst_cluster_count": 0,
            "burst_count": 0,
            "transmissions_in_bursts": 0,
            "isolated_transmission_count": 0,
            "burst_cluster_ratio": 0.0,
            "isolated_transmission_ratio": 0.0,
            "burst_threshold_ms": burst_threshold_ms,
            "mean_burst_length": 0.0,
            "packets_per_sec": 0.0,
            "bytes_per_sec": 0.0,
            "forward_count": 0,
            "reverse_count": 0,
            "forward_reverse_ratio": 0.0,
            "protocol": "UNKNOWN",
            "ipt_series_sample": []
        }

    # Chronologically sort valid packet records by timestamp
    valid_packet_tuples: List[Tuple[float, Dict[str, Any]]] = []
    for p in packets:
        try:
            ts = float(p.get("timestamp", 0.0))
            valid_packet_tuples.append((ts, p))
        except (ValueError, TypeError):
            continue

    if not valid_packet_tuples:
        # Fallback if timestamps were unparseable
        valid_packet_tuples = [(0.0, p) for p in packets]

    valid_packet_tuples.sort(key=lambda item: item[0])
    sorted_packets = [item[1] for item in valid_packet_tuples]
    timestamps = [item[0] for item in valid_packet_tuples]

    packet_count = len(sorted_packets)
    sizes = [int(p.get("size", 0)) for p in sorted_packets]
    total_bytes = sum(sizes)

    # Durations and timestamps
    t_start = timestamps[0]
    t_end = timestamps[-1]
    duration = max(0.0001, t_end - t_start)

    # Size statistics
    mean_size = float(statistics.mean(sizes)) if sizes else 0.0
    median_size = float(statistics.median(sizes)) if sizes else 0.0
    min_size = int(min(sizes)) if sizes else 0
    max_size = int(max(sizes)) if sizes else 0
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
    if packet_count == 1:
        ipt_list_ms = [0.0]
    else:
        for i in range(1, packet_count):
            dt = timestamps[i] - timestamps[i - 1]
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

    # Accurate burst detection from chronological arrival timestamps
    burst_info = detect_burst_clusters(timestamps, burst_threshold_ms=burst_threshold_ms)

    # Rates and ratios
    packets_per_sec = float(packet_count / duration)
    bytes_per_sec = float(total_bytes / duration)

    fwd_count = sum(1 for p in sorted_packets if p.get("direction", "C->S") == "C->S")
    rev_count = sum(1 for p in sorted_packets if p.get("direction") == "S->C")
    fwd_rev_ratio = float(fwd_count / max(1, rev_count)) if rev_count > 0 else float(fwd_count)

    proto = sorted_packets[0].get("proto", "TCP").upper() if sorted_packets else "TCP"

    # Time series sample for UI plotting (max 120 points)
    sampled_ipt = ipt_list_ms[:120] if len(ipt_list_ms) > 120 else ipt_list_ms

    return {
        "packet_count": packet_count,
        "total_transmissions": burst_info["total_transmissions"],
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
        "burst_cluster_count": burst_info["burst_cluster_count"],
        "burst_count": burst_info["burst_cluster_count"],  # backward compatibility alias
        "transmissions_in_bursts": burst_info["transmissions_in_bursts"],
        "isolated_transmission_count": burst_info["isolated_transmission_count"],
        "burst_cluster_ratio": burst_info["burst_cluster_ratio"],
        "isolated_transmission_ratio": burst_info["isolated_transmission_ratio"],
        "burst_threshold_ms": burst_info["burst_threshold_ms"],
        "mean_burst_length": burst_info["mean_burst_length"],
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
            try:
                packets.append({
                    "seq": int(row.get("seq", 0)),
                    "timestamp": float(row.get("timestamp", 0.0)),
                    "proto": row.get("proto", "TCP"),
                    "direction": row.get("direction", "C->S"),
                    "size": int(row.get("size", 0)),
                    "crc32": row.get("crc32", ""),
                    "src_port": int(row.get("src_port", 0) or 0),
                    "dst_port": int(row.get("dst_port", 0) or 0),
                    "preview": row.get("preview", "")
                })
            except (ValueError, TypeError):
                continue
    return packets


def extract_and_save_features(exp_id: str, suffix: str = "") -> Dict[str, Any]:
    """Load trace CSV, extract features, and save to JSON."""
    file_name = f"{exp_id}{suffix}.csv"
    csv_path = TRAFFIC_DIR / file_name
    packets = load_packets_from_csv(csv_path)

    features = extract_features_from_packets(packets)
    features["experiment_id"] = exp_id
    features["trace_file"] = file_name

    FEATURES_DIR.mkdir(parents=True, exist_ok=True)
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
