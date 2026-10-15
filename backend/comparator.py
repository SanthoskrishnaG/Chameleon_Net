"""
Feature & Classification Comparator.
Calculates before vs after deltas, confidence shifts, deceptive mimicry success ("fooled" status),
similarity to target profile, and comprehensive network overhead metrics.
"""

from typing import Dict, Any, Optional
from backend.profiles import get_profile


def calculate_delta(v_before: float, v_after: float) -> Dict[str, Any]:
    """Calculate absolute difference and percentage shift safely."""
    delta = round(v_after - v_before, 2)
    if v_before != 0:
        pct = round(((v_after - v_before) / abs(v_before)) * 100.0, 1)
    else:
        if v_after > 0:
            pct = 100.0
        elif v_after < 0:
            pct = -100.0
        else:
            pct = 0.0
    return {
        "before": round(v_before, 2),
        "after": round(v_after, 2),
        "delta": delta,
        "percent_change": pct
    }


def compare_features_and_classification(
    before_features: Dict[str, Any],
    after_features: Dict[str, Any],
    before_classification: Dict[str, Any],
    after_classification: Dict[str, Any],
    target_profile_id: str,
    overhead: Optional[Dict[str, Any]] = None,
    content_integrity_verified: Optional[bool] = None
) -> Dict[str, Any]:
    """
    Produce a complete comparison between original and mimicry-transformed traffic.
    """
    target_prof = get_profile(target_profile_id)

    # Calculate throughput fallback if needed
    before_thru = before_features.get("throughput_kbps")
    if before_thru is None:
        bps_b = float(before_features.get("bytes_per_sec", 0.0))
        before_thru = round(bps_b * 8.0 / 1000.0, 2)

    after_thru = after_features.get("throughput_kbps")
    if after_thru is None:
        bps_a = float(after_features.get("bytes_per_sec", 0.0))
        after_thru = round(bps_a * 8.0 / 1000.0, 2)

    # Feature comparison metrics
    feature_metrics = [
        ("mean_size", "Mean Packet Size (B)"),
        ("median_size", "Median Packet Size (B)"),
        ("mean_ipt_ms", "Inter-Packet Arrival Time (ms)"),
        ("jitter_ms", "Jitter (ms)"),
        ("burst_count", "Burst Count"),
        ("burst_cluster_ratio", "Burst-Cluster Ratio"),
        ("mean_burst_length", "Mean Burst Length"),
        ("total_bytes", "Total Transmitted Bytes (B)"),
        ("duration", "Duration (s)"),
        ("packets_per_sec", "Packets / sec"),
        ("bytes_per_sec", "Bytes / sec"),
        ("throughput_kbps", "Throughput (kbps)")
    ]

    deltas: Dict[str, Dict[str, Any]] = {}
    for key, label in feature_metrics:
        if key == "throughput_kbps":
            v_b = float(before_thru)
            v_a = float(after_thru)
        elif key == "burst_count":
            v_b = float(before_features.get("burst_cluster_count", before_features.get("burst_count", 0.0)))
            v_a = float(after_features.get("burst_cluster_count", after_features.get("burst_count", 0.0)))
        else:
            v_b = float(before_features.get(key, 0.0))
            v_a = float(after_features.get(key, 0.0))
        d_res = calculate_delta(v_b, v_a)
        d_res["label"] = label
        deltas[key] = d_res

    cat_before = before_classification.get("detected_category", "unknown")
    cat_after = after_classification.get("detected_category", "unknown")
    conf_before = float(before_classification.get("confidence", 0.0))
    conf_after = float(after_classification.get("confidence", 0.0))

    # DPI profile scores comparison
    dpi_scores_before = before_classification.get("profile_scores", {})
    dpi_scores_after = after_classification.get("profile_scores", {})
    all_profiles = set(dpi_scores_before.keys()) | set(dpi_scores_after.keys())
    dpi_score_deltas: Dict[str, Dict[str, Any]] = {}
    for prof_key in all_profiles:
        s_b = float(dpi_scores_before.get(prof_key, 0.0))
        s_a = float(dpi_scores_after.get(prof_key, 0.0))
        dpi_score_deltas[prof_key] = calculate_delta(s_b, s_a)

    # Deception flags
    fooled_target = (cat_after == target_profile_id)
    category_diverted = (cat_after != cat_before)
    fooled = fooled_target or (category_diverted and conf_after >= 50.0)

    # Similarity to target profile (0-100)
    similarity_to_target = float(after_classification.get("profile_scores", {}).get(target_profile_id, 0.0))

    # Verdict summary
    if fooled_target:
        verdict = (
            f"DPI Classifier FOOLED! The transformed traffic successfully convinced the inspection engine "
            f"that it is '{target_prof['name']}' with {conf_after:.1f}% confidence."
        )
        status_banner = "CLASSIFIER FOOLED"
        banner_type = "success"
    else:
        if category_diverted:
            verdict = (
                f"CLASSIFIER NOT FOOLED into target '{target_prof['name']}'. Due to protocol constraints or mismatch, "
                f"classification diverted to '{after_classification.get('category_name')}' ({conf_after:.1f}% confidence)."
            )
        else:
            verdict = (
                f"Mimicry unsuccessful. The classifier remained locked onto '{before_classification.get('category_name')}'. "
                f"Heuristic rules resisted the perturbation."
            )
        status_banner = "CLASSIFIER NOT FOOLED"
        banner_type = "danger"

    # Fallback overhead calculation if not provided
    if not overhead:
        orig_bytes = float(before_features.get("total_bytes", 0))
        trans_bytes = float(after_features.get("total_bytes", 0))
        extra_bytes_pct = round(((trans_bytes - orig_bytes) / max(1.0, orig_bytes)) * 100.0, 1)

        orig_dur = float(before_features.get("duration", 0.001))
        trans_dur = float(after_features.get("duration", 0.001))
        added_delay_pct = round(((trans_dur - orig_dur) / max(0.001, orig_dur)) * 100.0, 1)

        orig_bps = float(before_features.get("bytes_per_sec", 1.0))
        trans_bps = float(after_features.get("bytes_per_sec", 1.0))
        throughput_chg_pct = round(((trans_bps - orig_bps) / max(1.0, orig_bps)) * 100.0, 1)

        overhead = {
            "original_bytes": int(orig_bytes),
            "transformed_bytes": int(trans_bytes),
            "extra_bytes_percent": extra_bytes_pct,
            "byte_overhead_pct": extra_bytes_pct,
            "original_duration_sec": orig_dur,
            "transformed_duration_sec": trans_dur,
            "added_delay_percent": added_delay_pct,
            "delay_overhead_pct": added_delay_pct,
            "original_throughput_bps": orig_bps,
            "transformed_throughput_bps": trans_bps,
            "throughput_change_percent": throughput_chg_pct
        }

    return {
        "target_profile": target_prof,
        "deltas": deltas,
        "metrics": deltas,
        "classification": {
            "before": {
                "category": cat_before,
                "name": before_classification.get("category_name", cat_before),
                "confidence": conf_before,
                "label": before_classification.get("label", "Low")
            },
            "after": {
                "category": cat_after,
                "name": after_classification.get("category_name", cat_after),
                "confidence": conf_after,
                "label": after_classification.get("label", "Low")
            },
            "confidence_shift": round(conf_after - conf_before, 1)
        },
        "dpi_score_deltas": dpi_score_deltas,
        "fooled": fooled,
        "fooled_target": fooled_target,
        "category_diverted": category_diverted,
        "similarity_to_target": similarity_to_target,
        "verdict": verdict,
        "status_banner": status_banner,
        "banner_type": banner_type,
        "overhead": overhead,
        "content_integrity_verified": content_integrity_verified
    }
