"""
Feature & Classification Comparator.
Calculates before vs after deltas, confidence shifts, deceptive mimicry success ("fooled" status),
similarity to target profile, and comprehensive network overhead metrics.
"""

from typing import Dict, Any, Optional
from backend.profiles import get_profile


def calculate_delta(v_before: float, v_after: float) -> Dict[str, Any]:
    """Calculate absolute difference and percentage shift."""
    delta = round(v_after - v_before, 2)
    if v_before != 0:
        pct = round(((v_after - v_before) / abs(v_before)) * 100.0, 1)
    else:
        pct = 100.0 if v_after > 0 else 0.0
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
    overhead: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Produce a complete comparison between original and mimicry-transformed traffic.
    """
    target_prof = get_profile(target_profile_id)

    # Feature comparison metrics
    feature_metrics = [
        ("mean_size", "Mean Packet Size (B)"),
        ("median_size", "Median Packet Size (B)"),
        ("mean_ipt_ms", "Inter-Packet Time (ms)"),
        ("jitter_ms", "Jitter (ms)"),
        ("burst_count", "Burst Count"),
        ("mean_burst_length", "Mean Burst Length"),
        ("total_bytes", "Total Volume (B)"),
        ("duration", "Duration (s)"),
        ("packets_per_sec", "Packets / sec"),
        ("bytes_per_sec", "Bytes / sec")
    ]

    deltas: Dict[str, Dict[str, Any]] = {}
    for key, label in feature_metrics:
        v_b = float(before_features.get(key, 0.0))
        v_a = float(after_features.get(key, 0.0))
        d_res = calculate_delta(v_b, v_a)
        d_res["label"] = label
        deltas[key] = d_res

    cat_before = before_classification.get("detected_category", "unknown")
    cat_after = after_classification.get("detected_category", "unknown")
    conf_before = float(before_classification.get("confidence", 0.0))
    conf_after = float(after_classification.get("confidence", 0.0))

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

    return {
        "target_profile": target_prof,
        "deltas": deltas,
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
        "fooled": fooled,
        "fooled_target": fooled_target,
        "category_diverted": category_diverted,
        "similarity_to_target": similarity_to_target,
        "verdict": verdict,
        "status_banner": status_banner,
        "banner_type": banner_type,
        "overhead": overhead or {}
    }
