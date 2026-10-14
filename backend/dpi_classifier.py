"""
Explainable Rule-based DPI Classifier.
Evaluates traffic features against educational application profiles using 5 distinct rules:
1. Packet size distribution
2. Inter-packet timing (IPT)
3. Flow volume / packet count
4. Burstiness & Jitter
5. Transport protocol match
Completely ignores payload content and analyzes strictly observable statistical metrics.
"""

from typing import Dict, Any, List, Tuple
from backend.config import load_classifier_config
from backend.profiles import get_profiles


def score_range(val: float, r_min: float, r_max: float, tolerance: float) -> float:
    """
    Score a metric against an expected range [r_min, r_max].
    Full score 1.0 within bounds; linear decay to 0.0 outside bounds.
    """
    if r_min <= val <= r_max:
        return 1.0
    dist = (r_min - val) if val < r_min else (val - r_max)
    if tolerance <= 0:
        return 0.0
    score = 1.0 - (dist / tolerance)
    return max(0.0, min(1.0, score))


def classify_traffic(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute rule-based classification over extracted features.
    Returns detected category, confidence percentage, confidence label,
    per-profile scores, rule contribution breakdown, and narrative explanation.
    """
    config = load_classifier_config()
    weights = config.get("weights", {})
    thresholds = config.get("thresholds", {})
    tolerances = config.get("tolerances", {})

    w_size = float(weights.get("packet_size", 0.25))
    w_timing = float(weights.get("timing", 0.25))
    w_volume = float(weights.get("volume", 0.15))
    w_burst = float(weights.get("burst_jitter", 0.20))
    w_transport = float(weights.get("transport", 0.15))
    total_weight = w_size + w_timing + w_volume + w_burst + w_transport
    if total_weight <= 0:
        total_weight = 1.0

    t_size = float(tolerances.get("size_decay_bytes", 350.0))
    t_timing = float(tolerances.get("timing_decay_ms", 60.0))
    t_volume = float(tolerances.get("volume_decay_count", 80.0))
    t_jitter = float(tolerances.get("jitter_decay_ms", 25.0))
    t_burst = float(tolerances.get("burst_decay_len", 4.0))

    profiles = get_profiles()
    profile_scores: Dict[str, float] = {}
    profile_details: Dict[str, Dict[str, Any]] = {}

    mean_size = float(features.get("mean_size", 0.0))
    mean_ipt = float(features.get("mean_ipt_ms", 0.0))
    packet_count = float(features.get("packet_count", 0.0))
    jitter = float(features.get("jitter_ms", 0.0))
    mean_burst = float(features.get("mean_burst_length", 1.0))
    proto = str(features.get("protocol", "TCP")).upper()

    for pid, prof in profiles.items():
        s_size = score_range(mean_size, prof["size_range"][0], prof["size_range"][1], t_size)
        s_timing = score_range(mean_ipt, prof["ipt_range_ms"][0], prof["ipt_range_ms"][1], t_timing)
        s_vol = score_range(packet_count, prof["packet_count_range"][0], prof["packet_count_range"][1], t_volume)
        
        s_jit = score_range(jitter, prof["jitter_range_ms"][0], prof["jitter_range_ms"][1], t_jitter)
        s_bst = score_range(mean_burst, prof["burst_length_range"][0], prof["burst_length_range"][1], t_burst)
        s_burst_jit = (s_jit + s_bst) / 2.0

        s_trans = 1.0 if proto == prof["transport"].upper() else 0.0

        composite = (
            w_size * s_size +
            w_timing * s_timing +
            w_volume * s_vol +
            w_burst * s_burst_jit +
            w_transport * s_trans
        ) / total_weight

        profile_scores[pid] = round(composite * 100.0, 1)
        profile_details[pid] = {
            "name": prof["name"],
            "score": round(composite * 100.0, 1),
            "rules": {
                "packet_size": {"score": round(s_size, 3), "weight": w_size, "pass": s_size > 0.6},
                "timing": {"score": round(s_timing, 3), "weight": w_timing, "pass": s_timing > 0.6},
                "volume": {"score": round(s_vol, 3), "weight": w_volume, "pass": s_vol > 0.6},
                "burst_jitter": {"score": round(s_burst_jit, 3), "weight": w_burst, "pass": s_burst_jit > 0.6},
                "transport": {"score": round(s_trans, 3), "weight": w_transport, "pass": s_trans == 1.0}
            }
        }

    # Best profile match
    best_pid = max(profile_scores, key=lambda k: profile_scores[k])
    best_score = profile_scores[best_pid]
    best_prof = profiles[best_pid]

    high_thresh = float(thresholds.get("high_confidence", 80.0))
    mod_thresh = float(thresholds.get("moderate_confidence", 50.0))

    if best_score >= high_thresh:
        label = "High"
    elif best_score >= mod_thresh:
        label = "Moderate"
    else:
        label = "Low"

    # Generate explainable plain-English breakdown
    details = profile_details[best_pid]["rules"]
    passed_rules = [r for r, d in details.items() if d["pass"]]
    failed_rules = [r for r, d in details.items() if not d["pass"]]

    rule_names = {
        "packet_size": f"packet size ({mean_size:.0f} B)",
        "timing": f"inter-packet cadence ({mean_ipt:.1f} ms)",
        "volume": f"flow count ({packet_count:.0f} packets)",
        "burst_jitter": f"burst length ({mean_burst:.1f}) & jitter ({jitter:.1f} ms)",
        "transport": f"transport protocol ({proto})"
    }

    passed_desc = ", ".join([rule_names[r] for r in passed_rules]) if passed_rules else "no primary rules"
    failed_desc = ", ".join([rule_names[r] for r in failed_rules]) if failed_rules else "none"

    explanation = (
        f"Flow matched '{best_prof['name']}' with {label} confidence ({best_score:.1f}%). "
        f"Observable characteristics strongly aligned with {passed_desc}. "
    )
    if failed_rules:
        explanation += f"Deviations observed in {failed_desc}."
    else:
        explanation += "All 5 inspection heuristic rules satisfied target profile bounds."

    # Rule contribution weights for charts
    rule_contributions = {
        "Packet Size": round((w_size * details["packet_size"]["score"] / total_weight) * 100, 1),
        "Inter-Packet Timing": round((w_timing * details["timing"]["score"] / total_weight) * 100, 1),
        "Flow Volume": round((w_volume * details["volume"]["score"] / total_weight) * 100, 1),
        "Burst & Jitter": round((w_burst * details["burst_jitter"]["score"] / total_weight) * 100, 1),
        "Transport Match": round((w_transport * details["transport"]["score"] / total_weight) * 100, 1),
    }

    return {
        "detected_category": best_pid,
        "category_name": best_prof["name"],
        "confidence": best_score,
        "label": label,
        "explanation": explanation,
        "profile_scores": profile_scores,
        "profile_details": profile_details,
        "rule_contributions": rule_contributions
    }
