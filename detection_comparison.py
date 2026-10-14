"""
Detection Comparison Module
Compares original vs. transformed traffic flows across classification labels,
DPI confidence, packet statistics, entropy drift, and evasion efficacy metrics.
"""

from typing import Dict, Any, List
from traffic_generator import FlowRecord
from dpi_classifier import DPIClassifier

class DetectionComparison:
    """
    Evaluates the efficacy of Protocol Mimicry transformations against DPI systems.
    Computes evasion scores, feature drift, and structural metrics.
    """

    def __init__(self, classifier: DPIClassifier = None):
        self.classifier = classifier or DPIClassifier()

    def compare(
        self,
        original_flow: FlowRecord,
        transformed_flow: FlowRecord,
        target_mimicry_type: str
    ) -> Dict[str, Any]:
        """
        Runs DPI classification on both flows and computes comparative metrics.
        """
        orig_result = self.classifier.classify_flow(original_flow)
        trans_result = self.classifier.classify_flow(transformed_flow)

        orig_features = orig_result["features"]
        trans_features = trans_result["features"]

        # Expected target protocol mapping
        target_map = {
            "tls_https": "HTTPS/TLS",
            "dns_query": "DNS",
            "http_api": "HTTP/Web"
        }
        expected_class = target_map.get(target_mimicry_type, "HTTPS/TLS")

        # Determine evasion outcome
        trans_pred = trans_result["predicted_protocol"]
        orig_pred = orig_result["predicted_protocol"]

        if trans_pred == expected_class:
            evasion_status = "SUCCESSFUL_EVASION"
            status_badge = "Success: Mimicked Target Protocol"
            evasion_description = (
                f"The DPI system successfully misclassified the arbitrary traffic as {expected_class} "
                f"with {trans_result['confidence_percentage']} confidence."
            )
        elif trans_pred != orig_pred and trans_pred != "Unknown / Suspicious":
            evasion_status = "PARTIAL_EVASION"
            status_badge = "Partial: Diverted from Original Signature"
            evasion_description = (
                f"The traffic evaded the original classification ({orig_pred}) but was classified as {trans_pred}."
            )
        else:
            evasion_status = "DETECTED_OR_FLAGGED"
            status_badge = "Detected / Flagged"
            evasion_description = (
                f"The DPI system either retained detection of {orig_pred} or marked it as suspicious."
            )

        # Feature Drift calculations
        orig_bytes = orig_features["total_bytes"]
        trans_bytes = trans_features["total_bytes"]
        overhead_pct = round(((trans_bytes - orig_bytes) / orig_bytes * 100), 2) if orig_bytes > 0 else 0.0

        entropy_drift = round(trans_features["mean_entropy"] - orig_features["mean_entropy"], 3)
        mean_size_drift = round(trans_features["mean_packet_size"] - orig_features["mean_packet_size"], 2)
        duration_drift = round(trans_features["flow_duration_sec"] - orig_features["flow_duration_sec"], 4)

        # Generate educational analytical takeaways
        takeaways = self._generate_analysis_takeaways(
            orig_result, trans_result, expected_class, overhead_pct, entropy_drift
        )

        return {
            "evasion_status": evasion_status,
            "status_badge": status_badge,
            "evasion_description": evasion_description,
            "target_protocol_expected": expected_class,
            "original_analysis": {
                "predicted_protocol": orig_pred,
                "confidence": orig_result["confidence"],
                "confidence_percentage": orig_result["confidence_percentage"],
                "scores": orig_result["scores"],
                "matched_rules": orig_result["matched_rules"],
                "features": orig_features
            },
            "transformed_analysis": {
                "predicted_protocol": trans_pred,
                "confidence": trans_result["confidence"],
                "confidence_percentage": trans_result["confidence_percentage"],
                "scores": trans_result["scores"],
                "matched_rules": trans_result["matched_rules"],
                "features": trans_features
            },
            "drift_metrics": {
                "overhead_percentage": overhead_pct,
                "entropy_drift": entropy_drift,
                "mean_size_drift": mean_size_drift,
                "duration_drift": duration_drift,
                "packet_count_original": orig_features["packet_count"],
                "packet_count_transformed": trans_features["packet_count"]
            },
            "analysis_takeaways": takeaways
        }

    def _generate_analysis_takeaways(
        self,
        orig_res: Dict[str, Any],
        trans_res: Dict[str, Any],
        expected_class: str,
        overhead_pct: float,
        entropy_drift: float
    ) -> List[str]:
        takeaways = []
        orig_feat = orig_res["features"]
        trans_feat = trans_res["features"]

        if trans_res["predicted_protocol"] == expected_class:
            takeaways.append(
                f"Protocol Mimicry Engine successfully matched both L7 signatures and statistical properties of {expected_class}."
            )
        else:
            takeaways.append(
                f"DPI inspection rules identified residual anomalies preventing complete classification as {expected_class}."
            )

        if entropy_drift > 2.0:
            takeaways.append(
                f"Entropy increased significantly (+{entropy_drift:.2f} bits/byte), successfully blinding signature-based regex engines from reading cleartext payloads."
            )
        elif entropy_drift < -1.0:
            takeaways.append(
                f"Entropy decreased ({entropy_drift:.2f} bits/byte), fitting target plaintext/structured protocols."
            )

        if overhead_pct > 25.0:
            takeaways.append(
                f"Traffic shaping and padding introduced an observable bandwidth overhead of {overhead_pct}%, representing a practical trade-off for evasion."
            )

        takeaways.append(
            f"Defense Insight: DPI firewalls relying exclusively on port numbers and initial magic bytes are vulnerable to mimicry; robust defenses require bidirectional stateful flow profiling and side-channel timing analysis."
        )

        return takeaways
