"""
Deep Packet Inspection (DPI) & Traffic Classifier Module
Implements multi-stage traffic classification:
1. Layer 7 Signature & Magic-Byte Matching (Snort/Suricata style rules)
2. Statistical Heuristics (Shannon Entropy, packet size distributions)
3. Timing & Flow Profile Matching
4. Confidence Scoring and Explainability
"""

import re
from typing import Dict, Any, List, Tuple
from traffic_generator import FlowRecord, PacketRecord
from feature_extractor import FeatureExtractor

class DPIClassifier:
    """
    Simulates enterprise firewall and DPI engine behavior.
    Classifies raw network flows and provides explainable rule matches.
    """

    KNOWN_CLASSES = [
        "HTTPS/TLS",
        "DNS",
        "HTTP/Web",
        "Plaintext Remote Shell",
        "Bulk Data Transfer",
        "IoT / Periodic Beacon",
        "Unknown / Suspicious"
    ]

    SHELL_PATTERNS = [
        re.compile(b"(whoami|uname|passwd|netstat|ps aux|cat /|ls -|curl|wget)"),
        re.compile(b"(root@|admin@|bash|sh: )"),
        re.compile(b"(OK\n|ACK:)")
    ]

    HTTP_PATTERNS = [
        re.compile(b"^(GET|POST|PUT|DELETE|HEAD|OPTIONS) "),
        re.compile(b"HTTP/1\\.[01]"),
        re.compile(b"Host: "),
        re.compile(b"Content-Type: ")
    ]

    def __init__(self):
        pass

    def classify_flow(self, flow: FlowRecord) -> Dict[str, Any]:
        """
        Runs comprehensive DPI and statistical analysis on the network flow.
        """
        features = FeatureExtractor.extract_features(flow)
        packets = flow.packets

        if not packets:
            return {
                "predicted_protocol": "Unknown / Suspicious",
                "confidence": 0.0,
                "confidence_percentage": "0.0%",
                "scores": {c: 0.0 for c in self.KNOWN_CLASSES},
                "matched_rules": ["Empty flow - no packets to inspect"],
                "inspection_summary": "No packet data available",
                "features": features
            }

        scores = {c: 0.05 for c in self.KNOWN_CLASSES}
        matched_rules: List[str] = []

        # --- STAGE 1: L7 Signature & Magic Byte Inspection ---
        first_payload = packets[0].payload if packets else b""
        all_payloads = b"".join(p.payload[:128] for p in packets)

        # TLS Signatures
        tls_matched = False
        for p in packets:
            data = p.payload
            # TLS Record header: byte 0 in [0x16 (Handshake), 0x17 (AppData)], byte 1 is 0x03
            if len(data) >= 5:
                if (data[0] == 0x16 or data[0] == 0x17) and data[1] == 0x03:
                    tls_matched = True
                    break

        if tls_matched:
            scores["HTTPS/TLS"] += 0.55
            matched_rules.append("DPI-SIG-101: TLS Record Layer Frame detected (0x16/0x17, TLS 1.x version)")

        # DNS Signatures
        dns_matched = False
        if flow.transport_protocol == "UDP":
            for p in packets:
                data = p.payload
                # Check for standard DNS flags and query format
                if len(data) >= 12:
                    flags = int.from_bytes(data[2:4], "big")
                    qdcount = int.from_bytes(data[4:6], "big")
                    if (flags in (0x0100, 0x8180, 0x0000)) and qdcount >= 1:
                        dns_matched = True
                        break

        if dns_matched:
            scores["DNS"] += 0.60
            matched_rules.append("DPI-SIG-201: RFC 1035 DNS Header & Query structure verified on UDP")

        # HTTP Signatures
        http_matches = 0
        for pattern in self.HTTP_PATTERNS:
            if pattern.search(all_payloads):
                http_matches += 1

        if http_matches >= 2:
            scores["HTTP/Web"] += 0.55
            matched_rules.append(f"DPI-SIG-301: HTTP/1.1 verb and header structure identified ({http_matches} tokens)")

        # Plaintext Shell Signatures
        shell_matches = 0
        for pattern in self.SHELL_PATTERNS:
            if pattern.search(all_payloads):
                shell_matches += 1

        if shell_matches >= 1 and not tls_matched:
            scores["Plaintext Remote Shell"] += 0.50
            matched_rules.append(f"DPI-SIG-401: Plaintext terminal commands/responses matched in cleartext ({shell_matches} signatures)")

        # --- STAGE 2: Statistical & Entropy Inspection ---
        mean_entropy = features["mean_entropy"]
        mean_sz = features["mean_packet_size"]
        mean_iat = features["mean_iat_ms"]
        std_iat = features["std_iat_ms"]
        ascii_ratio = features["ascii_ratio"]

        # High Entropy (Ciphertext / Encrypted Tunnel)
        if mean_entropy >= 7.2:
            scores["HTTPS/TLS"] += 0.25
            matched_rules.append(f"DPI-STAT-102: High Shannon entropy ({mean_entropy:.2f} bits/byte) indicative of modern cryptographic ciphertexts")
        elif mean_entropy < 4.5 and ascii_ratio > 0.6:
            scores["Plaintext Remote Shell"] += 0.20
            scores["HTTP/Web"] += 0.15
            matched_rules.append(f"DPI-STAT-202: Low entropy ({mean_entropy:.2f} bits/byte) & high ASCII ratio ({ascii_ratio*100:.1f}%) indicative of plaintext protocols")

        # Packet Size Distribution Characteristics
        if mean_sz > 1000 and features["size_distribution"]["mtu_over_1200"] >= 2:
            scores["Bulk Data Transfer"] += 0.40
            matched_rules.append("DPI-STAT-301: Heavy MTU packet size clustering (>1200B) typical of bulk file transfer")
        elif mean_sz < 120 and flow.transport_protocol == "TCP":
            scores["Plaintext Remote Shell"] += 0.20
            matched_rules.append("DPI-STAT-302: Small mean packet size (<120B) consistent with interactive character echoing")
        elif mean_sz < 200 and flow.transport_protocol == "UDP":
            scores["DNS"] += 0.20
            matched_rules.append("DPI-STAT-303: Lightweight datagram size profile (<200B) aligning with DNS queries")

        # Periodic Timing Regularity (Beacon / Heartbeat)
        if len(packets) >= 4 and std_iat < 25.0 and mean_iat > 50.0:
            scores["IoT / Periodic Beacon"] += 0.45
            matched_rules.append(f"DPI-TIME-401: Highly periodic packet cadence (mean IAT={mean_iat:.1f}ms, std={std_iat:.1f}ms) detected")

        # Normalize probability scores with Softmax
        total_score = sum(scores.values())
        normalized_scores = {k: round(v / total_score, 4) for k, v in scores.items()}

        # Identify predicted class and top confidence
        predicted_protocol = max(normalized_scores, key=normalized_scores.get)
        confidence = normalized_scores[predicted_protocol]

        # Generate human-readable inspection summary
        summary = (
            f"Classified as '{predicted_protocol}' with {confidence*100:.1f}% confidence. "
            f"{len(matched_rules)} detection heuristic(s) triggered."
        )

        return {
            "predicted_protocol": predicted_protocol,
            "confidence": confidence,
            "confidence_percentage": f"{confidence * 100:.1f}%",
            "scores": normalized_scores,
            "matched_rules": matched_rules,
            "inspection_summary": summary,
            "features": features
        }
