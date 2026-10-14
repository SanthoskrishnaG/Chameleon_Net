"""
Traffic Feature Extraction Module
Extracts statistical, directional, timing, and entropy-based features from network flows.
Used by DPI classifiers to identify protocols and fingerprint traffic behavior.
"""

import math
from typing import List, Dict, Any
from traffic_generator import FlowRecord, PacketRecord

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def calculate_ascii_ratio(data: bytes) -> float:
    """Calculates the proportion of printable ASCII characters."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return round(printable / len(data), 4)

class FeatureExtractor:
    """
    Extracts comprehensive network flow and packet features:
    - Packet size statistics (min, max, mean, stddev, distribution)
    - Inter-arrival timing (IAT) statistics
    - Directional flow balance (C->S vs S->C)
    - Shannon entropy profile
    - Payload inspection signatures
    """

    @staticmethod
    def extract_features(flow: FlowRecord) -> Dict[str, Any]:
        packets = flow.packets
        if not packets:
            return {
                "flow_id": flow.flow_id,
                "traffic_type": flow.traffic_type,
                "transport_protocol": flow.transport_protocol,
                "packet_count": 0,
                "total_bytes": 0,
                "flow_duration_sec": 0.0,
                "mean_packet_size": 0.0,
                "std_packet_size": 0.0,
                "min_packet_size": 0,
                "max_packet_size": 0,
                "mean_iat_ms": 0.0,
                "std_iat_ms": 0.0,
                "mean_entropy": 0.0,
                "ascii_ratio": 0.0,
                "cs_ratio": 0.0,
                "bytes_per_sec": 0.0,
                "size_distribution": {},
                "packet_sizes": [],
                "iat_list_ms": [],
                "entropy_list": []
            }

        # Packet sizes
        sizes = [p.size for p in packets]
        total_bytes = sum(sizes)
        min_sz = min(sizes)
        max_sz = max(sizes)
        mean_sz = total_bytes / len(sizes)
        variance_sz = sum((s - mean_sz) ** 2 for s in sizes) / len(sizes)
        std_sz = math.sqrt(variance_sz)

        # Timings & Inter-Arrival Times (IAT)
        timestamps = [p.timestamp for p in packets]
        flow_duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.001
        if flow_duration <= 0:
            flow_duration = 0.001

        iats = []
        for i in range(1, len(timestamps)):
            gap = max(0.0, timestamps[i] - timestamps[i - 1]) * 1000.0  # in ms
            iats.append(gap)

        mean_iat = sum(iats) / len(iats) if iats else 0.0
        var_iat = sum((gap - mean_iat) ** 2 for gap in iats) / len(iats) if iats else 0.0
        std_iat = math.sqrt(var_iat)

        # Directional breakdown
        cs_count = sum(1 for p in packets if p.direction == "C->S")
        sc_count = sum(1 for p in packets if p.direction == "S->C")
        cs_ratio = round(cs_count / len(packets), 3)

        # Shannon Entropy & ASCII ratio
        entropies = [calculate_shannon_entropy(p.payload) for p in packets]
        mean_entropy = round(sum(entropies) / len(entropies), 3) if entropies else 0.0

        all_payload = b"".join(p.payload for p in packets)
        ascii_ratio = calculate_ascii_ratio(all_payload)

        # Histogram binned sizes: Small (<128), Med (128-512), Large (512-1200), MTU (>1200)
        size_bins = {
            "small_under_128": sum(1 for s in sizes if s < 128),
            "med_128_512": sum(1 for s in sizes if 128 <= s < 512),
            "large_512_1200": sum(1 for s in sizes if 512 <= s < 1200),
            "mtu_over_1200": sum(1 for s in sizes if s >= 1200)
        }

        bytes_per_sec = round(total_bytes / flow_duration, 2)

        return {
            "flow_id": flow.flow_id,
            "traffic_type": flow.traffic_type,
            "transport_protocol": flow.transport_protocol,
            "packet_count": len(packets),
            "total_bytes": total_bytes,
            "flow_duration_sec": round(flow_duration, 4),
            "mean_packet_size": round(mean_sz, 2),
            "std_packet_size": round(std_sz, 2),
            "min_packet_size": min_sz,
            "max_packet_size": max_sz,
            "mean_iat_ms": round(mean_iat, 2),
            "std_iat_ms": round(std_iat, 2),
            "mean_entropy": mean_entropy,
            "ascii_ratio": ascii_ratio,
            "cs_ratio": cs_ratio,
            "bytes_per_sec": bytes_per_sec,
            "size_distribution": size_bins,
            "packet_sizes": sizes,
            "iat_list_ms": [round(x, 2) for x in iats],
            "entropy_list": entropies
        }
