"""
Educational Traffic Profiles for DPI Classification & Protocol Mimicry.
Defines statistical fingerprints for 5 network application types.
"""

from typing import Dict, Any, List

PROFILES: Dict[str, Dict[str, Any]] = {
    "web_browsing": {
        "id": "web_browsing",
        "name": "HTTP-like Web Browsing",
        "transport": "TCP",
        "description": "Bursty HTTP/HTTPS document & asset requests over TCP, featuring irregular think-time intervals.",
        "size_range": [200, 1400],
        "target_size": 750,
        "ipt_range_ms": [30.0, 300.0],
        "target_ipt_ms": 120.0,
        "jitter_range_ms": [15.0, 120.0],
        "target_jitter_ms": 45.0,
        "packet_count_range": [20, 500],
        "burst_length_range": [2.0, 8.0],
        "target_burst_length": 4.0,
        "color": "#2563EB",
        "icon": "globe"
    },
    "dns_lookup": {
        "id": "dns_lookup",
        "name": "DNS-like Query Flow",
        "transport": "UDP",
        "description": "Short, lightweight UDP datagram exchanges with compact packet sizes and brief total flow duration.",
        "size_range": [60, 200],
        "target_size": 95,
        "ipt_range_ms": [10.0, 100.0],
        "target_ipt_ms": 40.0,
        "jitter_range_ms": [5.0, 50.0],
        "target_jitter_ms": 15.0,
        "packet_count_range": [2, 25],
        "burst_length_range": [1.0, 2.0],
        "target_burst_length": 1.0,
        "color": "#0D9488",
        "icon": "server"
    },
    "voip_call": {
        "id": "voip_call",
        "name": "VoIP-like Audio Stream",
        "transport": "UDP",
        "description": "Isochronous real-time voice packets (e.g., G.711 / Opus) transmitted at strict 20ms intervals with minimal jitter.",
        "size_range": [100, 220],
        "target_size": 160,
        "ipt_range_ms": [18.0, 22.0],
        "target_ipt_ms": 20.0,
        "jitter_range_ms": [0.5, 5.0],
        "target_jitter_ms": 2.0,
        "packet_count_range": [30, 1000],
        "burst_length_range": [1.0, 1.5],
        "target_burst_length": 1.0,
        "color": "#16A34A",
        "icon": "phone"
    },
    "video_stream": {
        "id": "video_stream",
        "name": "Video-Streaming-like",
        "transport": "TCP",
        "description": "High-throughput saturated segments approaching standard MTU with steady, rapid inter-arrival timing.",
        "size_range": [1000, 1460],
        "target_size": 1300,
        "ipt_range_ms": [5.0, 15.0],
        "target_ipt_ms": 10.0,
        "jitter_range_ms": [1.0, 8.0],
        "target_jitter_ms": 3.0,
        "packet_count_range": [80, 1000],
        "burst_length_range": [4.0, 15.0],
        "target_burst_length": 8.0,
        "color": "#D97706",
        "icon": "play-circle"
    },
    "bulk_transfer": {
        "id": "bulk_transfer",
        "name": "Bulk-Transfer / TCP-like Baseline",
        "transport": "TCP",
        "description": "Moderate packet sizes sent at uniform, paced intervals representing regular automated file sync or telemetry.",
        "size_range": [400, 700],
        "target_size": 550,
        "ipt_range_ms": [80.0, 120.0],
        "target_ipt_ms": 100.0,
        "jitter_range_ms": [10.0, 40.0],
        "target_jitter_ms": 20.0,
        "packet_count_range": [50, 250],
        "burst_length_range": [1.0, 4.0],
        "target_burst_length": 2.0,
        "color": "#64748B",
        "icon": "database"
    }
}


def get_profiles() -> Dict[str, Dict[str, Any]]:
    """Return dictionary of all available profiles."""
    return PROFILES.copy()


def get_profile_list() -> List[Dict[str, Any]]:
    """Return list of profile objects for frontend consumption."""
    return list(PROFILES.values())


def get_profile(profile_id: str) -> Dict[str, Any]:
    """Retrieve profile by ID, defaulting to bulk_transfer if unknown."""
    return PROFILES.get(profile_id, PROFILES["bulk_transfer"]).copy()
