"""
Configuration and Directory Management for Protocol Mimicry Engine.
Enforces loopback-only safety constraints and manages persistent storage locations.
"""

import json
from pathlib import Path
from typing import Dict, Any

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
TRAFFIC_DIR = DATA_DIR / "traffic"
FEATURES_DIR = DATA_DIR / "features"
EXPERIMENTS_DIR = DATA_DIR / "experiments"
RESULTS_DIR = BASE_DIR / "results"
CONFIG_DIR = BASE_DIR / "config"
WEB_DIR = BASE_DIR / "web"

CLASSIFIER_CONFIG_PATH = CONFIG_DIR / "classifier.json"
LOOPBACK_HOST = "127.0.0.1"
LOOPBACK_ALLOWED = {"127.0.0.1", "localhost", "::1", "testclient"}

DEFAULT_CLASSIFIER_CONFIG: Dict[str, Any] = {
    "weights": {
        "packet_size": 0.25,
        "timing": 0.25,
        "volume": 0.15,
        "burst_jitter": 0.20,
        "transport": 0.15
    },
    "thresholds": {
        "high_confidence": 80.0,
        "moderate_confidence": 50.0
    },
    "tolerances": {
        "size_decay_bytes": 350.0,
        "timing_decay_ms": 60.0,
        "volume_decay_count": 80.0,
        "jitter_decay_ms": 25.0,
        "burst_decay_len": 4.0
    },
    "burst_ipt_threshold_ms": 20.0
}


def ensure_directories():
    """Ensure all required directories exist."""
    for d in [DATA_DIR, TRAFFIC_DIR, FEATURES_DIR, EXPERIMENTS_DIR, RESULTS_DIR, CONFIG_DIR, WEB_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def is_loopback(host: str) -> bool:
    """Strictly verify that the host is a localhost loopback address."""
    if not host:
        return False
    host_clean = host.strip().lower()
    return host_clean in LOOPBACK_ALLOWED


def load_classifier_config() -> Dict[str, Any]:
    """Load classifier weights and thresholds, falling back to defaults."""
    ensure_directories()
    if CLASSIFIER_CONFIG_PATH.exists():
        try:
            with open(CLASSIFIER_CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data
        except Exception:
            pass
    save_classifier_config(DEFAULT_CLASSIFIER_CONFIG)
    return DEFAULT_CLASSIFIER_CONFIG.copy()


def save_classifier_config(config: Dict[str, Any]) -> None:
    """Persist updated classifier weights and thresholds."""
    ensure_directories()
    with open(CLASSIFIER_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def reset_classifier_config() -> Dict[str, Any]:
    """Reset configuration to standard factory defaults."""
    save_classifier_config(DEFAULT_CLASSIFIER_CONFIG)
    return DEFAULT_CLASSIFIER_CONFIG.copy()


ensure_directories()
