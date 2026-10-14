"""
Configuration and Directory Management for Protocol Mimicry Engine.
Enforces loopback-only safety constraints and manages persistent storage locations.
Supports production environment overrides for cloud hosting (Render, Railway, VPS).
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, Any, List

# --------------------------------------------------------------------------
# Base Paths
# --------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

# Storage and configuration directories (allow environment variable overrides)
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR / "data")).resolve()
TRAFFIC_DIR = Path(os.environ.get("TRAFFIC_DIR", DATA_DIR / "traffic")).resolve()
FEATURES_DIR = Path(os.environ.get("FEATURES_DIR", DATA_DIR / "features")).resolve()
EXPERIMENTS_DIR = Path(os.environ.get("EXPERIMENTS_DIR", DATA_DIR / "experiments")).resolve()
RESULTS_DIR = Path(os.environ.get("RESULTS_DIR", BASE_DIR / "results")).resolve()
CONFIG_DIR = Path(os.environ.get("CONFIG_DIR", BASE_DIR / "config")).resolve()
WEB_DIR = Path(os.environ.get("WEB_DIR", BASE_DIR / "web")).resolve()

SQLITE_DB_PATH = Path(os.environ.get("SQLITE_DB_PATH", DATA_DIR / "experiments.db")).resolve()
CLASSIFIER_CONFIG_PATH = CONFIG_DIR / "classifier.json"

# --------------------------------------------------------------------------
# Networking and Guard Settings
# --------------------------------------------------------------------------
LOOPBACK_HOST = "127.0.0.1"
LOOPBACK_ALLOWED = {"127.0.0.1", "localhost", "::1", "testclient"}

# Deployment mode detection
IS_DEPLOYMENT = (
    os.environ.get("RENDER", "").lower() in ("true", "1") or
    os.environ.get("DEPLOYMENT_MODE", "").lower() in ("true", "1") or
    bool(os.environ.get("ALLOWED_ORIGINS"))
)

# STRICT_LOCAL_IP_GUARD:
# When True, rejects HTTP requests coming from non-loopback IP addresses.
# Defaults to True in local standalone mode, and False in cloud deployment mode.
_env_guard = os.environ.get("STRICT_LOCAL_IP_GUARD")
if _env_guard is not None:
    STRICT_LOCAL_IP_GUARD = _env_guard.lower() in ("true", "1")
else:
    STRICT_LOCAL_IP_GUARD = not IS_DEPLOYMENT

# Server host & port
PORT = int(os.environ.get("PORT", 5000))
HOST = os.environ.get("HOST", "0.0.0.0" if (IS_DEPLOYMENT or os.environ.get("PORT")) else "127.0.0.1")

# Authentication / Access Control
# If set, mutating operations (traffic gen, mimicry apply, delete, settings) require this API key.
API_KEY = os.environ.get("API_KEY", "").strip()

# Bounding limits for experiment execution
MAX_ACTIVE_EXPERIMENTS = int(os.environ.get("MAX_ACTIVE_EXPERIMENTS", 3))
MAX_PACKET_COUNT = int(os.environ.get("MAX_PACKET_COUNT", 1000))
MAX_PACKET_SIZE = int(os.environ.get("MAX_PACKET_SIZE", 1500))
MAX_TEXT_LENGTH = int(os.environ.get("MAX_TEXT_LENGTH", 5000))

# --------------------------------------------------------------------------
# CORS Configuration
# --------------------------------------------------------------------------
DEFAULT_LOCAL_ORIGINS = [
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173"
]

ALLOW_VERCEL_PREVIEWS = os.environ.get("ALLOW_VERCEL_PREVIEWS", "true").lower() in ("true", "1")
VERCEL_PREVIEW_REGEX = re.compile(r"^https://[a-zA-Z0-9_-]+\.vercel\.app$")


def get_allowed_origins() -> List[str]:
    """Compile list of authorized frontend origins."""
    env_origins = os.environ.get("ALLOWED_ORIGINS", "").strip()
    origins = list(DEFAULT_LOCAL_ORIGINS)
    if env_origins:
        for orig in env_origins.split(","):
            cleaned = orig.strip().rstrip("/")
            if cleaned and cleaned not in origins:
                origins.append(cleaned)
    return origins


def is_origin_allowed(origin: str) -> bool:
    """Check if an incoming Origin header is permitted under CORS policy."""
    if not origin:
        return True
    clean_origin = origin.rstrip("/")
    allowed = get_allowed_origins()
    if "*" in allowed or clean_origin in allowed:
        return True
    if ALLOW_VERCEL_PREVIEWS and VERCEL_PREVIEW_REGEX.match(clean_origin):
        return True
    return False


# --------------------------------------------------------------------------
# Classifier Configuration Defaults
# --------------------------------------------------------------------------
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
    """Ensure all required data directories exist."""
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
