import json
import os
from typing import List, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", "") or os.path.join(BASE_DIR, "data")
MODEL_DIR = os.environ.get("MODEL_DIR", "") or os.path.join(BASE_DIR, "models")

# CNN Model Configuration
CNN_CONFIG = {
    "epochs": int(os.environ.get("CNN_EPOCHS") or 0),
    "batch_size": int(os.environ.get("CNN_BATCH_SIZE") or 0),
    "learning_rate": float(os.environ.get("CNN_LEARNING_RATE") or 0.0),
    "validation_split": float(os.environ.get("CNN_VALIDATION_SPLIT") or 0.0),
    "dropout_rate": float(os.environ.get("CNN_DROPOUT_RATE") or 0.0),
    "filters": [int(x) for x in os.environ.get("CNN_FILTERS", "").split(",") if x],
    "kernel_size": int(os.environ.get("CNN_KERNEL_SIZE") or 0),
    "dense_units": [int(x) for x in os.environ.get("CNN_DENSE_UNITS", "").split(",") if x],
}

# NSL-KDD Columns
NSL_KDD_COLUMNS = os.environ.get("NSL_KDD_COLUMNS", "").split(",")

# Attack type mapping (format: attack_type:category)
_attack_map_str = os.environ.get("ATTACK_MAP", "")
ATTACK_MAP = {}
if _attack_map_str:
    ATTACK_MAP = {k.strip(): v.strip() for k, v in (item.split(":") for item in _attack_map_str.split(","))}

FLASK_HOST = os.environ.get("FLASK_HOST", "")
FLASK_PORT = int(os.environ.get("FLASK_PORT") or 0)

# URL Analyzer Configuration - All values must be set via environment variables
URL_ANALYZER_CONFIG = {
    # Timeouts
    "request_timeout": int(os.environ.get("URL_REQUEST_TIMEOUT") or 0),
    "external_api_timeout": int(os.environ.get("URL_EXTERNAL_API_TIMEOUT") or 0),
    "deep_scan_timeout": int(os.environ.get("URL_DEEP_SCAN_TIMEOUT") or 0),
    "subpage_crawl_timeout": int(os.environ.get("URL_SUBPAGE_CRAWL_TIMEOUT") or 0),
    "ssl_timeout": int(os.environ.get("URL_SSL_TIMEOUT") or 0),
    
    # Redirect & Content limits
    "max_redirects": int(os.environ.get("URL_MAX_REDIRECTS") or 0),
    "max_content_length": int(os.environ.get("URL_MAX_CONTENT_LENGTH") or 0),
    "content_scan_limit": int(os.environ.get("URL_CONTENT_SCAN_LIMIT") or 0),
    "deep_scan_max_bytes": int(os.environ.get("URL_DEEP_SCAN_MAX_BYTES") or 0),
    "subpage_crawl_max_bytes": int(os.environ.get("URL_SUBPAGE_CRAWL_MAX_BYTES") or 0),
    "subpage_crawl_limit": int(os.environ.get("URL_SUBPAGE_CRAWL_LIMIT") or 0),
    
    # Analysis thresholds
    "long_domain_length": int(os.environ.get("URL_LONG_DOMAIN_LENGTH") or 0),
    "excessive_hyphens": int(os.environ.get("URL_EXCESSIVE_HYPHENS") or 0),
    "long_url_length": int(os.environ.get("URL_LONG_URL_LENGTH") or 0),
    "excessive_subdomains": int(os.environ.get("URL_EXCESSIVE_SUBDOMAINS") or 0),
    "encoded_chars_threshold": int(os.environ.get("URL_ENCODED_CHARS_THRESHOLD") or 0),
    "redirect_chain_threshold": int(os.environ.get("URL_REDIRECT_CHAIN_THRESHOLD") or 0),
    "external_domains_threshold": int(os.environ.get("URL_EXTERNAL_DOMAINS_THRESHOLD") or 0),
    "security_headers_threshold": int(os.environ.get("URL_SECURITY_HEADERS_THRESHOLD") or 0),
    "large_file_size": int(os.environ.get("URL_LARGE_FILE_SIZE") or 0),
    
    # Scan mode
    "fast_scan_mode": os.environ.get("URL_FAST_SCAN_MODE", "").strip().lower() in ("1", "true", "yes", "on"),

    # Risk scoring controls
    "invalid_url_risk_points": int(os.environ.get("URL_INVALID_URL_RISK_POINTS") or 95),
    "trusted_domain_bonus": int(os.environ.get("URL_TRUSTED_DOMAIN_BONUS") or -20),
    "trusted_domain_safe_score_cap": int(os.environ.get("URL_TRUSTED_DOMAIN_SAFE_SCORE_CAP") or 12),
    "multiple_phishing_keywords_threshold": int(os.environ.get("URL_MULTI_PHISHING_KEYWORDS_THRESHOLD") or 3),
    "missing_security_headers_threshold": int(os.environ.get("URL_MISSING_SECURITY_HEADERS_THRESHOLD") or 4),
    "missing_security_headers_risk_points": int(os.environ.get("URL_MISSING_SECURITY_HEADERS_RISK_POINTS") or 8),
    "phishing_page_possible_threshold": int(os.environ.get("URL_PHISHING_PAGE_POSSIBLE_THRESHOLD") or 3),
    "phishing_page_detected_threshold": int(os.environ.get("URL_PHISHING_PAGE_DETECTED_THRESHOLD") or 5),
    "phishing_page_possible_risk_points": int(os.environ.get("URL_PHISHING_PAGE_POSSIBLE_RISK_POINTS") or 12),
    "phishing_page_detected_risk_points": int(os.environ.get("URL_PHISHING_PAGE_DETECTED_RISK_POINTS") or 25),
    "risk_level_critical_min": int(os.environ.get("URL_RISK_LEVEL_CRITICAL_MIN") or 70),
    "risk_level_high_min": int(os.environ.get("URL_RISK_LEVEL_HIGH_MIN") or 50),
    "risk_level_medium_min": int(os.environ.get("URL_RISK_LEVEL_MEDIUM_MIN") or 30),
    "risk_level_low_min": int(os.environ.get("URL_RISK_LEVEL_LOW_MIN") or 15),
}

# Session Configuration
SESSION_CONFIG = {
    "max_redirects": int(os.environ.get("SESSION_MAX_REDIRECTS") or 0),
}

# Standard Ports
STANDARD_PORTS = [int(x) for x in os.environ.get("STANDARD_PORTS", "").split(",") if x]

# Private IP Ranges (regex patterns)
PRIVATE_IP_RANGES = os.environ.get("PRIVATE_IP_RANGES", "").split(",")

# Suspicious TLDs
SUSPICIOUS_TLDS = os.environ.get("SUSPICIOUS_TLDS", "").split(",")

# Trusted Domains
TRUSTED_DOMAINS = os.environ.get("TRUSTED_DOMAINS", "").split(",")

# Phishing Keywords
PHISHING_KEYWORDS = os.environ.get("PHISHING_KEYWORDS", "").split(",")

# Brand Names
BRAND_NAMES = os.environ.get("BRAND_NAMES", "").split(",")

# Phishing Urgency Keywords
PHISHING_URGENCY_KEYWORDS = os.environ.get("PHISHING_URGENCY_KEYWORDS", "").split(",")

# URL Analyzer - Suspicious Patterns
_suspicious_patterns_str = os.environ.get("SUSPICIOUS_PATTERNS", "")
SUSPICIOUS_PATTERNS = []
if _suspicious_patterns_str:
    for item in _suspicious_patterns_str.split(","):
        if "|" in item:
            pattern, description = item.rsplit("|", 1)
            SUSPICIOUS_PATTERNS.append((pattern, description))

# Malware File Patterns
_malware_patterns_str = os.environ.get("MALWARE_FILE_PATTERNS", "")
MALWARE_FILE_PATTERNS = []
if _malware_patterns_str:
    for item in _malware_patterns_str.split(","):
        if "|" in item:
            pattern, description = item.rsplit("|", 1)
            MALWARE_FILE_PATTERNS.append((pattern, description))

# Malicious JS Patterns
_malicious_js_str = os.environ.get("MALICIOUS_JS_PATTERNS", "")
MALICIOUS_JS_PATTERNS = []
if _malicious_js_str:
    for item in _malicious_js_str.split(","):
        if "|" in item:
            pattern, description = item.rsplit("|", 1)
            MALICIOUS_JS_PATTERNS.append((pattern, description))

# Cryptominer Patterns
_cryptominer_str = os.environ.get("CRYPTOMINER_PATTERNS", "")
CRYPTOMINER_PATTERNS = []
if _cryptominer_str:
    for item in _cryptominer_str.split(","):
        if "|" in item:
            pattern, description = item.rsplit("|", 1)
            CRYPTOMINER_PATTERNS.append((pattern, description))

# ==========================================================
# API KEYS - Configure via environment variables
# ==========================================================
# Get free API keys from:
# - VirusTotal: https://www.virustotal.com/gui/join-us
# - Google Safe Browsing: https://developers.google.com/safe-browsing/v4/get-started
# - AbuseIPDB: https://www.abuseipdb.com/account/api

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# Database Configuration
DATABASE_CONFIG = {
    "host": os.environ.get("DB_HOST", ""),
    "port": int(os.environ.get("DB_PORT") or 0),
    "database": os.environ.get("DB_NAME", ""),
    "user": os.environ.get("DB_USER", ""),
    "password": os.environ.get("DB_PASSWORD", ""),
}

# Logging Configuration
LOG_LEVEL = os.environ.get("LOG_LEVEL", "")
LOG_FORMAT = os.environ.get("LOG_FORMAT", "")

# Mock/placeholder prediction configuration
_severity_map_str = os.environ.get("ATTACK_SEVERITY_MAP", "")
ATTACK_SEVERITY_MAP = {}
if _severity_map_str:
    for item in _severity_map_str.split(","):
        if ":" in item:
            k, v = item.split(":", 1)
            ATTACK_SEVERITY_MAP[k.strip()] = v.strip()

_default_mock_classes = sorted(set(ATTACK_MAP.values())) or []
_env_mock_class_names = [
    x.strip() for x in os.environ.get("MOCK_CLASS_NAMES", "").split(",") if x.strip()
]
MOCK_CLASS_NAMES = _env_mock_class_names or _default_mock_classes or ["normal", "dos", "probe", "r2l", "u2r"]

_weights_raw = [x.strip() for x in os.environ.get("MOCK_CLASS_WEIGHTS", "").split(",") if x.strip()]
if _weights_raw and len(_weights_raw) == len(MOCK_CLASS_NAMES):
    MOCK_CLASS_WEIGHTS = [float(x) for x in _weights_raw]
else:
    MOCK_CLASS_WEIGHTS = []

MOCK_CONFIDENCE_MIN = float(os.environ.get("MOCK_CONFIDENCE_MIN") or 0.0)
MOCK_CONFIDENCE_MAX = float(os.environ.get("MOCK_CONFIDENCE_MAX") or 0.0)

def _load_metrics(env_key: str, fallback: dict):
    raw = os.environ.get(env_key, "").strip()
    if not raw:
        return fallback
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return fallback

_metrics_base = {
    "accuracy": 0.0,
    "precision": 0.0,
    "recall": 0.0,
    "f1_score": 0.0,
    "class_names": MOCK_CLASS_NAMES,
}
MOCK_MODEL_METRICS_UNLOADED = _load_metrics("MOCK_MODEL_METRICS_UNLOADED", _metrics_base)
MOCK_MODEL_METRICS_LOADED = _load_metrics("MOCK_MODEL_METRICS_LOADED", _metrics_base)
