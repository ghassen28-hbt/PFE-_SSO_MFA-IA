#enrichment.py
import os
import time
import hashlib
import ipaddress
import json
import pickle
import statistics
# BUG FIX 1 : 'timezone' manquait dans les imports — causait TypeError dans toutes les
#             comparaisons de dates (datetime naive vs aware).
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, List, Tuple
from collections import defaultdict
import logging

import requests

try:
    import geoip2.database
except Exception:
    geoip2 = None


# ============================================================
# CONFIGURATION GLOBALE
# ============================================================

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_ENABLED = os.getenv("ABUSEIPDB_ENABLED", "false").lower() == "true"

GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
GREYNOISE_ENABLED = os.getenv("GREYNOISE_ENABLED", "false").lower() == "true"

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_ENABLED = os.getenv("VIRUSTOTAL_ENABLED", "false").lower() == "true"

HIBP_ENABLED = os.getenv("HIBP_ENABLED", "true").lower() == "true"

TOR_BULK_ENABLED = os.getenv("TOR_BULK_ENABLED", "true").lower() == "true"
TOR_BULK_URL = os.getenv(
    "TOR_BULK_URL",
    "https://check.torproject.org/torbulkexitlist"
)
TOR_CACHE_TTL = int(os.getenv("TOR_CACHE_TTL", "21600"))

GEOLITE2_ENABLED = os.getenv("GEOLITE2_ENABLED", "false").lower() == "true"
GEOLITE2_DB_PATH = os.getenv("GEOLITE2_DB_PATH", "/app/data/GeoLite2-City.mmdb")

CACHE_TTL = int(os.getenv("ENRICHMENT_CACHE_TTL", "3600"))
HTTP_TIMEOUT = int(os.getenv("ENRICHMENT_HTTP_TIMEOUT", "5"))

# ============================================================
# CONFIGURATION - ADVANCED FEATURES (35)
# ============================================================

IPQS_API_KEY = os.getenv("IPQS_API_KEY", "")
SIEM_WEBHOOK_URL = os.getenv("SIEM_WEBHOOK_URL", "")
BLOCKED_COUNTRIES = os.getenv("BLOCKED_COUNTRIES", "KP,IR,SY").split(",")
RESTRICTED_COUNTRIES = os.getenv("RESTRICTED_COUNTRIES", "RU,CN").split(",")
ML_MODEL_VERSION = "v2.3.1"
ML_MODEL_PATH = "/app/models/xgb_anomaly_model.pkl"
VPN_DETECTION_THRESHOLD = float(os.getenv("VPN_DETECTION_THRESHOLD", "0.8"))
BOT_SCORE_THRESHOLD = float(os.getenv("BOT_SCORE_THRESHOLD", "0.7"))
IMPOSSIBLE_TRAVEL_SPEED_KMH = int(os.getenv("IMPOSSIBLE_TRAVEL_SPEED_KMH", "900"))
DORMANCY_DAYS = int(os.getenv("DORMANCY_DAYS", "30"))
SIEM_RISK_THRESHOLD = int(os.getenv("SIEM_RISK_THRESHOLD", "70"))

logger = logging.getLogger(__name__)

_http = requests.Session()


# ============================================================
# CACHES MÉMOIRE
# ============================================================

_abuse_cache: Dict[str, Dict[str, Any]] = {}
_greynoise_cache: Dict[str, Dict[str, Any]] = {}
_vt_cache: Dict[str, Dict[str, Any]] = {}
_geolite_cache: Dict[str, Dict[str, Any]] = {}
# BUG FIX 2 : cache IPQS partagé entre detect_vpn et detect_proxy pour éviter
#             deux appels HTTP identiques par événement.
_ipqs_cache: Dict[str, Dict[str, Any]] = {}

_tor_cache = {
    "expires": 0,
    "ips": set(),
}


# ============================================================
# UTILITAIRES
# ============================================================

def _now() -> float:
    return time.time()


def _cache_get(cache: Dict[str, Dict[str, Any]], key: str) -> Optional[dict]:
    entry = cache.get(key)
    if not entry:
        return None
    if entry["expires"] <= _now():
        cache.pop(key, None)
        return None
    return entry["data"]


def _cache_set(cache: Dict[str, Dict[str, Any]], key: str, data: dict, ttl: int = CACHE_TTL) -> None:
    cache[key] = {
        "data": data,
        "expires": _now() + ttl,
    }


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


def _safe_ip(ip: str) -> str:
    return (ip or "").split(",")[0].strip()


# ============================================================
# HIBP — PWNED PASSWORDS
# ============================================================

def is_password_pwned(password: str) -> int:
    """
    Vérifie si un mot de passe est compromis via HIBP Pwned Passwords.
    Retourne le nombre d'expositions (0 = pas trouvé).
    Utilise k-anonymity : seuls les 5 premiers caractères du SHA1 sont envoyés.
    """
    if not HIBP_ENABLED:
        return 0

    if not password:
        return 0

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        r = _http.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=HTTP_TIMEOUT,
        )
        r.raise_for_status()

        for line in r.text.splitlines():
            parts = line.split(":")
            if len(parts) != 2:
                continue
            returned_suffix = parts[0].strip().upper()
            count_str = parts[1].strip()
            if returned_suffix == suffix:
                try:
                    return int(count_str)
                except ValueError:
                    return 0

        return 0

    except Exception as e:
        print(f"[HIBP] Erreur : {e}")
        return 0


# ============================================================
# TOR PROJECT BULK EXIT LIST
# ============================================================

def _refresh_tor_bulk_if_needed() -> None:
    if not TOR_BULK_ENABLED:
        return

    if _tor_cache["expires"] > _now() and _tor_cache["ips"]:
        return

    try:
        r = _http.get(TOR_BULK_URL, timeout=HTTP_TIMEOUT)
        r.raise_for_status()

        ips = set()
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ips.add(line)

        _tor_cache["ips"] = ips
        _tor_cache["expires"] = _now() + TOR_CACHE_TTL
        print(f"[TOR] Liste mise à jour : {len(ips)} IPs")

    except Exception as e:
        print(f"[TOR] Erreur refresh bulk list : {e}")
        if not _tor_cache["ips"]:
            _tor_cache["expires"] = _now() + 300


def is_tor_exit_node(ip: str) -> bool:
    if not TOR_BULK_ENABLED:
        return False
    if not is_public_ip(ip):
        return False
    _refresh_tor_bulk_if_needed()
    return ip in _tor_cache["ips"]


# ============================================================
# ABUSEIPDB
# ============================================================

def get_ip_abuse_score(ip: str) -> dict:
    ip = _safe_ip(ip)

    default = {
        "source": "abuseipdb",
        "enabled": ABUSEIPDB_ENABLED,
        "abuse_score": 0,
        "total_reports": 0,
        "usage_type": "",
        "isp": "",
        "domain": "",
        "country_code": "",
        "last_reported_at": "",
        "error": "",
    }

    if not ABUSEIPDB_ENABLED:
        return default

    if not is_public_ip(ip):
        print(f"[AbuseIPDB] IP non publique ignorée : {ip}")
        return default

    if not ABUSEIPDB_API_KEY:
        print("[AbuseIPDB] Clé API absente")
        default["error"] = "missing_api_key"
        return default

    cached = _cache_get(_abuse_cache, ip)
    if cached:
        return cached

    try:
        r = _http.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
            },
            timeout=HTTP_TIMEOUT,
        )

        if r.status_code == 200:
            data = r.json().get("data", {})
            result = {
                "source": "abuseipdb",
                "enabled": True,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "usage_type": data.get("usageType", "") or "",
                "isp": data.get("isp", "") or "",
                "domain": data.get("domain", "") or "",
                "country_code": data.get("countryCode", "") or "",
                "last_reported_at": data.get("lastReportedAt", "") or "",
                "error": "",
            }
        else:
            result = default.copy()
            result["error"] = f"http_{r.status_code}"

        _cache_set(_abuse_cache, ip, result)
        return result

    except requests.exceptions.Timeout:
        result = default.copy()
        result["error"] = "timeout"
        return result

    except Exception as e:
        result = default.copy()
        result["error"] = str(e)
        return result


# ============================================================
# GREYNOISE COMMUNITY
# ============================================================

def get_greynoise_context(ip: str) -> dict:
    ip = _safe_ip(ip)

    default = {
        "source": "greynoise",
        "enabled": GREYNOISE_ENABLED,
        "noise": False,
        "riot": False,
        "classification": "",
        "name": "",
        "link": "",
        "error": "",
    }

    if not GREYNOISE_ENABLED:
        return default

    if not is_public_ip(ip):
        return default

    cached = _cache_get(_greynoise_cache, ip)
    if cached:
        return cached

    headers = {"Accept": "application/json"}
    if GREYNOISE_API_KEY:
        headers["key"] = GREYNOISE_API_KEY

    try:
        r = _http.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers=headers,
            timeout=HTTP_TIMEOUT,
        )

        if r.status_code == 200:
            data = r.json()
            result = {
                "source": "greynoise",
                "enabled": True,
                "noise": bool(data.get("noise", False)),
                "riot": bool(data.get("riot", False)),
                "classification": data.get("classification", "") or "",
                "name": data.get("name", "") or "",
                "link": data.get("link", "") or "",
                "error": "",
            }
        else:
            result = default.copy()
            result["error"] = f"http_{r.status_code}"

        _cache_set(_greynoise_cache, ip, result)
        return result

    except Exception as e:
        result = default.copy()
        result["error"] = str(e)
        return result


# ============================================================
# VIRUSTOTAL
# ============================================================

def get_virustotal_ip_context(ip: str) -> dict:
    ip = _safe_ip(ip)

    default = {
        "source": "virustotal",
        "enabled": VIRUSTOTAL_ENABLED,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "reputation": 0,
        "error": "",
    }

    if not VIRUSTOTAL_ENABLED:
        return default

    if not is_public_ip(ip):
        return default

    if not VIRUSTOTAL_API_KEY:
        default["error"] = "missing_api_key"
        return default

    cached = _cache_get(_vt_cache, ip)
    if cached:
        return cached

    try:
        r = _http.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=HTTP_TIMEOUT,
        )

        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {}) or {}
            result = {
                "source": "virustotal",
                "enabled": True,
                "malicious": int(stats.get("malicious", 0) or 0),
                "suspicious": int(stats.get("suspicious", 0) or 0),
                "harmless": int(stats.get("harmless", 0) or 0),
                "undetected": int(stats.get("undetected", 0) or 0),
                "reputation": int(data.get("reputation", 0) or 0),
                "error": "",
            }
        else:
            result = default.copy()
            result["error"] = f"http_{r.status_code}"

        _cache_set(_vt_cache, ip, result)
        return result

    except Exception as e:
        result = default.copy()
        result["error"] = str(e)
        return result


# ============================================================
# GEOLITE2 LOCAL
# ============================================================

def get_geolite2_info(ip: str) -> dict:
    ip = _safe_ip(ip)

    default = {
        "source": "geolite2",
        "enabled": GEOLITE2_ENABLED,
        "country": "",
        "country_code": "",
        "city": "",
        "postal_code": "",
        "latitude": 0.0,
        "longitude": 0.0,
        "timezone": "",
        "asn": 0,
        "asn_org": "",
        "error": "",
    }

    if not GEOLITE2_ENABLED:
        return default

    if not is_public_ip(ip):
        return default

    cached = _cache_get(_geolite_cache, ip)
    if cached:
        return cached

    if geoip2 is None:
        result = default.copy()
        result["error"] = "geoip2_library_missing"
        return result

    if not os.path.exists(GEOLITE2_DB_PATH):
        result = default.copy()
        result["error"] = "geolite_db_missing"
        return result

    try:
        with geoip2.database.Reader(GEOLITE2_DB_PATH) as reader:
            city = reader.city(ip)
            result = {
                "source": "geolite2",
                "enabled": True,
                "country": city.country.name or "",
                "country_code": city.country.iso_code or "",
                "city": city.city.name or "",
                "postal_code": city.postal.code or "",
                "latitude": float(city.location.latitude or 0.0),
                "longitude": float(city.location.longitude or 0.0),
                "timezone": city.location.time_zone or "",
                "asn": 0,
                "asn_org": "",
                "error": "",
            }

        _cache_set(_geolite_cache, ip, result)
        return result

    except Exception as e:
        result = default.copy()
        result["error"] = str(e)
        return result


# ============================================================
# CACHES FOR ADVANCED FEATURES
# ============================================================

user_login_history = defaultdict(list)  # user_id -> [events]
user_location_history = defaultdict(list)  # user_id -> [locations]
ml_model = None  # ML model cache


# ============================================================
# ADVANCED FEATURES (35) - GROUPE 13-20
# ============================================================

def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate distance between two points in km"""
    from math import radians, cos, sin, asin, sqrt
    try:
        lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))
        return 6371 * c
    except Exception:
        return 0.0


# ============================================================
# GROUPE 13: Advanced Context
# ============================================================

def _get_ipqs_data(ip: str) -> dict:
    """
    BUG FIX 2 : Appel IPQS mutualisé.
    detect_vpn et detect_proxy appelaient l'API deux fois par événement
    avec les mêmes paramètres. Cette fonction met le résultat en cache.
    """
    cached = _cache_get(_ipqs_cache, ip)
    if cached:
        return cached

    try:
        r = _http.get(
            f"https://ipqualityscore.com/api/json/ip/{ip}",
            params={"key": IPQS_API_KEY, "strictness": 1},
            timeout=HTTP_TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            _cache_set(_ipqs_cache, ip, data)
            return data
    except Exception as e:
        print(f"[IPQS] Error: {e}")
    return {}


def detect_vpn(ip: str) -> Tuple[int, str]:
    """[55-56] Detect VPN using IPQS"""
    try:
        if not IPQS_API_KEY or not is_public_ip(ip):
            return (0, "")
        data = _get_ipqs_data(ip)
        if data.get("vpn"):
            return (1, data.get("vpn_service", ""))
        return (0, "")
    except Exception as e:
        print(f"[VPN Detection] Error: {e}")
        return (0, "")


def detect_proxy(ip: str) -> Tuple[int, str]:
    """[57-58] Detect proxy using IPQS"""
    try:
        if not is_public_ip(ip):
            return (0, "")
        if not IPQS_API_KEY:
            return (0, "IPQS_KEY_NOT_CONFIGURED")
        data = _get_ipqs_data(ip)
        if data.get("proxy"):
            return (1, data.get("proxy_service", "proxy_service_unknown"))
        return (0, "")
    except Exception as e:
        print(f"[Proxy Detection] Error: {e}")
        return (0, "")


def update_user_location_history(user_id: str, geo_city: str, geo_latitude: float, geo_longitude: float, event_time: datetime, max_entries: int = 10) -> str:
    """Maintient l'historique des positions par utilisateur."""
    try:
        if not user_id:
            return "[]"
        history = user_location_history.get(user_id, [])
        entry = {
            "city": geo_city or "UNKNOWN",
            "country": "",
            "latitude": float(geo_latitude or 0.0),
            "longitude": float(geo_longitude or 0.0),
            "event_time": event_time.isoformat() if isinstance(event_time, datetime) else str(event_time),
        }
        history.append(entry)
        if len(history) > max_entries:
            history = history[-max_entries:]
        user_location_history[user_id] = history
        return json.dumps(history, ensure_ascii=False)
    except Exception as e:
        print(f"[User Location History] Error: {e}")
        return "[]"


def detect_impossible_travel(event_data: Dict, user_history: List) -> int:
    """[53] Detect impossible travel"""
    try:
        if not user_history or len(user_history) < 1:
            return 0

        current_lat = event_data.get("geo_latitude", 0)
        current_lon = event_data.get("geo_longitude", 0)
        current_time = event_data.get("event_time")

        prev = user_history[-1]

        # BUG FIX 3 : Les clés dans l'historique sont 'geo_latitude'/'geo_longitude'
        #             (nommées ainsi dans event_data_dict de main.py), pas 'latitude'/'longitude'.
        #             Avant : prev.get("latitude", 0) → toujours 0 → distance toujours 0
        #                     → voyage impossible jamais détecté.
        prev_lat = prev.get("geo_latitude", 0)
        prev_lon = prev.get("geo_longitude", 0)

        # BUG FIX 4 : La clé temps dans l'historique est 'event_time', pas 'timestamp'.
        #             Avant : prev.get("timestamp") → None → condition jamais vraie.
        prev_time = prev.get("event_time")

        if not current_time or not prev_time:
            return 0

        distance_km = haversine_distance(prev_lat, prev_lon, current_lat, current_lon)
        time_diff_hours = (current_time - prev_time).total_seconds() / 3600

        if time_diff_hours > 0:
            speed_required = distance_km / time_diff_hours
            if speed_required > IMPOSSIBLE_TRAVEL_SPEED_KMH:
                return 1

        return 0
    except Exception as e:
        print(f"[Impossible Travel] Error: {e}")
        return 0


def calculate_distance_from_last_location(event_data: Dict, user_history: List) -> float:
    """[54] Distance from last known location in km"""
    try:
        if not user_history:
            return 0.0
        prev = user_history[-1]
        return haversine_distance(
            prev.get("geo_latitude", 0), prev.get("geo_longitude", 0),
            event_data.get("geo_latitude", 0), event_data.get("geo_longitude", 0),
        )
    except Exception:
        return 0.0


# ============================================================
# GROUPE 14: Behavior
# ============================================================

def count_consecutive_failures(user_id: str) -> int:
    """[59] Count consecutive login failures from in-memory history"""
    try:
        events = user_login_history.get(user_id, [])
        count = 0
        for event in reversed(events):
            if not event.get("event_success"):
                count += 1
            else:
                break
        return count
    except Exception:
        return 0


def calculate_time_since_last_login(user_id: str) -> int:
    """[60] Minutes since last successful login"""
    try:
        events = user_login_history.get(user_id, [])
        for event in reversed(events):
            if event.get("event_success"):
                last_time = event.get("event_time")
                if last_time is None:
                    return -1
                # BUG FIX 5 : datetime.now() est naïf mais event_time est timezone-aware
                #             (datetime.now(timezone.utc) dans main.py).
                #             La soustraction levait TypeError.
                elapsed = (datetime.now(timezone.utc) - last_time).total_seconds() / 60
                return int(elapsed)
        return -1
    except Exception:
        return -1


def detect_account_dormant(user_id: str) -> int:
    """[61] Detect if account is dormant (30+ days without login)"""
    try:
        events = user_login_history.get(user_id, [])
        if not events:
            return 0
        last_login = events[-1].get("event_time")
        if last_login is None:
            return 0
        # BUG FIX 6 : Même problème naive vs aware.
        days_ago = (datetime.now(timezone.utc) - last_login).days
        return 1 if days_ago > DORMANCY_DAYS else 0
    except Exception:
        return 0


def calculate_login_frequency_deviation(user_id: str) -> float:
    """[62] Login frequency deviation (Z-score)"""
    try:
        events = user_login_history.get(user_id, [])
        if len(events) < 5:
            return 0.0

        times = []
        for i in range(len(events) - 1, 0, -1):
            t_curr = events[i].get("event_time")
            t_prev = events[i - 1].get("event_time")
            if t_curr and t_prev and events[i - 1].get("event_success") and events[i].get("event_success"):
                delta = (t_curr - t_prev).total_seconds()
                times.append(delta)

        if len(times) < 2:
            return 0.0

        avg = statistics.mean(times)
        stddev = statistics.stdev(times)
        if stddev == 0:
            return 0.0

        last_time = events[-1].get("event_time")
        if last_time is None:
            return 0.0

        # BUG FIX 7 : Même problème naive vs aware.
        current_interval = (datetime.now(timezone.utc) - last_time).total_seconds()
        z_score = abs((current_interval - avg) / stddev)
        return min(5.0, z_score)
    except Exception:
        return 0.0


def count_app_switches(user_id: str, session_id: str) -> int:
    """[63] Count distinct apps accessed in the current session"""
    try:
        events = user_login_history.get(user_id, [])
        apps = set()
        for event in events:
            if event.get("session_id") == session_id and event.get("client_id"):
                apps.add(event["client_id"])
        return len(apps)
    except Exception:
        return 0


# ============================================================
# GROUPE 15: ML
# ============================================================

def calculate_ml_anomaly_score(event_data: Dict) -> float:
    """[64] ML anomaly score (0-1). Falls back to heuristic if model absent."""
    try:
        if ml_model is None:
            return calculate_anomaly_heuristic(event_data)
        features = extract_feature_vector(event_data)
        score = ml_model.predict_proba([features])[0][1]
        return float(score)
    except Exception:
        return calculate_anomaly_heuristic(event_data)


def calculate_anomaly_heuristic(event_data: Dict) -> float:
    """Fallback anomaly scoring without ML model"""
    score = 0.0
    if event_data.get("is_tor"):
        score += 0.25
    if event_data.get("abuse_score", 0) > 40:
        score += 0.15
    if event_data.get("is_new_device"):
        score += 0.10
    if event_data.get("fails_1h", 0) > 5:
        score += 0.20
    if event_data.get("is_night_login"):
        score += 0.05
    if event_data.get("is_vpn_detected"):
        score += 0.10
    if event_data.get("is_impossible_travel"):
        score += 0.15
    return min(1.0, score)


def extract_feature_vector(event_data: Dict) -> list:
    """Extract feature vector for ML model (10 features)"""
    return [
        float(event_data.get("abuse_score", 0)),
        float(event_data.get("is_tor", 0)),
        float(event_data.get("is_new_device", 0)),
        float(event_data.get("fails_1h", 0)),
        float(event_data.get("is_night_login", 0)),
        float(event_data.get("geo_latitude", 0)),
        float(event_data.get("geo_longitude", 0)),
        float(event_data.get("greynoise_noise", 0)),
        float(event_data.get("vt_malicious", 0)),
        float(event_data.get("app_sensitivity", 0)),
    ]


# ============================================================
# GROUPE 16: MFA
# ============================================================

def get_mfa_method_used(event_data: Dict) -> str:
    """[68] Get MFA method used"""
    return event_data.get("mfa_method", "NONE")


def calculate_mfa_response_time(event_data: Dict) -> int:
    """[69] MFA response time in seconds (-1 = not applicable)"""
    return int(event_data.get("mfa_response_time", -1))


def get_mfa_success(event_data: Dict) -> int:
    """[70] MFA success flag (0/1)"""
    return 1 if event_data.get("mfa_success") else 0


def count_mfa_attempts_before_success(event_data: Dict) -> int:
    """[71] Number of MFA attempts before success (min 1)"""
    return max(1, int(event_data.get("mfa_attempts", 1)))


# ============================================================
# GROUPE 17: Security Detection
# ============================================================

def calculate_bot_score(event_data: Dict) -> float:
    """[72] Bot probability score (0-1) based on User-Agent analysis"""
    try:
        ua = event_data.get("ua_raw", "").lower()
        score = 0.0
        headless_indicators = ["headless", "phantom", "selenium", "automation", "bot"]
        if any(ind in ua for ind in headless_indicators):
            score += 0.5
        if "curl" in ua or "wget" in ua or "python-requests" in ua:
            score += 0.3
        return min(1.0, score)
    except Exception:
        return 0.0


def detect_credential_stuffing(event_data: Dict, user_history: List) -> int:
    """[73] Detect credential stuffing: same IP targeting multiple accounts"""
    try:
        events = user_history[-10:] if user_history else []
        ip_count: Dict[str, int] = {}
        for event in events:
            ip = event.get("ip")
            if ip:
                ip_count[ip] = ip_count.get(ip, 0) + 1
        return 1 if any(count > 3 for count in ip_count.values()) else 0
    except Exception:
        return 0


def detect_account_takeover(event_data: Dict, user_history: List) -> int:
    """
    [74] Detect account takeover (ATO).
    BUG FIX 8 : Cette fonction lisait event_data.get("is_vpn_detected") et
                event_data.get("is_impossible_travel"), mais ces champs n'étaient
                PAS dans event_data_dict au moment de l'appel (ils étaient calculés
                séparément dans main.py et non réinjectés).
                Résultat : le score ATO était systématiquement sous-estimé.
                Correction : main.py met maintenant à jour event_data_dict AVANT
                cet appel. Cette fonction peut donc lire les champs correctement.
    """
    try:
        score = 0
        if event_data.get("is_impossible_travel"):
            score += 1
        if event_data.get("is_vpn_detected"):
            score += 1
        if event_data.get("is_new_device"):
            score += 1
        if event_data.get("fails_1h", 0) > 5:
            score += 1
        if event_data.get("abuse_score", 0) > 40:
            score += 1
        return 1 if score >= 2 else 0
    except Exception:
        return 0


def detect_session_hijacking(event_data: Dict, user_history: List) -> int:
    """[75] Detect session hijacking: same session ID but different device fingerprint"""
    try:
        if not user_history:
            return 0
        prev = user_history[-1]
        if (event_data.get("session_id") == prev.get("session_id") and
                event_data.get("session_id") and
                event_data.get("device_fp") != prev.get("device_fp")):
            return 1
        return 0
    except Exception:
        return 0


# ============================================================
# GROUPE 18: Predictive
# ============================================================

def calculate_risk_trend(user_id: str) -> str:
    """[76] Risk trend over last 10 events: STABLE / INCREASING / DECREASING"""
    try:
        events = user_login_history.get(user_id, [])
        if len(events) < 5:
            return "STABLE"
        recent = [e.get("risk_score", 0) for e in events[-5:]]
        avg_recent = sum(recent) / len(recent)
        older = [e.get("risk_score", 0) for e in events[-10:-5]] if len(events) >= 10 else recent
        avg_older = sum(older) / len(older)
        if avg_recent > avg_older * 1.2:
            return "INCREASING"
        elif avg_recent < avg_older * 0.8:
            return "DECREASING"
        return "STABLE"
    except Exception:
        return "STABLE"


def predict_next_login_risk(event_data: Dict) -> float:
    """[77] Predicted risk score for next login based on current trend"""
    trend = calculate_risk_trend(event_data.get("user_id", ""))
    current_risk = float(event_data.get("risk_score", 0))
    if trend == "INCREASING":
        return min(100.0, current_risk * 1.2)
    elif trend == "DECREASING":
        return max(0.0, current_risk * 0.8)
    return current_risk


# ============================================================
# GROUPE 19: Compliance
# ============================================================

def classify_regulatory(event_data: Dict) -> str:
    """[78] Map app sensitivity to regulatory classification"""
    sensitivity = event_data.get("app_sensitivity", 0)
    if sensitivity >= 4:
        return "PCI-DSS"
    elif sensitivity == 3:
        return "HIPAA"
    elif sensitivity == 2:
        return "GDPR"
    return "NONE"


def check_breach_flag(event_data: Dict) -> int:
    """
    [79] Check if username appears in known breaches via HIBP.
    BUG FIX 9 : L'ancienne version appelait is_password_pwned("") — mot de passe
                vide — qui retourne immédiatement 0 par design.
                La fonction retournait donc TOUJOURS 0.
                Correction : utilise l'API HIBP breachedaccount sur le username.
                Si HIBP n'est pas activé ou si l'appel échoue, retourne 0.
    """
    if not HIBP_ENABLED:
        return 0
    username = event_data.get("username", "")
    if not username:
        return 0
    try:
        r = _http.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{username}",
            headers={
                "hibp-api-key": os.getenv("HIBP_API_KEY", ""),
                "User-Agent": "PFE-SSO-MFA-IA",
            },
            timeout=HTTP_TIMEOUT,
        )
        if r.status_code == 200:
            return 1  # trouvé dans au moins une fuite
        if r.status_code == 404:
            return 0  # pas trouvé
        return 0
    except Exception as e:
        print(f"[HIBP breachedaccount] Error: {e}")
        return 0


def check_restricted_country(event_data: Dict) -> int:
    """[80] Flag logins from restricted countries"""
    country_code = event_data.get("geo_country_code", "")
    return 1 if country_code in RESTRICTED_COUNTRIES else 0


# ============================================================
# GROUPE 20: Integration
# ============================================================

def send_to_siem(event_data: Dict) -> str:
    """
    [81] Send alert to SIEM webhook.
    Envoi uniquement si risk_score dépasse le seuil configuré.
    """
    try:
        if not SIEM_WEBHOOK_URL:
            return ""
        if event_data.get("risk_score", 0) < SIEM_RISK_THRESHOLD:
            return ""
        payload = {
            "username": event_data.get("username"),
            "ip": event_data.get("ip"),
            "risk_score": event_data.get("risk_score"),
            "event_type": event_data.get("event_type"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        r = requests.post(SIEM_WEBHOOK_URL, json=payload, timeout=5)
        return f"sent_{r.status_code}"
    except Exception:
        return ""


def check_external_threat_feeds(ip: str) -> str:
    """[82] Check external threat feed matches (placeholder)"""
    return json.dumps([])


def check_darknet_mention(ip: str) -> int:
    """[83] Check darknet mentions (placeholder)"""
    return 0


# ============================================================
# INITIALISATION
# ============================================================

def initialize():
    """Load ML model on startup. Falls back gracefully if absent."""
    global ml_model
    try:
        if os.path.exists(ML_MODEL_PATH):
            with open(ML_MODEL_PATH, "rb") as f:
                ml_model = pickle.load(f)
                print("[Enrichment] ML model loaded successfully")
        else:
            print(f"[Enrichment] ML model not found at {ML_MODEL_PATH}, using heuristic fallback")
            ml_model = None
    except Exception as e:
        print(f"[Enrichment] Error loading ML model: {e}")
        ml_model = None


# ============================================================
# POINT D'ENTRÉE PRINCIPAL
# ============================================================

def enrich_ip(ip: str) -> dict:
    """
    Enrichissement centralisé d'une IP.
    Appelé par main.py pour chaque événement entrant.
    """
    ip = _safe_ip(ip)

    result = {
        "ip": ip,
        "is_public_ip": is_public_ip(ip),
        "is_tor_bulk": False,
        "abuseipdb": {},
        "greynoise": {},
        "virustotal": {},
        "geolite2": {},
        "risk_flags": [],
    }

    if not result["is_public_ip"]:
        result["risk_flags"].append("NON_PUBLIC_IP")
        return result

    result["is_tor_bulk"] = is_tor_exit_node(ip)
    if result["is_tor_bulk"]:
        result["risk_flags"].append("TOR_EXIT_NODE")

    abuse = get_ip_abuse_score(ip)
    result["abuseipdb"] = abuse
    if abuse.get("abuse_score", 0) >= 40:
        result["risk_flags"].append("HIGH_ABUSE_SCORE")
    elif abuse.get("abuse_score", 0) > 0:
        result["risk_flags"].append("NON_ZERO_ABUSE_SCORE")

    gn = get_greynoise_context(ip)
    result["greynoise"] = gn
    if gn.get("noise"):
        result["risk_flags"].append("GREYNOISE_NOISE")
    if gn.get("classification"):
        result["risk_flags"].append(f"GREYNOISE_{gn['classification'].upper()}")

    vt = get_virustotal_ip_context(ip)
    result["virustotal"] = vt
    if vt.get("malicious", 0) > 0:
        result["risk_flags"].append("VT_MALICIOUS")
    if vt.get("suspicious", 0) > 0:
        result["risk_flags"].append("VT_SUSPICIOUS")

    geo = get_geolite2_info(ip)
    result["geolite2"] = geo
    if geo.get("country_code"):
        result["risk_flags"].append(f"GEO_{geo['country_code']}")

    return result