import os
import time
import hashlib
import ipaddress
import pickle
import logging
from typing import Any, Dict, Optional

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
TOR_BULK_URL = os.getenv("TOR_BULK_URL", "https://check.torproject.org/torbulkexitlist")
TOR_CACHE_TTL = int(os.getenv("TOR_CACHE_TTL", "21600"))

GEOLITE2_ENABLED = os.getenv("GEOLITE2_ENABLED", "false").lower() == "true"
GEOLITE2_DB_PATH = os.getenv("GEOLITE2_DB_PATH", "/app/data/GeoLite2-City.mmdb")
GEOLITE2_ASN_DB_PATH = os.getenv("GEOLITE2_ASN_DB_PATH", "/app/data/GeoLite2-ASN.mmdb")

CACHE_TTL = int(os.getenv("ENRICHMENT_CACHE_TTL", "3600"))
HTTP_TIMEOUT = int(os.getenv("ENRICHMENT_HTTP_TIMEOUT", "5"))

ML_MODEL_PATH = os.getenv("ENRICHMENT_MODEL_PATH", "/app/models/xgb_anomaly_model.pkl")

logger = logging.getLogger(__name__)
_http = requests.Session()

_geolite_city_reader = None
_geolite_asn_reader = None

_abuse_cache: Dict[str, Dict[str, Any]] = {}
_greynoise_cache: Dict[str, Dict[str, Any]] = {}
_vt_cache: Dict[str, Dict[str, Any]] = {}
_geolite_cache: Dict[str, Dict[str, Any]] = {}

_tor_cache = {
    "expires": 0,
    "ips": set(),
}

ml_model = None


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


def _safe_ip(ip: str) -> str:
    return (ip or "").split(",")[0].strip()


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


# ============================================================
# HIBP — PWNED PASSWORDS
# ============================================================

def is_password_pwned(password: str) -> int:
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
        logger.warning("[HIBP] erreur: %s", e)
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
        logger.info("[TOR] liste mise à jour: %s IPs", len(ips))

    except Exception as e:
        logger.warning("[TOR] erreur refresh: %s", e)
        if not _tor_cache["ips"]:
            _tor_cache["expires"] = _now() + 300


def is_tor_exit_node(ip: str) -> bool:
    if not TOR_BULK_ENABLED or not is_public_ip(ip):
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
        return default
    if not ABUSEIPDB_API_KEY:
        result = default.copy()
        result["error"] = "missing_api_key"
        return result

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
                "verbose": "true",
            },
            timeout=HTTP_TIMEOUT,
        )

        if r.status_code == 200:
            data = r.json().get("data", {})
            result = {
                "source": "abuseipdb",
                "enabled": True,
                "abuse_score": int(data.get("abuseConfidenceScore", 0) or 0),
                "total_reports": int(data.get("totalReports", 0) or 0),
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

    if not GREYNOISE_ENABLED or not is_public_ip(ip):
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

    if not VIRUSTOTAL_ENABLED or not is_public_ip(ip):
        return default

    if not VIRUSTOTAL_API_KEY:
        result = default.copy()
        result["error"] = "missing_api_key"
        return result

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
# GEOLITE2
# ============================================================

def _open_geolite_readers():
    global _geolite_city_reader, _geolite_asn_reader

    if geoip2 is None:
        return

    if GEOLITE2_ENABLED and _geolite_city_reader is None and os.path.exists(GEOLITE2_DB_PATH):
        _geolite_city_reader = geoip2.database.Reader(GEOLITE2_DB_PATH)

    if GEOLITE2_ENABLED and _geolite_asn_reader is None and os.path.exists(GEOLITE2_ASN_DB_PATH):
        _geolite_asn_reader = geoip2.database.Reader(GEOLITE2_ASN_DB_PATH)


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

    if not GEOLITE2_ENABLED or not is_public_ip(ip):
        return default

    cached = _cache_get(_geolite_cache, ip)
    if cached:
        return cached

    if geoip2 is None:
        result = default.copy()
        result["error"] = "geoip2_library_missing"
        return result

    _open_geolite_readers()

    if _geolite_city_reader is None:
        result = default.copy()
        result["error"] = "geolite_city_db_missing"
        return result

    try:
        city = _geolite_city_reader.city(ip)
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

        if _geolite_asn_reader is not None:
            try:
                asn_info = _geolite_asn_reader.asn(ip)
                result["asn"] = int(asn_info.autonomous_system_number or 0)
                result["asn_org"] = asn_info.autonomous_system_organization or ""
            except Exception:
                pass

        _cache_set(_geolite_cache, ip, result)
        return result

    except Exception as e:
        result = default.copy()
        result["error"] = str(e)
        return result


# ============================================================
# INITIALISATION
# ============================================================

def initialize():
    global ml_model
    try:
        _open_geolite_readers()
    except Exception as e:
        logger.warning("[Enrichment] GeoLite init error: %s", e)

    try:
        if os.path.exists(ML_MODEL_PATH):
            with open(ML_MODEL_PATH, "rb") as f:
                ml_model = pickle.load(f)
            logger.info("[Enrichment] ML model loaded")
        else:
            ml_model = None
            logger.info("[Enrichment] ML model absent, heuristic fallback")
    except Exception as e:
        logger.warning("[Enrichment] ML init error: %s", e)
        ml_model = None

    if TOR_BULK_ENABLED:
        try:
            _refresh_tor_bulk_if_needed()
        except Exception as e:
            logger.warning("[Enrichment] TOR init error: %s", e)


# ============================================================
# POINT D'ENTRÉE PRINCIPAL
# ============================================================

def enrich_ip(ip: str) -> dict:
    ip = _safe_ip(ip)

    result = {
        "ip": ip,
        "is_public_ip": is_public_ip(ip),
        "is_tor_bulk": False,
        "abuseipdb": {},
        "greynoise": {},
        "virustotal": {},
        "geolite2": {},
        "asn": 0,
        "asn_org": "",
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
    result["asn"] = geo.get("asn", 0) or 0
    result["asn_org"] = geo.get("asn_org", "") or ""
    if geo.get("country_code"):
        result["risk_flags"].append(f"GEO_{geo['country_code']}")

    return result
