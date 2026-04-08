from fastapi import FastAPI, Request, HTTPException
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
import re
import math
import requests
import ipaddress
from typing import Optional

from user_agents import parse as parse_ua

from enrichment import (
    enrich_ip,
    is_password_pwned,
    initialize,
)

app = FastAPI()


@app.on_event("startup")
async def startup_event():
    initialize()


# ============================================================
# CONFIGURATION CLICKHOUSE
# ============================================================

CLICKHOUSE_URL = os.getenv("CLICKHOUSE_URL", "http://clickhouse:8123")
CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "iam")
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
TABLE = os.getenv("CLICKHOUSE_TABLE", "login_events")

# ============================================================
# CONFIGURATION RISK SCORING SERVICE
# ============================================================

SCORING_ENABLED = os.getenv("SCORING_ENABLED", "true").lower() == "true"
SCORING_URL = os.getenv("SCORING_URL", "http://host.docker.internal:8090/score")
SCORING_TIMEOUT = int(os.getenv("SCORING_TIMEOUT", "5"))
RECENT_LOGIN_LOOKBACK_MINUTES = int(os.getenv("RECENT_LOGIN_LOOKBACK_MINUTES", "3"))
STEP_UP_LOGIN_LOOKBACK_MINUTES = int(
    os.getenv("STEP_UP_LOGIN_LOOKBACK_MINUTES", str(max(RECENT_LOGIN_LOOKBACK_MINUTES, 10)))
)
HISTORY_RESET_AT_RAW = os.getenv("HISTORY_RESET_AT", "").strip()
STEP_UP_CLIENT_IDS_RAW = os.getenv("STEP_UP_CLIENT_IDS", "portal-stepup-totp-client")

_http = requests.Session()


# ============================================================
# OUTILS CLICKHOUSE
# ============================================================

def ch_query(sql: str) -> str:
    r = _http.post(
        f"{CLICKHOUSE_URL}/?database={CLICKHOUSE_DB}",
        data=sql.encode("utf-8"),
        auth=(CLICKHOUSE_USER, CLICKHOUSE_PASSWORD),
        timeout=20,
    )
    r.raise_for_status()
    return r.text


def sql_escape(value: str) -> str:
    if value is None:
        return ""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def parse_csv_set(raw: str) -> set:
    return {
        item.strip()
        for item in str(raw or "").split(",")
        if item and item.strip()
    }


STEP_UP_CLIENT_IDS = parse_csv_set(STEP_UP_CLIENT_IDS_RAW)


def is_step_up_client(client_id: str) -> bool:
    return str(client_id or "").strip() in STEP_UP_CLIENT_IDS


def step_up_client_exclusion_sql(column: str = "client_id") -> str:
    if not STEP_UP_CLIENT_IDS:
        return "1 = 1"

    values = ", ".join(
        f"'{sql_escape(client_id)}'"
        for client_id in sorted(STEP_UP_CLIENT_IDS)
    )
    return f"{column} NOT IN ({values})"


# ============================================================
# OUTILS GÉNÉRAUX
# ============================================================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_config_datetime(raw: str) -> Optional[datetime]:
    if not raw:
        return None

    raw_str = str(raw).strip()
    if not raw_str:
        return None

    candidates = [raw_str]
    if " " in raw_str and "T" not in raw_str:
        candidates.append(raw_str.replace(" ", "T"))

    for candidate in candidates:
        try:
            dt = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            continue

    return None


HISTORY_RESET_AT = parse_config_datetime(HISTORY_RESET_AT_RAW)


def apply_history_reset_floor(
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
):
    if HISTORY_RESET_AT is None:
        return since, until

    floored_since = max(filter(None, [since, HISTORY_RESET_AT])) if since is not None else HISTORY_RESET_AT

    if until is not None and floored_since > until:
        floored_since = until

    return floored_since, until


def parse_event_time(data: dict) -> datetime:
    candidates = [
        data.get("ts"),
        data.get("event_time"),
        data.get("timestamp"),
        data.get("time"),
    ]

    for raw in candidates:
        if raw is None:
            continue

        raw_str = str(raw).strip()
        if not raw_str:
            continue

        try:
            if raw_str.isdigit() and len(raw_str) >= 13:
                return datetime.fromtimestamp(int(raw_str) / 1000, tz=timezone.utc)
            if raw_str.isdigit() and len(raw_str) >= 10:
                return datetime.fromtimestamp(int(raw_str), tz=timezone.utc)
            return datetime.fromisoformat(raw_str.replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            continue

    return now_utc()


def time_features(dt: datetime):
    hour = dt.hour
    dow = dt.weekday() + 1
    weekend = 1 if dow >= 6 else 0
    return hour, dow, weekend


def _pick_first_valid_ip(candidates, prefer_public: bool = True) -> str:
    public_ips = []
    other_ips = []

    for value in candidates:
        if not value:
            continue
        parts = [p.strip() for p in str(value).split(",") if p.strip()]
        for ip in parts:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            if is_public_ip(ip):
                public_ips.append(ip)
            else:
                other_ips.append(ip)

    if prefer_public and public_ips:
        return public_ips[0]
    if other_ips:
        return other_ips[0]
    return ""


def extract_real_ip(data: dict, request: Request) -> str:
    details = data.get("details") or {}

    high_priority = [
        request.headers.get("x-forwarded-for", ""),
        request.headers.get("x-real-ip", ""),
        data.get("http_x_forwarded_for", ""),
        data.get("http_x_real_ip", ""),
        details.get("client_ip", ""),
        details.get("ipAddress", ""),
    ]
    ip = _pick_first_valid_ip(high_priority, prefer_public=True)
    if ip:
        return ip

    low_priority = [
        data.get("ipAddress", ""),
        data.get("event_ip", ""),
        request.client.host if request.client else "",
    ]
    return _pick_first_valid_ip(low_priority, prefer_public=False)


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


def extract_username(data: dict) -> str:
    details = data.get("details") or {}
    return (
        details.get("username")
        or details.get("preferred_username")
        or details.get("auth_username")
        or details.get("attempted_username")
        or details.get("login_username")
        or data.get("username")
        or ""
    ).strip()


# ============================================================
# CLIENT HINTS / USER-AGENT
# ============================================================

def extract_client_hints(data: dict, request: Request) -> dict:
    return {
        "sec_ch_ua": data.get("http_sec_ch_ua") or request.headers.get("sec-ch-ua", "") or "",
        "sec_ch_ua_platform": data.get("http_sec_ch_ua_platform") or request.headers.get("sec-ch-ua-platform", "") or "",
        "sec_ch_ua_platform_version": data.get("http_sec_ch_ua_platform_version") or request.headers.get("sec-ch-ua-platform-version", "") or "",
        "sec_ch_ua_full_version_list": data.get("http_sec_ch_ua_full_version_list") or request.headers.get("sec-ch-ua-full-version-list", "") or "",
        "accept_language": data.get("http_accept_language") or request.headers.get("accept-language", "") or "",
    }


def _extract_brand_version(full_version_list: str, brand: str) -> str:
    if not full_version_list:
        return ""
    pattern = rf'"{re.escape(brand)}";v="([^"]+)"'
    match = re.search(pattern, full_version_list)
    return match.group(1) if match else ""


def infer_browser(ua_raw: str, ch: dict) -> str:
    sec_ch_ua = ch.get("sec_ch_ua", "")
    sec_ch_ua_full = ch.get("sec_ch_ua_full_version_list", "")

    if "Brave" in sec_ch_ua or "Brave" in sec_ch_ua_full:
        version = _extract_brand_version(sec_ch_ua_full, "Brave")
        return f"Brave {version}".strip()

    if "Microsoft Edge" in sec_ch_ua_full or '"Microsoft Edge"' in sec_ch_ua:
        version = _extract_brand_version(sec_ch_ua_full, "Microsoft Edge")
        return f"Edge {version}".strip()

    if "Google Chrome" in sec_ch_ua_full or '"Google Chrome"' in sec_ch_ua:
        version = _extract_brand_version(sec_ch_ua_full, "Google Chrome")
        return f"Chrome {version}".strip()

    ua = parse_ua(ua_raw) if ua_raw else None
    return f"{ua.browser.family} {ua.browser.version_string}".strip() if ua else ""


def infer_os(ua_raw: str, ch: dict) -> str:
    platform_name = (ch.get("sec_ch_ua_platform", "") or "").replace('"', "").strip()
    platform_version = (ch.get("sec_ch_ua_platform_version", "") or "").replace('"', "").strip()

    if platform_name.lower() == "windows":
        try:
            major = int(platform_version.split(".")[0])
        except Exception:
            major = 0
        return "Windows 11" if major >= 13 else "Windows 10"

    if platform_name:
        return platform_name

    ua = parse_ua(ua_raw) if ua_raw else None
    return f"{ua.os.family} {ua.os.version_string}".strip() if ua else ""


def infer_device(ua_raw: str) -> str:
    ua = parse_ua(ua_raw) if ua_raw else None
    if not ua:
        return "other"
    if ua.is_mobile:
        return "mobile"
    if ua.is_tablet:
        return "tablet"
    if ua.is_pc:
        return "pc"
    return "other"


def device_fingerprint(
    ua_raw: str,
    ua_browser: str,
    ua_os: str,
    ua_device: str,
    ch: dict,
) -> str:
    stable_browser = (ua_browser or "").split(" ")[0].strip().lower()
    stable_os = (ua_os or "").strip().lower()
    stable_device = (ua_device or "").strip().lower()
    stable_lang = (ch.get("accept_language", "") or "").split(",")[0].strip().lower()

    parts = [
        stable_browser,
        stable_os,
        stable_device,
        stable_lang,
    ]

    base = "|".join(parts)
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


# ============================================================
# FEATURES HISTORIQUES (depuis ClickHouse)
# RÈGLE MÉTIER:
# - LOGIN / LOGIN_ERROR = risque
# - APP_SESSION_STARTED = audit uniquement
# Toutes les features historiques de risque doivent donc se baser
# uniquement sur les événements LOGIN et LOGIN_ERROR.
# ============================================================

def build_identity_filter(user_id: str, username: str) -> str:
    clauses = []
    if user_id:
        clauses.append(f"user_id = '{sql_escape(user_id)}'")
    if username:
        clauses.append(f"username = '{sql_escape(username)}'")

    if not clauses:
        return "1 = 0"

    return "(" + " OR ".join(clauses) + ")"


def build_failure_filter(user_id: str, username: str, ip: str) -> str:
    identity_clauses = []
    if user_id:
        identity_clauses.append(f"user_id = '{sql_escape(user_id)}'")
    if username:
        identity_clauses.append(f"username = '{sql_escape(username)}'")

    if identity_clauses:
        return "(" + " OR ".join(identity_clauses) + ")"
    if ip:
        return f"(ip = '{sql_escape(ip)}')"
    return "1 = 0"


def count_login_errors_minutes(
    window_minutes: int,
    user_id: str = "",
    username: str = "",
    ip: str = "",
    ref_time: Optional[datetime] = None,
):
    base_time = ref_time or now_utc()
    since = base_time - timedelta(minutes=window_minutes)
    since, _ = apply_history_reset_floor(since=since, until=base_time)
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")
    until_str = base_time.strftime("%Y-%m-%d %H:%M:%S")
    match_filter = build_failure_filter(user_id, username, ip)

    sql = f"""
    SELECT count()
    FROM {TABLE}
    WHERE {match_filter}
      AND event_type = 'LOGIN_ERROR'
      AND event_time >= toDateTime('{since_str}')
      AND event_time <= toDateTime('{until_str}')
    """
    return int(ch_query(sql).strip() or "0")


def count_login_errors_hours(
    hours: int,
    user_id: str = "",
    username: str = "",
    ip: str = "",
    ref_time: Optional[datetime] = None,
):
    base_time = ref_time or now_utc()
    since = base_time - timedelta(hours=hours)
    since, _ = apply_history_reset_floor(since=since, until=base_time)
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")
    until_str = base_time.strftime("%Y-%m-%d %H:%M:%S")
    match_filter = build_failure_filter(user_id, username, ip)

    sql = f"""
    SELECT count()
    FROM {TABLE}
    WHERE {match_filter}
      AND event_type = 'LOGIN_ERROR'
      AND event_time >= toDateTime('{since_str}')
      AND event_time <= toDateTime('{until_str}')
    """
    return int(ch_query(sql).strip() or "0")


def login_count_hours(
    hours: int,
    user_id: str = "",
    username: str = "",
    ref_time: Optional[datetime] = None,
):
    base_time = ref_time or now_utc()
    since = base_time - timedelta(hours=hours)
    since, _ = apply_history_reset_floor(since=since, until=base_time)
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")
    until_str = base_time.strftime("%Y-%m-%d %H:%M:%S")
    identity_filter = build_identity_filter(user_id, username)

    sql = f"""
    SELECT count()
    FROM {TABLE}
    WHERE {identity_filter}
      AND event_type = 'LOGIN'
      AND event_success = 1
      AND {step_up_client_exclusion_sql()}
      AND event_time >= toDateTime('{since_str}')
      AND event_time <= toDateTime('{until_str}')
    """
    return int(ch_query(sql).strip() or "0")


def successful_login_count(
    user_id: str = "",
    username: str = "",
    ref_time: Optional[datetime] = None,
):
    identity_filter = build_identity_filter(user_id, username)
    if identity_filter == "1 = 0":
        return 0

    clauses = [
        identity_filter,
        "event_type = 'LOGIN'",
        "event_success = 1",
        step_up_client_exclusion_sql(),
    ]

    if HISTORY_RESET_AT is not None:
        reset_str = HISTORY_RESET_AT.strftime("%Y-%m-%d %H:%M:%S")
        clauses.append(f"event_time >= toDateTime('{reset_str}')")

    if ref_time is not None:
        until_str = ref_time.strftime("%Y-%m-%d %H:%M:%S")
        clauses.append(f"event_time <= toDateTime('{until_str}')")

    sql = f"""
    SELECT count()
    FROM {TABLE}
    WHERE {" AND ".join(clauses)}
    """
    return int(ch_query(sql).strip() or "0")


def normalize_risk_score_value(raw_score) -> Optional[float]:
    if raw_score in (None, "", "\\N"):
        return None

    try:
        score_value = float(raw_score)
    except Exception:
        return None

    if score_value > 1.0:
        score_value /= 100.0

    return round(max(0.0, min(1.0, score_value)), 4)


def get_recent_login_scoring(
    user_id: str = "",
    username: str = "",
    client_id: str = "",
    ip: str = "",
    ref_time: Optional[datetime] = None,
    lookback_minutes: int = RECENT_LOGIN_LOOKBACK_MINUTES,
    exclude_step_up_clients: bool = True,
):
    identity_filter = build_identity_filter(user_id, username)
    if identity_filter == "1 = 0":
        return None

    base_time = ref_time or now_utc()
    since = base_time - timedelta(minutes=max(1, lookback_minutes))
    since, _ = apply_history_reset_floor(since=since, until=base_time)
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")
    until_str = base_time.strftime("%Y-%m-%d %H:%M:%S")

    clauses = [
        identity_filter,
        "event_type = 'LOGIN'",
        "event_success = 1",
        f"event_time >= toDateTime('{since_str}')",
        f"event_time <= toDateTime('{until_str}')",
    ]

    if client_id:
        clauses.append(f"client_id = '{sql_escape(client_id)}'")
    if exclude_step_up_clients:
        clauses.append(step_up_client_exclusion_sql())
    if ip:
        clauses.append(f"ip = '{sql_escape(ip)}'")

    sql = f"""
    SELECT
      risk_score,
      risk_label,
      decision,
      required_factor,
      auth_path,
      policy_reason,
      distance_from_last_location_km,
      is_impossible_travel,
      is_new_ip_for_user,
      is_new_device
    FROM {TABLE}
    WHERE {" AND ".join(clauses)}
    ORDER BY event_time DESC
    LIMIT 1
    """

    result = ch_query(sql).strip()
    if not result:
        return None

    parts = result.split("\t")
    if len(parts) < 6:
        return None

    return {
        "risk_score": normalize_risk_score_value(parts[0]),
        "risk_label": parts[1] or "unknown",
        "decision": parts[2] or "ALLOW",
        "required_factor": parts[3] or "NONE",
        "auth_path": parts[4] or "SSO_ONLY",
        "policy_reason": parts[5] or "unknown_policy_reason",
        "distance_from_last_location_km": float(parts[6]) if len(parts) > 6 and parts[6] else None,
        "is_impossible_travel": int(parts[7]) if len(parts) > 7 and parts[7] else None,
        "is_new_ip_for_user": int(parts[8]) if len(parts) > 8 and parts[8] else None,
        "is_new_device": int(parts[9]) if len(parts) > 9 and parts[9] else None,
    }


def is_new_device(user_id: str, username: str, fp: str):
    identity_filter = build_identity_filter(user_id, username)
    time_filter = ""
    if HISTORY_RESET_AT is not None:
        reset_str = HISTORY_RESET_AT.strftime("%Y-%m-%d %H:%M:%S")
        time_filter = f"\n      AND event_time >= toDateTime('{reset_str}')"
    sql = f"""
    SELECT count()
    FROM {TABLE}
    WHERE {identity_filter}
      AND event_type = 'LOGIN'
      AND event_success = 1
      AND {step_up_client_exclusion_sql()}
      AND device_fp = '{sql_escape(fp)}'
      {time_filter}
    """
    return 1 if int(ch_query(sql).strip() or "0") == 0 else 0


def is_new_ip_for_user(user_id: str, username: str, ip: str):
    if not ip:
        return 0
    identity_filter = build_identity_filter(user_id, username)
    time_filter = ""
    if HISTORY_RESET_AT is not None:
        reset_str = HISTORY_RESET_AT.strftime("%Y-%m-%d %H:%M:%S")
        time_filter = f"\n      AND event_time >= toDateTime('{reset_str}')"
    sql = f"""
    SELECT count()
    FROM {TABLE}
    WHERE {identity_filter}
      AND event_type = 'LOGIN'
      AND event_success = 1
      AND {step_up_client_exclusion_sql()}
      AND ip = '{sql_escape(ip)}'
      {time_filter}
    """
    return 1 if int(ch_query(sql).strip() or "0") == 0 else 0


def get_last_distinct_successful_location(
    user_id: str,
    username: str,
    current_ip: str,
    current_lat: float,
    current_lon: float,
    trusted_only: bool = True,
):
    identity_filter = build_identity_filter(user_id, username)
    current_ip = sql_escape(current_ip)
    trust_filter = ""
    if trusted_only:
        trust_filter = """
      AND is_vpn_detected = 0
      AND is_proxy_detected = 0
      AND is_tor = 0
        """

    sql = f"""
    SELECT ip, geo_latitude, geo_longitude, event_time
    FROM {TABLE}
    WHERE {identity_filter}
      AND event_type = 'LOGIN'
      AND event_success = 1
      AND {step_up_client_exclusion_sql()}
      AND geo_latitude != 0
      AND geo_longitude != 0
      {trust_filter}
      {"AND event_time >= toDateTime('" + HISTORY_RESET_AT.strftime("%Y-%m-%d %H:%M:%S") + "')" if HISTORY_RESET_AT is not None else ""}
    ORDER BY event_time DESC
    LIMIT 10
    """
    result = ch_query(sql).strip()
    if not result:
        return None

    for row in result.splitlines():
        parts = row.split("\t")
        if len(parts) != 4:
            continue

        try:
            prev_ip = parts[0]
            prev_lat = float(parts[1])
            prev_lon = float(parts[2])
            prev_dt = datetime.strptime(parts[3], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            continue

        same_ip = prev_ip == current_ip
        same_coords = abs(prev_lat - current_lat) < 0.0001 and abs(prev_lon - current_lon) < 0.0001
        if same_ip and same_coords:
            continue

        return {
            "ip": prev_ip,
            "lat": prev_lat,
            "lon": prev_lon,
            "event_time": prev_dt,
        }

    return None


def app_sensitivity(client_id: str):
    mapping = {
        "portal-client-5": 1,
        "portal-main-client": 1,
        "portal-stepup-totp-client": 1,
        "crm-client-2": 2,
        "hr-client-4": 3,
        "finance-client-3": 4,
        "admin-console-client-1": 5,
    }
    return mapping.get(client_id, 0)


# ============================================================
# GÉO / IMPOSSIBLE TRAVEL
# ============================================================

def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)

    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return r * c


def compute_travel_features(
    user_id: str,
    username: str,
    current_ip: str,
    current_lat: float,
    current_lon: float,
    current_time: datetime,
):
    if current_lat == 0 or current_lon == 0:
        return 0.0, 0

    previous = get_last_distinct_successful_location(
        user_id=user_id,
        username=username,
        current_ip=current_ip,
        current_lat=current_lat,
        current_lon=current_lon,
        trusted_only=True,
    )
    if not previous:
        previous = get_last_distinct_successful_location(
            user_id=user_id,
            username=username,
            current_ip=current_ip,
            current_lat=current_lat,
            current_lon=current_lon,
            trusted_only=False,
        )

    if not previous:
        return 0.0, 0

    distance_km = haversine_km(previous["lat"], previous["lon"], current_lat, current_lon)
    delta_hours = max((current_time - previous["event_time"]).total_seconds() / 3600.0, 0.001)
    speed_kmh = distance_km / delta_hours
    is_impossible = 1 if distance_km >= 500 and speed_kmh >= 900 else 0
    return round(distance_km, 2), is_impossible


# ============================================================
# VPN / PROXY HEURISTICS
# ============================================================

def detect_vpn_proxy(ip_data: dict, geo_country_code: str):
    abuse = ip_data.get("abuseipdb", {}) or {}

    usage_type = str(abuse.get("usage_type", "") or "")
    isp_name = str(abuse.get("isp", "") or "")
    country_code = str(abuse.get("country_code", "") or geo_country_code or "")

    text = f"{usage_type} {isp_name}".lower()

    vpn_keywords = [
        "vpn", "hosting", "web hosting", "datacenter", "data center", "transit",
        "cloud", "server hosting", "colo", "colocation", "worldstream", "m247",
        "digitalocean", "hetzner", "ovh", "linode", "vultr", "contabo",
        "leaseweb", "hosted",
    ]

    proxy_keywords = [
        "proxy", "anonymous proxy", "public proxy", "forward proxy", "reverse proxy",
    ]

    isp_proxy_keywords = [
        "proxy", "vpn", "worldstream", "m247", "digitalocean", "hetzner",
        "ovh", "linode", "vultr", "contabo", "leaseweb", "hosted",
    ]

    usage_type_l = usage_type.lower()
    isp_name_l = isp_name.lower()

    is_vpn_detected = 1 if (
        any(k in text for k in vpn_keywords)
        or any(k in usage_type_l for k in ["hosting", "datacenter", "transit", "cloud"])
        or any(k in isp_name_l for k in isp_proxy_keywords)
    ) else 0

    is_proxy_detected = 1 if (
        any(k in text for k in proxy_keywords)
        or "proxy" in usage_type_l
        or "proxy" in isp_name_l
    ) else 0

    vpn_provider = isp_name if is_vpn_detected else ""
    proxy_provider = isp_name if is_proxy_detected else ""

    return {
        "is_vpn_detected": is_vpn_detected,
        "vpn_provider": vpn_provider,
        "is_proxy_detected": is_proxy_detected,
        "proxy_provider": proxy_provider,
        "abuse_country_code": country_code,
        "abuse_isp": isp_name,
        "abuse_usage_type": usage_type,
    }


# ============================================================
# RISK SCORING
# ============================================================

def score_event(features: dict) -> dict:
    default_response = {
        "risk_score": None,
        "risk_label": "unknown",
        "decision": "ALLOW",
        "required_factor": "NONE",
        "auth_path": "SSO_ONLY",
        "policy_reason": "scoring_disabled" if not SCORING_ENABLED else "not_called",
        "scoring_status": "disabled" if not SCORING_ENABLED else "not_called",
    }

    if not SCORING_ENABLED:
        return default_response

    try:
        response = _http.post(
            SCORING_URL,
            json=features,
            timeout=SCORING_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        normalized_score = normalize_risk_score_value(payload.get("risk_score"))
        return {
            "risk_score": normalized_score,
            "risk_label": payload.get("risk_label", "unknown"),
            "decision": payload.get("decision", "ALLOW"),
            "required_factor": payload.get("required_factor", "NONE"),
            "auth_path": payload.get("auth_path", "SSO_ONLY"),
            "policy_reason": payload.get("policy_reason", "unknown_policy_reason"),
            "scoring_status": "ok",
        }
    except Exception as e:
        print(f"[SCORING] Error calling scoring service: {e}")
        return {
            "risk_score": None,
            "risk_label": "unknown",
            "decision": "ALLOW",
            "required_factor": "NONE",
            "auth_path": "SSO_ONLY",
            "policy_reason": "scoring_error",
            "scoring_status": "error",
        }


# ============================================================
# INSERTION CLICKHOUSE
# ============================================================

def insert_event(row: dict):
    json_line = json.dumps(row, ensure_ascii=False)
    sql = f"INSERT INTO {TABLE} FORMAT JSONEachRow\n{json_line}\n"
    ch_query(sql)


# ============================================================
# BUILD CONTEXT / FEATURES
# ============================================================

def build_event_context(data: dict, req: Request, event_type: str = "ASSESS"):
    realm = data.get("realm", "")
    client_id = data.get("clientId", "")
    user_id = data.get("userId", "")
    error = data.get("error", "")
    details = data.get("details") or {}

    username = extract_username(data)

    ip = extract_real_ip(data, req)

    ua_raw = (
        data.get("http_user_agent")
        or details.get("user_agent")
        or details.get("userAgent")
        or details.get("user-agent")
        or req.headers.get("user-agent", "")
    )

    ch = extract_client_hints(data, req)
    ua_browser = infer_browser(ua_raw, ch)
    ua_os = infer_os(ua_raw, ch)
    ua_device = infer_device(ua_raw)

    event_time = parse_event_time(data)
    hour, dow, weekend = time_features(event_time)

    is_night_login = 1 if hour >= 22 or hour < 6 else 0
    is_business_hours = 1 if 8 <= hour <= 18 else 0

    if event_type == "LOGIN":
        event_success = 1 if not error else 0
    elif event_type == "LOGIN_ERROR":
        event_success = 0
    elif event_type in ["APP_SESSION_STARTED", "ASSESS", "LOGOUT"]:
        event_success = 1
    else:
        event_success = 0 if error else 1

    fp = device_fingerprint(
        ua_raw=ua_raw,
        ua_browser=ua_browser,
        ua_os=ua_os,
        ua_device=ua_device,
        ch=ch,
    )

    identity_available = bool(user_id or username)

    fails_5m = count_login_errors_minutes(5, user_id=user_id, username=username, ip=ip, ref_time=event_time)
    fails_1h = count_login_errors_hours(1, user_id=user_id, username=username, ip=ip, ref_time=event_time)
    fails_24h = count_login_errors_hours(24, user_id=user_id, username=username, ip=ip, ref_time=event_time)

    login_1h = 0
    new_dev = 0
    new_ip = 0
    prior_successful_logins = 0

    if identity_available:
        prior_successful_logins = successful_login_count(
            user_id=user_id,
            username=username,
            ref_time=event_time,
        )
        login_1h = login_count_hours(1, user_id=user_id, username=username, ref_time=event_time)

        if prior_successful_logins > 0:
            new_dev = is_new_device(user_id, username, fp)
            new_ip = is_new_ip_for_user(user_id, username, ip)

        if event_type == "LOGIN" and event_success == 1 and not is_step_up_client(client_id):
            login_1h += 1

    ip_data = enrich_ip(ip)
    abuse = ip_data.get("abuseipdb", {}) or {}
    geo = ip_data.get("geolite2", {}) or {}

    abuse_score = int(abuse.get("abuse_score", 0) or 0)
    is_tor = 1 if ip_data.get("is_tor_bulk") else 0

    geo_country = geo.get("country", "") or ""
    geo_country_code = geo.get("country_code", "") or ""
    geo_city = geo.get("city", "") or ""
    geo_postal_code = (
        geo.get("postal_code", "")
        or details.get("postal_code", "")
        or details.get("zip", "")
        or details.get("address_zip", "")
        or ""
    )
    geo_latitude = float(geo.get("latitude", 0.0) or 0.0)
    geo_longitude = float(geo.get("longitude", 0.0) or 0.0)
    geo_timezone = geo.get("timezone", "") or ""

    legacy_country = geo_country
    legacy_city = geo_city
    legacy_isp = abuse.get("isp", "") or ""
    legacy_org = abuse.get("usage_type", "") or ""

    asn_value = 0
    asn_org = ""
    for candidate in [geo.get("asn"), ip_data.get("asn")]:
        try:
            if candidate is not None and str(candidate).strip() != "":
                asn_value = int(candidate)
                break
        except Exception:
            pass

    for candidate in [geo.get("asn_org"), ip_data.get("asn_org"), abuse.get("isp")]:
        if candidate and str(candidate).strip():
            asn_org = str(candidate).strip()
            break

    vpn_proxy = detect_vpn_proxy(ip_data, geo_country_code)

    distance_from_last_location_km = 0.0
    is_impossible_travel = 0

    geo_available_for_travel = (
        event_type == "LOGIN"
        and event_success == 1
        and ip
        and is_public_ip(ip)
        and geo_country_code != ""
        and geo_latitude != 0
        and geo_longitude != 0
    )

    if geo_available_for_travel and identity_available:
        distance_from_last_location_km, is_impossible_travel = compute_travel_features(
            user_id=user_id,
            username=username,
            current_ip=ip,
            current_lat=geo_latitude,
            current_lon=geo_longitude,
            current_time=event_time,
        )

    app_sens = app_sensitivity(client_id)

    scoring_features = {
        "client_id": client_id or "unknown",
        "app_sensitivity": app_sens,
        "ua_browser": ua_browser or "unknown",
        "ua_os": ua_os or "unknown",
        "ua_device": ua_device or "unknown",
        "geo_country_code": geo_country_code or "unknown",
        "asn_org": asn_org or "unknown",
        "hour": hour,
        "day_of_week": dow,
        "is_weekend": weekend,
        "is_night_login": is_night_login,
        "is_business_hours": is_business_hours,
        "is_new_device": new_dev,
        "is_new_ip_for_user": new_ip,
        "fails_5m": fails_5m,
        "fails_1h": fails_1h,
        "fails_24h": fails_24h,
        "login_1h": login_1h,
        "is_vpn_detected": vpn_proxy["is_vpn_detected"],
        "is_proxy_detected": vpn_proxy["is_proxy_detected"],
        "is_tor": is_tor,
        "distance_from_last_location_km": distance_from_last_location_km,
        "is_impossible_travel": is_impossible_travel,
        "abuse_confidence_score": abuse_score,
    }

    return {
        "event_time": event_time,
        "realm": realm,
        "client_id": client_id,
        "user_id": user_id,
        "username": username,
        "event_type": event_type,
        "ip": ip,
        "error": error,
        "ua_raw": ua_raw,
        "ua_browser": ua_browser,
        "ua_os": ua_os,
        "ua_device": ua_device,
        "device_fp": fp,
        "is_new_device": new_dev,
        "is_new_ip_for_user": new_ip,
        "hour": hour,
        "day_of_week": dow,
        "is_weekend": weekend,
        "is_night_login": is_night_login,
        "is_business_hours": is_business_hours,
        "fails_5m": fails_5m,
        "fails_1h": fails_1h,
        "fails_24h": fails_24h,
        "login_1h": login_1h,
        "event_success": event_success,
        "app_sensitivity": app_sens,
        "country": legacy_country,
        "city": legacy_city,
        "isp": legacy_isp,
        "org": legacy_org,
        "asn": asn_value,
        "asn_org": asn_org,
        "is_tor": is_tor,
        "abuse_confidence_score": abuse_score,
        "geo_country": geo_country,
        "geo_city": geo_city,
        "geo_country_code": geo_country_code,
        "geo_postal_code": geo_postal_code,
        "geo_latitude": geo_latitude,
        "geo_longitude": geo_longitude,
        "geo_timezone": geo_timezone,
        "is_vpn_detected": vpn_proxy["is_vpn_detected"],
        "vpn_provider": vpn_proxy["vpn_provider"],
        "is_proxy_detected": vpn_proxy["is_proxy_detected"],
        "proxy_provider": vpn_proxy["proxy_provider"],
        "distance_from_last_location_km": distance_from_last_location_km,
        "is_impossible_travel": is_impossible_travel,
        "scoring_features": scoring_features,
        "abuse_details": abuse,
        "ip_enrichment": ip_data,
    }


def row_from_context(context: dict, scoring_result: Optional[dict] = None) -> dict:
    scoring_result = scoring_result or {
        "risk_score": None,
        "risk_label": "not_applicable",
        "decision": "NOT_SCORED",
        "required_factor": "NONE",
        "auth_path": "NONE",
        "policy_reason": "event_type_not_scored",
        "scoring_status": "skipped",
    }

    return {
        "event_time": context["event_time"].strftime("%Y-%m-%d %H:%M:%S"),
        "realm": context["realm"],
        "client_id": context["client_id"],
        "user_id": context["user_id"],
        "username": context["username"],
        "event_type": context["event_type"],
        "ip": context["ip"],
        "error": context["error"],
        "ua_raw": context["ua_raw"],
        "ua_browser": context["ua_browser"],
        "ua_os": context["ua_os"],
        "ua_device": context["ua_device"],
        "device_fp": context["device_fp"],
        "is_new_device": context["is_new_device"],
        "is_new_ip_for_user": context["is_new_ip_for_user"],
        "hour": context["hour"],
        "day_of_week": context["day_of_week"],
        "is_weekend": context["is_weekend"],
        "is_night_login": context["is_night_login"],
        "is_business_hours": context["is_business_hours"],
        "fails_5m": context["fails_5m"],
        "fails_1h": context["fails_1h"],
        "fails_24h": context["fails_24h"],
        "login_1h": context["login_1h"],
        "event_success": context["event_success"],
        "app_sensitivity": context["app_sensitivity"],
        "country": context["country"],
        "city": context["city"],
        "isp": context["isp"],
        "org": context["org"],
        "asn": context["asn"],
        "asn_org": context["asn_org"],
        "is_tor": context["is_tor"],
        "abuse_confidence_score": context["abuse_confidence_score"],
        "geo_country": context["geo_country"],
        "geo_city": context["geo_city"],
        "geo_country_code": context["geo_country_code"],
        "geo_postal_code": context["geo_postal_code"],
        "geo_latitude": context["geo_latitude"],
        "geo_longitude": context["geo_longitude"],
        "geo_timezone": context["geo_timezone"],
        "is_vpn_detected": context["is_vpn_detected"],
        "vpn_provider": context["vpn_provider"],
        "is_proxy_detected": context["is_proxy_detected"],
        "proxy_provider": context["proxy_provider"],
        "distance_from_last_location_km": context["distance_from_last_location_km"],
        "is_impossible_travel": context["is_impossible_travel"],
        "risk_score": scoring_result["risk_score"],
        "risk_label": scoring_result["risk_label"],
        "decision": scoring_result["decision"],
        "required_factor": scoring_result["required_factor"],
        "auth_path": scoring_result["auth_path"],
        "policy_reason": scoring_result["policy_reason"],
        "scoring_status": scoring_result["scoring_status"],
    }


INHERITED_RECENT_LOGIN_FEATURES = [
    "distance_from_last_location_km",
    "is_impossible_travel",
    "is_new_ip_for_user",
    "is_new_device",
]


def inherit_recent_login_features(context: dict, scoring_result: dict):
    for inherited_feature in INHERITED_RECENT_LOGIN_FEATURES:
        if scoring_result.get(inherited_feature) is None:
            continue

        context[inherited_feature] = scoring_result[inherited_feature]
        if inherited_feature in context.get("scoring_features", {}):
            context["scoring_features"][inherited_feature] = scoring_result[inherited_feature]


def as_completed_step_up_scoring(scoring_result: dict) -> dict:
    original_reason = scoring_result.get("policy_reason") or "unknown_policy_reason"
    original_decision = scoring_result.get("decision", "ALLOW")
    original_factor = scoring_result.get("required_factor", "NONE")

    can_complete_with_totp = (
        original_decision in {"ALLOW", "STEP_UP_TOTP"}
        or original_factor in {"NONE", "TOTP_OR_WEBAUTHN", "KEYCLOAK_TOTP"}
    )

    if not can_complete_with_totp:
        return {
            **scoring_result,
            "policy_reason": f"mfa_step_observed_without_downgrade_after_{original_reason}",
            "scoring_status": "mfa_step_inherited_recent_login",
        }

    return {
        **scoring_result,
        "decision": "ALLOW",
        "required_factor": "NONE",
        "auth_path": "MFA_COMPLETED",
        "policy_reason": f"adaptive_keycloak_totp_verified_after_{original_reason}",
        "scoring_status": "mfa_step_inherited_recent_login",
    }


def get_completed_step_up_scoring(context: dict) -> Optional[dict]:
    scoring_result = get_recent_login_scoring(
        user_id=context["user_id"],
        username=context["username"],
        client_id="",
        ip=context["ip"],
        ref_time=context["event_time"],
        lookback_minutes=STEP_UP_LOGIN_LOOKBACK_MINUTES,
        exclude_step_up_clients=True,
    )

    if not scoring_result:
        return None

    inherit_recent_login_features(context, scoring_result)
    return as_completed_step_up_scoring(scoring_result)


# ============================================================
# ROUTES
# ============================================================

@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "event-collector",
        "scoring_enabled": SCORING_ENABLED,
        "scoring_url": SCORING_URL,
        "clickhouse_db": CLICKHOUSE_DB,
        "clickhouse_table": TABLE,
    }


@app.get("/health")
def health():
    try:
        ch_query("SELECT 1")
        clickhouse_status = "ok"
    except Exception as e:
        clickhouse_status = f"error: {e}"

    return {
        "status": "ok",
        "service": "event-collector",
        "clickhouse": clickhouse_status,
    }


@app.post("/check-password")
async def check_password(req: Request):
    body = await req.json()
    password = body.get("password", "")
    exposure_count = is_password_pwned(password)
    return {
        "pwned": exposure_count > 0,
        "exposure_count": exposure_count,
        "message": "Mot de passe compromis !" if exposure_count > 0 else "OK",
    }


@app.post("/assess")
async def assess_event(req: Request):
    data = await req.json()
    context = build_event_context(data, req, event_type="ASSESS")
    scoring_result = get_recent_login_scoring(
        user_id=context["user_id"],
        username=context["username"],
        client_id=context["client_id"],
        ip=context["ip"],
        ref_time=context["event_time"],
    )

    if scoring_result:
        scoring_result = {
            **scoring_result,
            "scoring_status": "reused_recent_login",
        }
    else:
        scoring_result = score_event(context["scoring_features"])

    return {
        "status": "ok",
        "realm": context["realm"],
        "client_id": context["client_id"],
        "user_id": context["user_id"],
        "username": context["username"],
        "ip": context["ip"],
        "risk_score": scoring_result["risk_score"],
        "risk_label": scoring_result["risk_label"],
        "decision": scoring_result["decision"],
        "required_factor": scoring_result["required_factor"],
        "auth_path": scoring_result["auth_path"],
        "policy_reason": scoring_result["policy_reason"],
        "scoring_status": scoring_result["scoring_status"],
        "features_used": context["scoring_features"],
    }


@app.post("/events")
async def receive_event(req: Request):
    try:
        data = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = data.get("type", "") or "UNKNOWN"

    # LOGIN et LOGIN_ERROR uniquement pour le risque
    tracked_for_scoring = {"LOGIN", "LOGIN_ERROR"}

    context = build_event_context(data, req, event_type=event_type)

    if event_type == "LOGIN" and is_step_up_client(context["client_id"]):
        scoring_result = get_completed_step_up_scoring(context)
        if scoring_result is None:
            fallback_scoring = score_event(context["scoring_features"])
            scoring_result = {
                **fallback_scoring,
                "policy_reason": f"mfa_step_without_recent_login_{fallback_scoring['policy_reason']}",
                "scoring_status": "mfa_step_scored_without_recent_login",
            }
        row = row_from_context(context, scoring_result)
    elif event_type in tracked_for_scoring:
        scoring_result = score_event(context["scoring_features"])
        row = row_from_context(context, scoring_result)
    elif event_type == "APP_SESSION_STARTED":
        scoring_result = get_recent_login_scoring(
            user_id=context["user_id"],
            username=context["username"],
            client_id=context["client_id"],
            ip=context["ip"],
            ref_time=context["event_time"],
        )

        if scoring_result:
            inherit_recent_login_features(context, scoring_result)
            scoring_result = {
                **scoring_result,
                "scoring_status": "inherited_recent_login",
            }
            row = row_from_context(context, scoring_result)
        else:
            row = row_from_context(context, None)
            scoring_result = {
                "risk_score": None,
                "risk_label": "not_applicable",
                "decision": "NOT_SCORED",
                "required_factor": "NONE",
                "auth_path": "NONE",
                "policy_reason": "app_session_without_recent_login",
                "scoring_status": "skipped",
            }
    else:
        row = row_from_context(context, None)
        scoring_result = {
            "risk_score": None,
            "risk_label": "not_applicable",
            "decision": "NOT_SCORED",
            "required_factor": "NONE",
            "auth_path": "NONE",
            "policy_reason": "audit_only_event",
            "scoring_status": "skipped",
        }

    insert_event(row)

    return {
        "status": "ok",
        "stored": True,
        "features": row,
        "scoring": scoring_result,
    }
