import hashlib
import math
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

RAW_OUTPUT_PATH = DATA_DIR / "synthetic_login_events_raw.csv"
OUTPUT_PATH = DATA_DIR / "synthetic_risk_dataset.csv"

REALM = "PFE-SSO"
TOTAL_USERS = 64
START_DAYS_AGO = 75
RANDOM_SEED = 42

RISK_CLASS_MAP = {
    "low": 0,
    "moderate": 1,
    "high": 2,
    "critical": 3,
}

CLASS_TARGETS = {
    "low": 320,
    "moderate": 180,
    "high": 100,
    "critical": 60,
}

CLIENT_SENSITIVITY = {
    "portal-main-client": 1,
    "crm-client-2": 2,
    "hr-client-4": 3,
    "finance-client-3": 4,
    "admin-console-client-1": 5,
}

CLIENTS = list(CLIENT_SENSITIVITY.keys())

POLICY_BY_LABEL = {
    "low": {
        "decision": "ALLOW",
        "required_factor": "NONE",
        "auth_path": "SSO_ONLY",
        "policy_reason": "synthetic_rule_low",
    },
    "moderate": {
        "decision": "STEP_UP_TOTP",
        "required_factor": "TOTP_OR_WEBAUTHN",
        "auth_path": "SECOND_FACTOR",
        "policy_reason": "synthetic_rule_moderate",
    },
    "high": {
        "decision": "STEP_UP_BIOMETRIC",
        "required_factor": "FACE_RECOGNITION",
        "auth_path": "BIOMETRIC_FACTOR",
        "policy_reason": "synthetic_rule_high",
    },
    "critical": {
        "decision": "BLOCK_REVIEW",
        "required_factor": "ADMIN_REVIEW",
        "auth_path": "TEMP_BLOCK",
        "policy_reason": "synthetic_rule_critical",
    },
}

LOCATION_PROFILES = {
    "tunis_ati": {
        "country": "Tunisia",
        "city": "Tunis",
        "country_code": "TN",
        "postal_code": "1000",
        "latitude": 36.8065,
        "longitude": 10.1815,
        "timezone": "Africa/Tunis",
        "isp": "ATI - Agence Tunisienne Internet",
        "org": "Fixed ISP",
        "asn_org": "ATI - Agence Tunisienne Internet",
        "asn": 37705,
        "ip_prefixes": ["197.25.125", "197.25.126", "197.25.127"],
        "is_vpn_detected": 0,
        "vpn_provider": "",
        "is_proxy_detected": 0,
        "proxy_provider": "",
    },
    "aryanah_orange": {
        "country": "Tunisia",
        "city": "Aryanah",
        "country_code": "TN",
        "postal_code": "2080",
        "latitude": 36.8625,
        "longitude": 10.1956,
        "timezone": "Africa/Tunis",
        "isp": "Orange Tunisie",
        "org": "Mobile ISP",
        "asn_org": "Orange Tunisie",
        "asn": 37492,
        "ip_prefixes": ["165.51.134", "196.176.199", "41.224.23"],
        "is_vpn_detected": 0,
        "vpn_provider": "",
        "is_proxy_detected": 0,
        "proxy_provider": "",
    },
    "sfax_topnet": {
        "country": "Tunisia",
        "city": "Sfax",
        "country_code": "TN",
        "postal_code": "3000",
        "latitude": 34.7406,
        "longitude": 10.7603,
        "timezone": "Africa/Tunis",
        "isp": "TOPNET",
        "org": "Broadband ISP",
        "asn_org": "TOPNET",
        "asn": 37704,
        "ip_prefixes": ["41.231.55", "41.228.117"],
        "is_vpn_detected": 0,
        "vpn_provider": "",
        "is_proxy_detected": 0,
        "proxy_provider": "",
    },
    "paris_orange": {
        "country": "France",
        "city": "Paris",
        "country_code": "FR",
        "postal_code": "75001",
        "latitude": 48.8566,
        "longitude": 2.3522,
        "timezone": "Europe/Paris",
        "isp": "Orange S.A.",
        "org": "Residential ISP",
        "asn_org": "Orange S.A.",
        "asn": 3215,
        "ip_prefixes": ["90.84.114", "81.249.32"],
        "is_vpn_detected": 0,
        "vpn_provider": "",
        "is_proxy_detected": 0,
        "proxy_provider": "",
    },
    "frankfurt_dt": {
        "country": "Germany",
        "city": "Frankfurt",
        "country_code": "DE",
        "postal_code": "60311",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "timezone": "Europe/Berlin",
        "isp": "Deutsche Telekom AG",
        "org": "Residential ISP",
        "asn_org": "Deutsche Telekom AG",
        "asn": 3320,
        "ip_prefixes": ["87.152.220", "93.192.54"],
        "is_vpn_detected": 0,
        "vpn_provider": "",
        "is_proxy_detected": 0,
        "proxy_provider": "",
    },
    "amsterdam_vpn": {
        "country": "The Netherlands",
        "city": "Amsterdam",
        "country_code": "NL",
        "postal_code": "1012",
        "latitude": 52.3676,
        "longitude": 4.9041,
        "timezone": "Europe/Amsterdam",
        "isp": "JSC Ukrtelecom",
        "org": "Data Center/Web Hosting/Transit",
        "asn_org": "JSC Ukrtelecom",
        "asn": 3257,
        "ip_prefixes": ["95.135.253", "185.107.56"],
        "is_vpn_detected": 1,
        "vpn_provider": "JSC Ukrtelecom",
        "is_proxy_detected": 0,
        "proxy_provider": "",
        "is_tor": 0,
    },
    "roubaix_proxy": {
        "country": "France",
        "city": "Roubaix",
        "country_code": "FR",
        "postal_code": "59100",
        "latitude": 50.6927,
        "longitude": 3.1778,
        "timezone": "Europe/Paris",
        "isp": "OVH SAS",
        "org": "Data Center",
        "asn_org": "OVH SAS",
        "asn": 16276,
        "ip_prefixes": ["51.68.77", "146.59.14"],
        "is_vpn_detected": 1,
        "vpn_provider": "OVH SAS",
        "is_proxy_detected": 1,
        "proxy_provider": "OVH Proxy",
        "is_tor": 0,
    },
    "ashburn_cloud": {
        "country": "United States",
        "city": "Ashburn",
        "country_code": "US",
        "postal_code": "20147",
        "latitude": 39.0438,
        "longitude": -77.4874,
        "timezone": "America/New_York",
        "isp": "Amazon Data Services",
        "org": "Cloud / Hosting",
        "asn_org": "Amazon Data Services",
        "asn": 14618,
        "ip_prefixes": ["3.217.12", "52.70.191"],
        "is_vpn_detected": 1,
        "vpn_provider": "Amazon Cloud",
        "is_proxy_detected": 1,
        "proxy_provider": "Cloud Proxy",
        "is_tor": 0,
    },
    "berlin_tor": {
        "country": "Germany",
        "city": "Berlin",
        "country_code": "DE",
        "postal_code": "10115",
        "latitude": 52.52,
        "longitude": 13.405,
        "timezone": "Europe/Berlin",
        "isp": "Tor Exit Relay",
        "org": "Tor Network Exit Node",
        "asn_org": "Tor Exit Relay",
        "asn": 0,
        "ip_prefixes": ["185.220.101", "185.220.102"],
        "is_vpn_detected": 1,
        "vpn_provider": "Tor Network",
        "is_proxy_detected": 1,
        "proxy_provider": "Tor Exit Proxy",
        "is_tor": 1,
    },
}

HOME_LOCATION_KEYS = [
    "tunis_ati",
    "aryanah_orange",
    "sfax_topnet",
    "paris_orange",
    "frankfurt_dt",
]

ANOMALY_LOCATION_KEYS = [
    "amsterdam_vpn",
    "roubaix_proxy",
    "ashburn_cloud",
    "berlin_tor",
]

DEVICE_TEMPLATES = {
    "brave_windows_11_pc": {
        "ua_browser": "Brave 146.0.0.0",
        "ua_os": "Windows 11",
        "ua_device": "pc",
        "ua_raw": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
        ),
    },
    "chrome_windows_11_laptop": {
        "ua_browser": "Chrome 146.0.0.0",
        "ua_os": "Windows 11",
        "ua_device": "laptop",
        "ua_raw": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
        ),
    },
    "edge_windows_11_laptop": {
        "ua_browser": "Edge 146.0.0.0",
        "ua_os": "Windows 11",
        "ua_device": "laptop",
        "ua_raw": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0"
        ),
    },
    "firefox_ubuntu_laptop": {
        "ua_browser": "Firefox 138.0",
        "ua_os": "Ubuntu",
        "ua_device": "laptop",
        "ua_raw": (
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) "
            "Gecko/20100101 Firefox/138.0"
        ),
    },
    "firefox_macos_laptop": {
        "ua_browser": "Firefox 138.0",
        "ua_os": "macOS",
        "ua_device": "laptop",
        "ua_raw": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:138.0) "
            "Gecko/20100101 Firefox/138.0"
        ),
    },
    "facebook_ios_mobile": {
        "ua_browser": "Facebook 555.0.0",
        "ua_os": "iOS 18.7",
        "ua_device": "mobile",
        "ua_raw": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 "
            "[FBAN/FBIOS;FBAV/555.0.0.37.106;FBBV/923361586;FBDV/iPhone12,1;"
            "FBMD=iPhone;FBSN=iOS;FBSV=18.7;FBSS=2;FBLC=en_US;FBOP=80]"
        ),
    },
    "chrome_android_mobile": {
        "ua_browser": "Chrome 146.0.0.0",
        "ua_os": "Android 15",
        "ua_device": "mobile",
        "ua_raw": (
            "Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"
        ),
    },
}

USER_ARCHETYPES = [
    {
        "name": "portal_employee",
        "client_weights": {
            "portal-main-client": 0.62,
            "crm-client-2": 0.18,
            "hr-client-4": 0.14,
            "finance-client-3": 0.04,
            "admin-console-client-1": 0.02,
        },
        "home_weights": [0.46, 0.34, 0.14, 0.04, 0.02],
        "device_weights": {
            "brave_windows_11_pc": 0.56,
            "chrome_windows_11_laptop": 0.22,
            "edge_windows_11_laptop": 0.10,
            "firefox_ubuntu_laptop": 0.06,
            "chrome_android_mobile": 0.06,
        },
    },
    {
        "name": "finance_officer",
        "client_weights": {
            "portal-main-client": 0.18,
            "crm-client-2": 0.10,
            "hr-client-4": 0.05,
            "finance-client-3": 0.52,
            "admin-console-client-1": 0.15,
        },
        "home_weights": [0.36, 0.28, 0.08, 0.14, 0.14],
        "device_weights": {
            "brave_windows_11_pc": 0.34,
            "chrome_windows_11_laptop": 0.30,
            "edge_windows_11_laptop": 0.20,
            "firefox_macos_laptop": 0.10,
            "chrome_android_mobile": 0.06,
        },
    },
    {
        "name": "hr_specialist",
        "client_weights": {
            "portal-main-client": 0.24,
            "crm-client-2": 0.08,
            "hr-client-4": 0.54,
            "finance-client-3": 0.08,
            "admin-console-client-1": 0.06,
        },
        "home_weights": [0.42, 0.28, 0.18, 0.07, 0.05],
        "device_weights": {
            "brave_windows_11_pc": 0.28,
            "chrome_windows_11_laptop": 0.28,
            "edge_windows_11_laptop": 0.16,
            "firefox_macos_laptop": 0.16,
            "chrome_android_mobile": 0.12,
        },
    },
    {
        "name": "admin_operator",
        "client_weights": {
            "portal-main-client": 0.12,
            "crm-client-2": 0.08,
            "hr-client-4": 0.05,
            "finance-client-3": 0.20,
            "admin-console-client-1": 0.55,
        },
        "home_weights": [0.30, 0.18, 0.07, 0.20, 0.25],
        "device_weights": {
            "edge_windows_11_laptop": 0.34,
            "chrome_windows_11_laptop": 0.26,
            "brave_windows_11_pc": 0.18,
            "firefox_ubuntu_laptop": 0.12,
            "chrome_android_mobile": 0.10,
        },
    },
    {
        "name": "mobile_sales",
        "client_weights": {
            "portal-main-client": 0.50,
            "crm-client-2": 0.32,
            "hr-client-4": 0.08,
            "finance-client-3": 0.06,
            "admin-console-client-1": 0.04,
        },
        "home_weights": [0.34, 0.28, 0.18, 0.12, 0.08],
        "device_weights": {
            "facebook_ios_mobile": 0.40,
            "chrome_android_mobile": 0.26,
            "brave_windows_11_pc": 0.16,
            "chrome_windows_11_laptop": 0.10,
            "firefox_ubuntu_laptop": 0.08,
        },
    },
]

FIRST_NAMES = [
    "Ahmed", "Yasmine", "Amine", "Sarra", "Nour", "Meriem", "Walid", "Salma",
    "Hatem", "Ines", "Omar", "Lina", "Rania", "Sami", "Alya", "Karim",
    "Maya", "Nidhal", "Aya", "Rim", "Tarek", "Moez", "Farah", "Aymen",
]
LAST_NAMES = [
    "BenAli", "Trabelsi", "Bouzid", "Jaziri", "Gharbi", "Hammami", "Khelifi",
    "Nafti", "Chaabane", "Mejri", "Masmoudi", "Khadraoui", "Abid", "Amri",
]
EMAIL_DOMAINS = ["example.tn", "corp.local", "pfe-sso.test", "mail.test"]


@dataclass
class UserProfile:
    user_id: str
    username: str
    archetype: str
    home_location_key: str
    alternate_location_keys: list[str]
    client_weights: dict
    device_weights: dict
    baseline_start: datetime


@dataclass
class UserState:
    history: list = field(default_factory=list)
    devices: list = field(default_factory=list)
    seen_ips: set = field(default_factory=set)


def weighted_choice(mapping: dict) -> str:
    items = list(mapping.items())
    population = [key for key, _ in items]
    weights = [value for _, value in items]
    return random.choices(population, weights=weights, k=1)[0]


def random_username(index: int) -> str:
    first = random.choice(FIRST_NAMES).lower()
    last = random.choice(LAST_NAMES).lower()
    if random.random() < 0.58:
        return f"{first}.{last}{index}@{random.choice(EMAIL_DOMAINS)}"
    return f"{first}{last}{index}"


def build_user_profiles() -> list:
    profiles = []
    base_start = datetime.now() - timedelta(days=START_DAYS_AGO)

    for index in range(TOTAL_USERS):
        archetype = random.choice(USER_ARCHETYPES)
        home_location_key = random.choices(
            HOME_LOCATION_KEYS,
            weights=archetype["home_weights"],
            k=1,
        )[0]
        alternate_location_keys = [
            key for key in HOME_LOCATION_KEYS if key != home_location_key
        ]
        random.shuffle(alternate_location_keys)

        baseline_start = base_start + timedelta(
            hours=random.randint(0, START_DAYS_AGO * 24 // 2)
        )

        profiles.append(
            UserProfile(
                user_id=str(uuid.uuid4()),
                username=random_username(index),
                archetype=archetype["name"],
                home_location_key=home_location_key,
                alternate_location_keys=alternate_location_keys[:3],
                client_weights=archetype["client_weights"],
                device_weights=archetype["device_weights"],
                baseline_start=baseline_start,
            )
        )

    return profiles


def get_primary_device_key(profile: UserProfile) -> str:
    return weighted_choice(profile.device_weights)


def create_device_instance(profile: UserProfile, state: UserState, device_key: str):
    slot = 1 + sum(1 for item in state.devices if item["device_key"] == device_key)
    fingerprint = hashlib.sha256(
        f"{profile.user_id}|{device_key}|{slot}".encode("utf-8")
    ).hexdigest()
    instance = {
        "device_key": device_key,
        "device_fp": fingerprint,
    }
    state.devices.append(instance)
    return instance


def choose_device_instance(
    profile: UserProfile,
    state: UserState,
    target_label: str,
):
    if not state.devices:
        return create_device_instance(profile, state, get_primary_device_key(profile)), 0

    new_device_probabilities = {
        "low": 0.03,
        "moderate": 0.24,
        "high": 0.48,
        "critical": 0.66,
    }
    should_create_new = random.random() < new_device_probabilities[target_label]

    if not should_create_new:
        return random.choice(state.devices), 0

    available_device_keys = list(DEVICE_TEMPLATES.keys())
    if target_label in {"high", "critical"} and random.random() < 0.55:
        known_keys = {item["device_key"] for item in state.devices}
        alternative_keys = [key for key in available_device_keys if key not in known_keys]
        device_key = random.choice(alternative_keys or available_device_keys)
    else:
        device_key = get_primary_device_key(profile)

    return create_device_instance(profile, state, device_key), 1


def choose_location_key(profile: UserProfile, target_label: str) -> str:
    if target_label == "low":
        choices = [profile.home_location_key] + profile.alternate_location_keys[:2]
        weights = [0.85, 0.10, 0.05][: len(choices)]
        return random.choices(choices, weights=weights, k=1)[0]

    if target_label == "moderate":
        if random.random() < 0.68:
            choices = [profile.home_location_key] + profile.alternate_location_keys[:2]
            weights = [0.55, 0.30, 0.15][: len(choices)]
            return random.choices(choices, weights=weights, k=1)[0]
        return random.choice(ANOMALY_LOCATION_KEYS)

    if target_label == "high":
        if random.random() < 0.45:
            return random.choice(profile.alternate_location_keys[:2] or [profile.home_location_key])
        return random.choice(ANOMALY_LOCATION_KEYS)

    return random.choice(ANOMALY_LOCATION_KEYS)


def generate_ip(location_key: str) -> str:
    location = LOCATION_PROFILES[location_key]
    prefix = random.choice(location["ip_prefixes"])
    last_octet = random.randint(2, 250)
    return f"{prefix}.{last_octet}"


def choose_ip(profile: UserProfile, state: UserState, target_label: str, location_key: str):
    if not state.history:
        ip = generate_ip(location_key)
        return ip, 0

    new_ip_probabilities = {
        "low": 0.04,
        "moderate": 0.28,
        "high": 0.52,
        "critical": 0.70,
    }
    should_use_new_ip = random.random() < new_ip_probabilities[target_label]

    known_ips = [
        item["ip"]
        for item in state.history
        if item["location_key"] == location_key and item["event_success"] == 1
    ]

    if known_ips and not should_use_new_ip:
        return random.choice(known_ips), 0

    if not known_ips and random.random() < 0.45 and state.seen_ips:
        return random.choice(list(state.seen_ips)), 0

    ip = generate_ip(location_key)
    return ip, 1 if ip not in state.seen_ips else 0


def sample_hour(target_label: str) -> int:
    if target_label == "low":
        weights = [
            1, 1, 1, 1, 1, 1,
            2, 4, 7, 10, 10, 10,
            10, 10, 9, 8, 7, 6,
            4, 3, 2, 1, 1, 1,
        ]
    elif target_label == "moderate":
        weights = [
            2, 2, 2, 2, 2, 2,
            3, 4, 6, 8, 8, 8,
            8, 8, 7, 7, 6, 5,
            5, 4, 4, 3, 3, 3,
        ]
    elif target_label == "high":
        weights = [
            4, 4, 4, 4, 4, 4,
            3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3,
            4, 4, 5, 5, 5, 5,
        ]
    else:
        weights = [
            7, 7, 7, 7, 6, 6,
            4, 3, 2, 1, 1, 1,
            1, 1, 1, 1, 1, 2,
            3, 4, 5, 6, 7, 7,
        ]

    return random.choices(list(range(24)), weights=weights, k=1)[0]


def next_event_time(profile: UserProfile, state: UserState, target_label: str) -> datetime:
    last_event_time = state.history[-1]["event_time"] if state.history else profile.baseline_start

    if target_label == "low":
        delta = timedelta(hours=random.randint(8, 72), minutes=random.randint(0, 59))
    elif target_label == "moderate":
        delta = timedelta(hours=random.randint(2, 36), minutes=random.randint(0, 59))
    elif target_label == "high":
        delta = timedelta(minutes=random.randint(12, 360))
    else:
        delta = timedelta(minutes=random.randint(1, 75))

    candidate = last_event_time + delta
    sampled_hour = sample_hour(target_label)
    sampled_minute = random.randint(0, 59)
    sampled_second = random.randint(0, 59)
    candidate = candidate.replace(
        hour=sampled_hour,
        minute=sampled_minute,
        second=sampled_second,
        microsecond=0,
    )

    if candidate <= last_event_time:
        candidate = last_event_time + timedelta(minutes=random.randint(5, 90))

    now = datetime.now()
    if candidate > now:
        candidate = now - timedelta(minutes=random.randint(1, 30))

    return candidate


def count_recent_logins(state: UserState, current_time: datetime, hours: int) -> int:
    lower_bound = current_time - timedelta(hours=hours)
    return sum(
        1
        for item in state.history
        if item["event_success"] == 1 and item["event_time"] >= lower_bound
    )


def sample_fail_counts(
    target_label: str,
    app_sensitivity: int,
    login_1h: int,
    is_new_device: int,
    is_new_ip_for_user: int,
):
    anomaly_count = is_new_device + is_new_ip_for_user

    if target_label == "low":
        fails_5m = random.choices([0, 1], weights=[88, 12], k=1)[0]
        fails_1h = random.randint(fails_5m, max(1, fails_5m + 1))
        fails_24h = random.randint(fails_1h, fails_1h + 2)
        return fails_5m, fails_1h, fails_24h

    if target_label == "moderate":
        if app_sensitivity >= 4 and anomaly_count == 0:
            fails_5m = random.randint(0, 1)
            fails_1h = random.randint(max(2, fails_5m), 3)
        else:
            fails_5m = random.randint(0, 2)
            fails_1h = random.randint(max(1, fails_5m), 3)
        fails_24h = random.randint(fails_1h, max(fails_1h + 3, login_1h + 1))
        return fails_5m, fails_1h, fails_24h

    if target_label == "high":
        if anomaly_count >= 2 and app_sensitivity >= 4:
            fails_5m = random.randint(0, 2)
            fails_1h = random.randint(2, 4)
        else:
            fails_5m = random.randint(2, 4)
            fails_1h = random.randint(max(3, fails_5m), 6)
        fails_24h = random.randint(fails_1h + 1, max(7, fails_1h + 5))
        return fails_5m, fails_1h, fails_24h

    if app_sensitivity >= 5 and anomaly_count >= 2:
        fails_5m = random.randint(2, 5)
        fails_1h = random.randint(2, 6)
    else:
        fails_5m = random.randint(4, 6)
        fails_1h = random.randint(max(5, fails_5m), 9)
    fails_24h = random.randint(max(8, fails_1h), fails_1h + 8)
    return fails_5m, fails_1h, fails_24h


def choose_client_id(profile: UserProfile, target_label: str) -> str:
    client_weights = profile.client_weights.copy()

    if target_label == "high":
        client_weights["finance-client-3"] += 0.10
        client_weights["admin-console-client-1"] += 0.10
    if target_label == "critical":
        client_weights["finance-client-3"] += 0.14
        client_weights["admin-console-client-1"] += 0.18
        client_weights["portal-main-client"] = max(
            0.06,
            client_weights["portal-main-client"] - 0.08,
        )

    total = sum(client_weights.values())
    normalized = {key: value / total for key, value in client_weights.items()}
    return weighted_choice(normalized)


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(d_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return radius * c


def compute_geo_features(state: UserState, current_time: datetime, location_key: str):
    location = LOCATION_PROFILES[location_key]

    if not state.history:
        return 0.0, 0

    last_success = next(
        (item for item in reversed(state.history) if item["event_success"] == 1),
        None,
    )
    if not last_success:
        return 0.0, 0

    previous_location = LOCATION_PROFILES[last_success["location_key"]]
    distance_km = haversine_distance_km(
        previous_location["latitude"],
        previous_location["longitude"],
        location["latitude"],
        location["longitude"],
    )

    hours_since_last = max(
        (current_time - last_success["event_time"]).total_seconds() / 3600.0,
        0.01,
    )
    impossible_travel = 1 if distance_km > 500 and (distance_km / hours_since_last) > 900 else 0

    return round(distance_km, 2), impossible_travel


def stable_unit_interval(value: str) -> float:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) / 0xFFFFFFFF


def assign_risk_label(row: dict) -> str:
    score = float(row.get("synthetic_rule_score", compute_synthetic_rule_score(row)))
    if score >= 0.70:
        return "critical"
    if score >= 0.48:
        return "high"
    if score >= 0.26:
        return "moderate"
    return "low"


def compute_synthetic_rule_score(row: dict) -> float:
    anomaly_count = int(row["is_new_device"]) + int(row["is_new_ip_for_user"])
    app_norm = max(0.0, min(1.0, (int(row["app_sensitivity"]) - 1) / 4.0))
    fail_pressure = min(
        1.0,
        0.20 * min(int(row["fails_5m"]) / 6.0, 1.0)
        + 0.45 * min(int(row["fails_1h"]) / 8.0, 1.0)
        + 0.35 * min(int(row["fails_24h"]) / 12.0, 1.0),
    )
    velocity_pressure = min(
        1.0,
        0.65 * min(int(row["login_1h"]) / 5.0, 1.0)
        + 0.35 * min(anomaly_count / 2.0, 1.0),
    )
    network_pressure = min(
        1.0,
        0.20 * int(row["is_vpn_detected"])
        + 0.25 * int(row["is_proxy_detected"])
        + 0.35 * int(row["is_tor"])
        + 0.20 * min(int(row["abuse_confidence_score"]) / 100.0, 1.0),
    )
    geo_pressure = min(
        1.0,
        0.65 * min(float(row["distance_from_last_location_km"]) / 2000.0, 1.0)
        + 0.35 * int(row["is_impossible_travel"]),
    )
    temporal_pressure = min(
        1.0,
        0.60 * int(row["is_night_login"]) + 0.40 * (1 - int(row["is_business_hours"])),
    )
    hidden_user_risk = stable_unit_interval(f"{row['user_id']}|{row['username']}")
    score = (
        0.04
        + 0.28 * fail_pressure
        + 0.16 * velocity_pressure
        + 0.12 * min(anomaly_count / 2.0, 1.0)
        + 0.12 * network_pressure
        + 0.11 * geo_pressure
        + 0.08 * app_norm
        + 0.05 * temporal_pressure
        + 0.08 * hidden_user_risk
        + random.uniform(-0.05, 0.05)
    )
    return round(max(0.0, min(0.99, score)), 4)


def build_candidate_event(profile: UserProfile, state: UserState, target_label: str) -> dict:
    current_time = next_event_time(profile, state, target_label)
    client_id = choose_client_id(profile, target_label)
    app_sensitivity = CLIENT_SENSITIVITY[client_id]

    device_instance, suggested_new_device = choose_device_instance(profile, state, target_label)
    device_template = DEVICE_TEMPLATES[device_instance["device_key"]]

    location_key = choose_location_key(profile, target_label)
    ip, suggested_new_ip = choose_ip(profile, state, target_label, location_key)

    prior_success_count = sum(1 for item in state.history if item["event_success"] == 1)
    is_new_device = 1 if prior_success_count > 0 and suggested_new_device == 1 else 0
    is_new_ip_for_user = 1 if prior_success_count > 0 and suggested_new_ip == 1 else 0

    hour = current_time.hour
    day_of_week = current_time.isoweekday()
    is_weekend = 1 if day_of_week in [6, 7] else 0
    is_night_login = 1 if hour >= 22 or hour < 6 else 0
    is_business_hours = 1 if 8 <= hour <= 18 else 0

    login_1h = count_recent_logins(state, current_time, hours=1) + 1
    fails_5m, fails_1h, fails_24h = sample_fail_counts(
        target_label=target_label,
        app_sensitivity=app_sensitivity,
        login_1h=login_1h,
        is_new_device=is_new_device,
        is_new_ip_for_user=is_new_ip_for_user,
    )

    distance_km, impossible_travel = compute_geo_features(state, current_time, location_key)
    location = LOCATION_PROFILES[location_key]

    row = {
        "event_time": current_time,
        "realm": REALM,
        "client_id": client_id,
        "user_id": profile.user_id,
        "username": profile.username,
        "event_type": "LOGIN",
        "ip": ip,
        "error": "",
        "ua_raw": device_template["ua_raw"],
        "ua_browser": device_template["ua_browser"],
        "ua_os": device_template["ua_os"],
        "ua_device": device_template["ua_device"],
        "device_fp": device_instance["device_fp"],
        "is_new_device": is_new_device,
        "hour": hour,
        "day_of_week": day_of_week,
        "is_weekend": is_weekend,
        "is_night_login": is_night_login,
        "is_business_hours": is_business_hours,
        "fails_5m": fails_5m,
        "fails_1h": fails_1h,
        "fails_24h": fails_24h,
        "login_1h": login_1h,
        "event_success": 1,
        "app_sensitivity": app_sensitivity,
        "country": location["country"],
        "city": location["city"],
        "isp": location["isp"],
        "org": location["org"],
        "asn": location["asn"],
        "is_tor": location.get("is_tor", 0),
        "abuse_confidence_score": (
            random.randint(40, 95)
            if location.get("is_tor", 0)
            else random.randint(18, 75)
            if location["is_proxy_detected"]
            else random.randint(0, 20)
            if location["is_vpn_detected"]
            else random.randint(0, 8)
        ),
        "geo_country": location["country"],
        "geo_city": location["city"],
        "geo_country_code": location["country_code"],
        "geo_postal_code": location["postal_code"],
        "geo_latitude": location["latitude"],
        "geo_longitude": location["longitude"],
        "geo_timezone": location["timezone"],
        "asn_org": location["asn_org"],
        "is_vpn_detected": location["is_vpn_detected"],
        "vpn_provider": location["vpn_provider"],
        "is_proxy_detected": location["is_proxy_detected"],
        "proxy_provider": location["proxy_provider"],
        "distance_from_last_location_km": distance_km,
        "is_impossible_travel": impossible_travel,
        "is_new_ip_for_user": is_new_ip_for_user,
        "location_key": location_key,
        "data_origin": "synthetic",
    }

    row["synthetic_rule_score"] = compute_synthetic_rule_score(row)
    row["risk_label"] = assign_risk_label(row)
    row["risk_class"] = RISK_CLASS_MAP[row["risk_label"]]
    row["source_risk_score"] = None
    row["source_risk_label"] = row["risk_label"]
    policy = POLICY_BY_LABEL[row["risk_label"]]
    row["source_decision"] = policy["decision"]
    row["source_policy_reason"] = policy["policy_reason"]
    row["decision"] = policy["decision"]
    row["scoring_status"] = "ok"
    row["required_factor"] = policy["required_factor"]
    row["auth_path"] = policy["auth_path"]
    row["policy_reason"] = policy["policy_reason"]

    return row


def commit_event(state: UserState, event: dict):
    state.history.append(event)
    state.seen_ips.add(event["ip"])


def pick_profile_for_label(profiles: list, states: dict, target_label: str) -> UserProfile:
    if target_label == "low":
        return random.choice(profiles)

    eligible = [profile for profile in profiles if states[profile.user_id].history]
    if target_label in {"high", "critical"}:
        weighted = sorted(
            eligible,
            key=lambda profile: (
                len(states[profile.user_id].history),
                CLIENT_SENSITIVITY[max(profile.client_weights, key=profile.client_weights.get)],
            ),
            reverse=True,
        )
        top_slice = weighted[: max(8, len(weighted) // 3)]
        return random.choice(top_slice)

    return random.choice(eligible or profiles)


def warmup_low_events(profiles: list, states: dict):
    rows = []
    for profile in profiles:
        state = states[profile.user_id]
        attempts = 0
        while attempts < 50:
            event = build_candidate_event(profile, state, "low")
            if event["risk_label"] == "low":
                commit_event(state, event)
                rows.append(event)
                break
            attempts += 1
    return rows


def generate_rows_for_targets(profiles: list, states: dict):
    rows = warmup_low_events(profiles, states)

    remaining_targets = CLASS_TARGETS.copy()
    remaining_targets["low"] = max(0, remaining_targets["low"] - len(rows))

    label_pool = []
    for label, count in remaining_targets.items():
        label_pool.extend([label] * count)

    random.shuffle(label_pool)

    for label in label_pool:
        attempts = 0
        while attempts < 120:
            profile = pick_profile_for_label(profiles, states, label)
            state = states[profile.user_id]
            event = build_candidate_event(profile, state, label)
            if event["risk_label"] == label:
                commit_event(state, event)
                rows.append(event)
                break
            attempts += 1

        if attempts >= 120:
            raise RuntimeError(f"Unable to generate a valid synthetic event for label '{label}'.")

    return rows


def project_training_columns(df: pd.DataFrame) -> pd.DataFrame:
    cols = [
        "event_time",
        "client_id",
        "app_sensitivity",
        "ua_browser",
        "ua_os",
        "ua_device",
        "geo_country_code",
        "asn_org",
        "hour",
        "day_of_week",
        "is_weekend",
        "is_night_login",
        "is_business_hours",
        "is_new_device",
        "is_new_ip_for_user",
        "fails_5m",
        "fails_1h",
        "fails_24h",
        "login_1h",
        "is_vpn_detected",
        "is_proxy_detected",
        "is_tor",
        "distance_from_last_location_km",
        "is_impossible_travel",
        "abuse_confidence_score",
        "synthetic_rule_score",
        "source_risk_score",
        "source_risk_label",
        "source_decision",
        "source_policy_reason",
        "risk_label",
        "risk_class",
        "data_origin",
    ]
    return df[cols].copy()


def main():
    random.seed(RANDOM_SEED)

    profiles = build_user_profiles()
    states = {profile.user_id: UserState() for profile in profiles}
    rows = generate_rows_for_targets(profiles, states)

    raw_df = pd.DataFrame(rows).sort_values("event_time").reset_index(drop=True)
    raw_df.to_csv(RAW_OUTPUT_PATH, index=False)

    training_df = project_training_columns(raw_df)
    training_df.to_csv(OUTPUT_PATH, index=False)

    print(f"Synthetic raw login dataset generated: {RAW_OUTPUT_PATH}")
    print(f"Synthetic training dataset generated: {OUTPUT_PATH}")
    print(f"Total synthetic LOGIN rows: {len(raw_df)}")
    print(f"Synthetic users simulated: {raw_df['user_id'].nunique()}")

    print("\nDistribution by risk_class:")
    print(training_df["risk_class"].value_counts().sort_index())

    print("\nDistribution by risk_label:")
    print(training_df["risk_label"].value_counts().sort_index())

    print("\nTop client distribution:")
    print(training_df["client_id"].value_counts().sort_index())

    print("\nTop browser / OS combinations:")
    print(
        raw_df.groupby(["ua_browser", "ua_os"]).size().sort_values(ascending=False).head(10)
    )


if __name__ == "__main__":
    main()
