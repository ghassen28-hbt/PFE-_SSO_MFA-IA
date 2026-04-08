from __future__ import annotations

from typing import Iterable

import pandas as pd


SCHEMA_VERSION = "2.2"

RISK_CLASS_TO_LABEL = {
    0: "low",
    1: "moderate",
    2: "high",
    3: "critical",
}

RISK_LABEL_TO_CLASS = {label: risk_class for risk_class, label in RISK_CLASS_TO_LABEL.items()}

CATEGORICAL_FEATURES = [
    "client_id",
    "ua_browser",
    "ua_os",
    "ua_device",
    "geo_country_code",
    "asn_org",
]

NUMERIC_FEATURES = [
    "app_sensitivity",
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
]

ALL_FEATURES = CATEGORICAL_FEATURES + NUMERIC_FEATURES

PROVENANCE_COLUMNS = [
    "synthetic_rule_score",
    "source_risk_score",
    "source_risk_label",
    "source_decision",
    "source_policy_reason",
    "data_origin",
]

DATASET_COLUMNS = [
    "event_time",
    *ALL_FEATURES,
    *PROVENANCE_COLUMNS,
    "risk_label",
    "risk_class",
]

SCORING_REQUEST_DEFAULTS = {
    "client_id": "unknown",
    "ua_browser": "unknown",
    "ua_os": "unknown",
    "ua_device": "unknown",
    "geo_country_code": "unknown",
    "asn_org": "unknown",
    "app_sensitivity": 0,
    "hour": 0,
    "day_of_week": 1,
    "is_weekend": 0,
    "is_night_login": 0,
    "is_business_hours": 0,
    "is_new_device": 0,
    "is_new_ip_for_user": 0,
    "fails_5m": 0,
    "fails_1h": 0,
    "fails_24h": 0,
    "login_1h": 0,
    "is_vpn_detected": 0,
    "is_proxy_detected": 0,
    "is_tor": 0,
    "distance_from_last_location_km": 0.0,
    "is_impossible_travel": 0,
    "abuse_confidence_score": 0,
}

MRMR_CANDIDATE_TOP_KS = [6, 8, 10, 12]
MRMR_MIN_FEATURES = 4
MRMR_SCORE_FLOOR = 0.000001
CALIBRATION_HOLDOUT_RATIO = 0.20
CALIBRATION_METRIC_TOLERANCE = 0.005
SCORE_METHOD = "expected_multiclass_severity=sum(p_i * class_i)/(num_classes-1)"

ABLATION_SETS = {
    "baseline_core": [
        "client_id",
        "ua_browser",
        "ua_os",
        "ua_device",
        "app_sensitivity",
        "hour",
        "day_of_week",
        "is_weekend",
        "is_night_login",
        "is_business_hours",
    ],
    "baseline_plus_network": [
        "client_id",
        "ua_browser",
        "ua_os",
        "ua_device",
        "app_sensitivity",
        "hour",
        "day_of_week",
        "is_weekend",
        "is_night_login",
        "is_business_hours",
        "geo_country_code",
        "asn_org",
        "is_vpn_detected",
        "is_proxy_detected",
        "is_tor",
        "abuse_confidence_score",
    ],
    "baseline_plus_network_geo_history": [
        "client_id",
        "ua_browser",
        "ua_os",
        "ua_device",
        "app_sensitivity",
        "hour",
        "day_of_week",
        "is_weekend",
        "is_night_login",
        "is_business_hours",
        "geo_country_code",
        "asn_org",
        "is_vpn_detected",
        "is_proxy_detected",
        "is_tor",
        "abuse_confidence_score",
        "is_new_device",
        "is_new_ip_for_user",
        "fails_5m",
        "fails_1h",
        "fails_24h",
        "login_1h",
        "distance_from_last_location_km",
        "is_impossible_travel",
    ],
}


def normalize_risk_label(value) -> str:
    text = str(value or "").strip().lower()
    return text if text in RISK_LABEL_TO_CLASS else "unknown"


def ensure_columns(df: pd.DataFrame, columns: Iterable[str]) -> pd.DataFrame:
    for column in columns:
        if column not in df.columns:
            df[column] = None
    return df


def normalize_dataset_schema(df: pd.DataFrame) -> pd.DataFrame:
    df = ensure_columns(df.copy(), DATASET_COLUMNS)
    df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce")
    df["risk_label"] = df["risk_label"].map(normalize_risk_label)
    df["risk_class"] = pd.to_numeric(df["risk_class"], errors="coerce").astype("Int64")

    for column in NUMERIC_FEATURES + ["synthetic_rule_score", "source_risk_score"]:
        df[column] = pd.to_numeric(df[column], errors="coerce")

    for column in CATEGORICAL_FEATURES + ["source_risk_label", "source_decision", "source_policy_reason", "data_origin"]:
        df[column] = df[column].fillna("unknown").astype(str)

    return df[DATASET_COLUMNS].copy()
