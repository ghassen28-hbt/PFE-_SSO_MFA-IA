import json
import sys
import warnings
from pathlib import Path
from threading import Lock
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
TRAINING_DIR = PROJECT_ROOT / "training"
ARTIFACTS_DIR = TRAINING_DIR / "artifacts"

if str(TRAINING_DIR) not in sys.path:
    sys.path.insert(0, str(TRAINING_DIR))

from pipeline_schema import (  # noqa: E402
    ALL_FEATURES,
    CATEGORICAL_FEATURES,
    NUMERIC_FEATURES,
    RISK_CLASS_TO_LABEL,
    SCHEMA_VERSION,
    SCORING_REQUEST_DEFAULTS,
    SCORE_METHOD,
)


MODEL_PATH = ARTIFACTS_DIR / "risk_model_v1.joblib"
FEATURES_PATH = ARTIFACTS_DIR / "risk_model_v1_features.json"
ARTIFACT_LOCK = Lock()
ARTIFACT_CONTEXT = {}
ARTIFACT_FINGERPRINT = None


class RiskRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    client_id: Optional[str] = Field(default=None, json_schema_extra={"example": "finance-client-3"})
    app_sensitivity: Optional[int] = Field(default=None, json_schema_extra={"example": 4})
    ua_browser: Optional[str] = Field(default=None, json_schema_extra={"example": "Brave 146.0.0.0"})
    ua_os: Optional[str] = Field(default=None, json_schema_extra={"example": "Windows 11"})
    ua_device: Optional[str] = Field(default=None, json_schema_extra={"example": "pc"})
    geo_country_code: Optional[str] = Field(default=None, json_schema_extra={"example": "TN"})
    asn_org: Optional[str] = Field(default=None, json_schema_extra={"example": "Orange Tunisie"})
    hour: Optional[int] = Field(default=None, ge=0, le=23, json_schema_extra={"example": 2})
    day_of_week: Optional[int] = Field(default=None, ge=1, le=7, json_schema_extra={"example": 3})
    is_weekend: Optional[int] = Field(default=None, ge=0, le=1, json_schema_extra={"example": 0})
    is_night_login: Optional[int] = Field(default=None, ge=0, le=1, json_schema_extra={"example": 1})
    is_business_hours: Optional[int] = Field(default=None, ge=0, le=1, json_schema_extra={"example": 0})
    is_new_device: Optional[int] = Field(default=None, ge=0, le=1, json_schema_extra={"example": 1})
    is_new_ip_for_user: Optional[int] = Field(default=None, ge=0, le=1, json_schema_extra={"example": 1})
    fails_5m: Optional[int] = Field(default=None, ge=0, json_schema_extra={"example": 2})
    fails_1h: Optional[int] = Field(default=None, ge=0, json_schema_extra={"example": 4})
    fails_24h: Optional[int] = Field(default=None, ge=0, json_schema_extra={"example": 5})
    login_1h: Optional[int] = Field(default=None, ge=0, json_schema_extra={"example": 1})
    is_vpn_detected: Optional[int] = Field(default=None, ge=0, le=1, json_schema_extra={"example": 0})
    is_proxy_detected: Optional[int] = Field(default=None, ge=0, le=1, json_schema_extra={"example": 0})
    is_tor: Optional[int] = Field(default=None, ge=0, le=1, json_schema_extra={"example": 0})
    distance_from_last_location_km: Optional[float] = Field(default=None, ge=0, json_schema_extra={"example": 0.0})
    is_impossible_travel: Optional[int] = Field(default=None, ge=0, le=1, json_schema_extra={"example": 0})
    abuse_confidence_score: Optional[int] = Field(default=None, ge=0, json_schema_extra={"example": 0})


def load_feature_metadata():
    if not FEATURES_PATH.exists():
        return {}
    with open(FEATURES_PATH, "r", encoding="utf-8") as feature_file:
        return json.load(feature_file)


def load_artifacts():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

    artifact = joblib.load(MODEL_PATH)
    metadata = load_feature_metadata()

    class_mapping_raw = artifact.get("class_mapping") or metadata.get("class_mapping") or {
        str(key): value for key, value in RISK_CLASS_TO_LABEL.items()
    }
    class_mapping = {int(key): value for key, value in class_mapping_raw.items()}

    selected_features = (
        artifact.get("selected_features")
        or metadata.get("selected_features")
        or ALL_FEATURES
    )
    selected_categorical_features = (
        artifact.get("selected_categorical_features")
        or metadata.get("selected_categorical_features")
        or [feature for feature in CATEGORICAL_FEATURES if feature in selected_features]
    )

    if "predictor" in artifact:
        return {
            "artifact_mode": "pipeline_v2",
            "predictor": artifact["predictor"],
            "selected_features": selected_features,
            "selected_categorical_features": selected_categorical_features,
            "class_mapping": class_mapping,
            "selected_model_name": (
                artifact.get("selected_model_name")
                or metadata.get("selected_model_name")
                or "unknown"
            ),
            "score_method": artifact.get(
                "score_method",
                SCORE_METHOD,
            ),
        }

    return {
        "artifact_mode": "legacy_v1",
        "model": artifact["model"],
        "imputer": artifact["imputer"],
        "selected_features": selected_features,
        "selected_categorical_features": selected_categorical_features,
        "class_mapping": class_mapping,
        "selected_model_name": metadata.get("selected_model_name", "legacy_v1"),
        "score_method": SCORE_METHOD,
        "schema_version": SCHEMA_VERSION,
    }


def get_artifact_fingerprint():
    mtimes = []
    for path in [MODEL_PATH, FEATURES_PATH]:
        if path.exists():
            mtimes.append(path.stat().st_mtime)
    return max(mtimes) if mtimes else None


def refresh_artifacts_if_needed(force: bool = False):
    global ARTIFACT_CONTEXT, ARTIFACT_FINGERPRINT

    fingerprint = get_artifact_fingerprint()
    if not force and ARTIFACT_CONTEXT and fingerprint == ARTIFACT_FINGERPRINT:
        return ARTIFACT_CONTEXT

    with ARTIFACT_LOCK:
        fingerprint = get_artifact_fingerprint()
        if not force and ARTIFACT_CONTEXT and fingerprint == ARTIFACT_FINGERPRINT:
            return ARTIFACT_CONTEXT

        try:
            refreshed = load_artifacts()
        except Exception:
            if ARTIFACT_CONTEXT:
                return ARTIFACT_CONTEXT
            raise

        refreshed["artifact_fingerprint"] = fingerprint
        ARTIFACT_CONTEXT = refreshed
        ARTIFACT_FINGERPRINT = fingerprint
        return ARTIFACT_CONTEXT


refresh_artifacts_if_needed(force=True)

app = FastAPI(title="Risk Scoring Service", version="2.2")


def coerce_payload(payload: dict) -> dict:
    normalized = dict(SCORING_REQUEST_DEFAULTS)
    normalized.update({key: value for key, value in payload.items() if value is not None})

    for feature in CATEGORICAL_FEATURES:
        normalized[feature] = str(normalized.get(feature) or "unknown").strip() or "unknown"

    for feature in NUMERIC_FEATURES:
        default = SCORING_REQUEST_DEFAULTS.get(feature, 0)
        value = normalized.get(feature, default)
        try:
            normalized[feature] = float(value)
        except Exception:
            normalized[feature] = float(default)

    integer_like = {
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
        "is_impossible_travel",
        "abuse_confidence_score",
    }
    for feature in integer_like:
        normalized[feature] = int(round(normalized[feature]))

    normalized["distance_from_last_location_km"] = max(
        0.0,
        float(normalized["distance_from_last_location_km"]),
    )
    return normalized


def expected_severity_score(probabilities: np.ndarray, class_mapping: dict[int, str]) -> float:
    max_class_id = max(class_mapping.keys()) if class_mapping else 1
    severity = sum(class_id * float(probability) for class_id, probability in enumerate(probabilities))
    score = severity / max(1, max_class_id)
    return round(max(0.0, min(1.0, score)), 4)


def normalize_probabilities(probabilities: np.ndarray, class_mapping: dict[int, str]) -> dict:
    probabilities = normalize_probability_vector(probabilities)
    return {
        class_mapping.get(index, str(index)): round(float(probability), 4)
        for index, probability in enumerate(probabilities)
    }


def normalize_probability_vector(probabilities: np.ndarray) -> np.ndarray:
    probabilities = np.asarray(probabilities, dtype=float)
    probabilities = np.clip(probabilities, 1e-12, 1.0)
    total = probabilities.sum()
    if total <= 0.0:
        total = 1.0
    return probabilities / total


def compute_ml_probabilities(row: dict, context: dict) -> np.ndarray:
    selected_features = context["selected_features"]
    df = pd.DataFrame([{feature: row.get(feature) for feature in ALL_FEATURES}])

    if context["artifact_mode"] == "pipeline_v2":
        predictor = context["predictor"]
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message="X does not have valid feature names, but LGBMClassifier was fitted with feature names",
                category=UserWarning,
            )
            probabilities = predictor.predict_proba(df[selected_features])[0]
        return normalize_probability_vector(probabilities)

    legacy_model = context["model"]
    legacy_imputer = context["imputer"]
    legacy_numeric = [feature for feature in NUMERIC_FEATURES if feature in selected_features]
    legacy_categorical = [feature for feature in CATEGORICAL_FEATURES if feature in selected_features]

    for feature in legacy_categorical:
        df[feature] = df[feature].fillna("unknown").astype(str).astype("category")
    if legacy_numeric:
        df[legacy_numeric] = legacy_imputer.transform(df[legacy_numeric])

    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="X does not have valid feature names, but LGBMClassifier was fitted with feature names",
            category=UserWarning,
        )
        probabilities = legacy_model.predict_proba(df[selected_features])[0]
    return normalize_probability_vector(probabilities)


def compute_policy(risk_class: int, policy_reason: str):
    label = RISK_CLASS_TO_LABEL.get(risk_class, "low")
    policies = {
        0: ("ALLOW", "NONE", "SSO_ONLY"),
        1: ("STEP_UP_TOTP", "TOTP_OR_WEBAUTHN", "SECOND_FACTOR"),
        2: ("STEP_UP_BIOMETRIC", "FACE_RECOGNITION", "BIOMETRIC_FACTOR"),
        3: ("BLOCK_REVIEW", "ADMIN_REVIEW", "TEMP_BLOCK"),
    }
    decision, required_factor, auth_path = policies.get(risk_class, policies[0])
    return {
        "risk_label": label,
        "decision": decision,
        "required_factor": required_factor,
        "auth_path": auth_path,
        "policy_reason": policy_reason,
    }


def apply_hard_rule_override(row: dict):
    anomaly_count = int(row["is_new_device"]) + int(row["is_new_ip_for_user"])
    anonymous_network = (
        int(row["is_vpn_detected"]) == 1
        or int(row["is_proxy_detected"]) == 1
        or int(row["is_tor"]) == 1
    )
    long_geo_shift = float(row["distance_from_last_location_km"]) >= 500.0

    if int(row["fails_5m"]) >= 5 or int(row["fails_1h"]) >= 8 or int(row["fails_24h"]) >= 12:
        return 3, "critical_hard_rule_excessive_failures"

    if long_geo_shift and int(row["is_impossible_travel"]) == 1:
        if (
            int(row["app_sensitivity"]) >= 4
            or int(row["is_proxy_detected"]) == 1
            or int(row["is_tor"]) == 1
            or int(row["abuse_confidence_score"]) >= 75
        ):
            return 3, "critical_hard_rule_impossible_travel"
        if anonymous_network or anomaly_count >= 1:
            return 2, "high_hard_rule_impossible_travel"
        return 1, "moderate_hard_rule_impossible_travel"

    if (
        anonymous_network
        and long_geo_shift
        and int(row["is_new_ip_for_user"]) == 1
        and int(row["abuse_confidence_score"]) < 75
    ):
        if int(row["app_sensitivity"]) >= 4:
            return 2, "high_hard_rule_vpn_geo_shift_sensitive_app"
        return 1, "moderate_hard_rule_vpn_geo_shift"

    if (
        int(row["app_sensitivity"]) >= 5
        and anomaly_count >= 2
        and (
            int(row["is_impossible_travel"]) == 1
            or int(row["is_proxy_detected"]) == 1
            or int(row["is_tor"]) == 1
        )
    ):
        return 3, "critical_hard_rule_sensitive_extreme_anomaly"

    if (
        int(row["abuse_confidence_score"]) >= 75
        and (int(row["is_proxy_detected"]) == 1 or int(row["is_tor"]) == 1)
    ):
        return 3, "critical_hard_rule_high_abuse_proxy"

    return None


def risk_score_floor_for_class(risk_class: int) -> float:
    return {
        0: 0.0,
        1: 0.35,
        2: 0.70,
        3: 0.95,
    }.get(risk_class, 0.0)


@app.get("/")
def health():
    context = refresh_artifacts_if_needed()
    return {
        "service": "risk-scoring-service",
        "status": "ok",
        "model_loaded": True,
        "model_path": str(MODEL_PATH),
        "risk_mode": "multiclass_hybrid",
        "schema_version": SCHEMA_VERSION,
        "artifact_mode": context["artifact_mode"],
        "class_mapping": context["class_mapping"],
        "model_name": context.get("selected_model_name", "unknown"),
        "artifact_fingerprint": context.get("artifact_fingerprint"),
    }


@app.post("/score")
def score_risk(payload: RiskRequest):
    try:
        context = refresh_artifacts_if_needed()
        row = coerce_payload(payload.model_dump(exclude_none=True))
        model_probabilities = compute_ml_probabilities(row, context)
        model_risk_class = int(np.argmax(model_probabilities))
        model_risk_score = expected_severity_score(
            model_probabilities,
            context["class_mapping"],
        )

        override = apply_hard_rule_override(row)
        if override is not None:
            final_risk_class, policy_reason = override
            final_probabilities = np.zeros(len(context["class_mapping"]), dtype=float)
            final_probabilities[final_risk_class] = 1.0
            prediction_source = "hard_rule_override"
            risk_score = max(model_risk_score, risk_score_floor_for_class(final_risk_class))
        else:
            final_risk_class = model_risk_class
            policy_reason = f"ml_predicted_{RISK_CLASS_TO_LABEL[final_risk_class]}"
            final_probabilities = model_probabilities
            prediction_source = "ml_model"
            risk_score = model_risk_score

        policy = compute_policy(final_risk_class, policy_reason)

        response = {
            "risk_class": final_risk_class,
            "risk_label": policy["risk_label"],
            "risk_score": round(float(risk_score), 4),
            "model_risk_score": model_risk_score,
            "decision": policy["decision"],
            "required_factor": policy["required_factor"],
            "auth_path": policy["auth_path"],
            "policy_reason": policy["policy_reason"],
            "class_probabilities": normalize_probabilities(
                final_probabilities,
                context["class_mapping"],
            ),
            "model_class_probabilities": normalize_probabilities(
                model_probabilities,
                context["class_mapping"],
            ),
            "features_used": context["selected_features"],
            "selected_categorical_features": context["selected_categorical_features"],
            "prediction_source": prediction_source,
            "score_source": "ml_expected_multiclass_severity",
            "score_formula": context["score_method"],
            "schema_version": SCHEMA_VERSION,
            "model_name": context.get("selected_model_name", "unknown"),
            "artifact_fingerprint": context.get("artifact_fingerprint"),
        }
        return response
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scoring error: {str(exc)}")
