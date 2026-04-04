import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
TRAINING_DIR = PROJECT_ROOT / "training"
ARTIFACTS_DIR = TRAINING_DIR / "artifacts"

MODEL_PATH = ARTIFACTS_DIR / "risk_model_v1.joblib"
FEATURES_PATH = ARTIFACTS_DIR / "risk_model_v1_features.json"

NUMERIC_COLS = [
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
]

CATEGORICAL_COLS = [
    "client_id",
    "ua_browser",
    "ua_os",
    "ua_device",
]

DEFAULT_CLASS_MAPPING = {
    0: "low",
    1: "moderate",
    2: "high",
    3: "critical",
}


class RiskRequest(BaseModel):
    client_id: str = Field(..., example="finance-client-3")
    app_sensitivity: int = Field(..., example=4)
    ua_browser: str = Field(..., example="Brave")
    ua_os: str = Field(..., example="Windows 11")
    ua_device: str = Field(..., example="pc")
    hour: int = Field(..., ge=0, le=23, example=2)
    day_of_week: int = Field(..., ge=1, le=7, example=3)
    is_weekend: int = Field(..., ge=0, le=1, example=0)
    is_night_login: int = Field(..., ge=0, le=1, example=1)
    is_business_hours: int = Field(..., ge=0, le=1, example=0)
    is_new_device: int = Field(..., ge=0, le=1, example=1)
    is_new_ip_for_user: int = Field(..., ge=0, le=1, example=1)
    fails_5m: int = Field(..., ge=0, example=2)
    fails_1h: int = Field(..., ge=0, example=4)
    fails_24h: int = Field(..., ge=0, example=5)
    login_1h: int = Field(..., ge=0, example=1)


def load_feature_metadata():
    if not FEATURES_PATH.exists():
        return {}

    with open(FEATURES_PATH, "r", encoding="utf-8") as feature_file:
        data = json.load(feature_file)

    return data if isinstance(data, dict) else {"selected_features": data}


def load_artifacts():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

    artifact = joblib.load(MODEL_PATH)
    feature_metadata = load_feature_metadata()

    model = artifact["model"]
    imputer = artifact["imputer"]

    feature_cols = (
        artifact.get("feature_cols")
        or feature_metadata.get("selected_features")
        or CATEGORICAL_COLS + NUMERIC_COLS
    )
    selected_categorical_cols = (
        artifact.get("selected_categorical_cols")
        or feature_metadata.get("selected_categorical_features")
        or [col for col in CATEGORICAL_COLS if col in feature_cols]
    )

    class_mapping_raw = (
        artifact.get("class_mapping")
        or feature_metadata.get("class_mapping")
        or DEFAULT_CLASS_MAPPING
    )
    class_mapping = {int(key): value for key, value in class_mapping_raw.items()}

    return model, imputer, feature_cols, selected_categorical_cols, class_mapping


model, imputer, feature_cols, selected_categorical_cols, class_mapping = load_artifacts()

app = FastAPI(title="Risk Scoring Service", version="2.0")


@app.get("/")
def health():
    return {
        "service": "risk-scoring-service",
        "status": "ok",
        "model_loaded": True,
        "model_path": str(MODEL_PATH),
        "risk_mode": "multiclass",
        "class_mapping": class_mapping,
    }


def compute_policy(risk_class: int):
    policies = {
        0: {
            "risk_label": "low",
            "decision": "ALLOW",
            "required_factor": "NONE",
            "auth_path": "SSO_ONLY",
            "policy_reason": "predicted_multiclass_low",
        },
        1: {
            "risk_label": "moderate",
            "decision": "STEP_UP_TOTP",
            "required_factor": "TOTP_OR_WEBAUTHN",
            "auth_path": "SECOND_FACTOR",
            "policy_reason": "predicted_multiclass_moderate",
        },
        2: {
            "risk_label": "high",
            "decision": "STEP_UP_BIOMETRIC",
            "required_factor": "FACE_RECOGNITION",
            "auth_path": "BIOMETRIC_FACTOR",
            "policy_reason": "predicted_multiclass_high",
        },
        3: {
            "risk_label": "critical",
            "decision": "BLOCK_REVIEW",
            "required_factor": "ADMIN_REVIEW",
            "auth_path": "TEMP_BLOCK",
            "policy_reason": "predicted_multiclass_critical",
        },
    }
    return policies.get(risk_class, policies[0])


def normalize_risk_score(probabilities: np.ndarray) -> float:
    if probabilities.size == 0:
        return 0.0

    max_class_id = max(class_mapping.keys()) if class_mapping else 1
    severity = 0.0
    for class_id, probability in enumerate(probabilities):
        severity += class_id * float(probability)

    normalized = severity / max(1, max_class_id)
    return round(max(0.0, min(1.0, normalized)), 4)


def normalize_probabilities(probabilities: np.ndarray):
    labels = [class_mapping.get(i, str(i)) for i in range(len(probabilities))]
    return {
        label: round(float(probability), 4)
        for label, probability in zip(labels, probabilities)
    }


@app.post("/score")
def score_risk(payload: RiskRequest):
    try:
        row = payload.model_dump()
        df = pd.DataFrame([row])

        for col in CATEGORICAL_COLS:
            df[col] = df[col].fillna("unknown").astype(str).astype("category")

        for col in NUMERIC_COLS:
            df[col] = pd.to_numeric(df[col], errors="coerce")

        df[NUMERIC_COLS] = imputer.transform(df[NUMERIC_COLS])
        df = df[feature_cols]

        probabilities = np.asarray(model.predict_proba(df)[0], dtype=float)
        risk_class = int(np.argmax(probabilities))
        risk_label = class_mapping.get(risk_class, "unknown")
        risk_score = normalize_risk_score(probabilities)
        policy = compute_policy(risk_class)

        return {
            "risk_class": risk_class,
            "risk_score": risk_score,
            "risk_label": risk_label,
            "decision": policy["decision"],
            "required_factor": policy["required_factor"],
            "auth_path": policy["auth_path"],
            "policy_reason": policy["policy_reason"],
            "class_probabilities": normalize_probabilities(probabilities),
            "features_used": feature_cols,
            "selected_categorical_features": selected_categorical_cols,
        }

    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scoring error: {str(exc)}")
