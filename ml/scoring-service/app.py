from pathlib import Path
import json
import joblib
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


def load_artifacts():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Modèle introuvable : {MODEL_PATH}")

    if not FEATURES_PATH.exists():
        raise FileNotFoundError(f"Features introuvables : {FEATURES_PATH}")

    artifact = joblib.load(MODEL_PATH)
    model = artifact["model"]
    imputer = artifact["imputer"]

    with open(FEATURES_PATH, "r", encoding="utf-8") as f:
        feature_cols = json.load(f)

    return model, imputer, feature_cols


model, imputer, feature_cols = load_artifacts()

app = FastAPI(title="Risk Scoring Service", version="1.1")


@app.get("/")
def health():
    return {
        "service": "risk-scoring-service",
        "status": "ok",
        "model_loaded": True,
        "model_path": str(MODEL_PATH),
    }


def compute_risk_policy(score: float, row: dict):
    app_sensitivity = int(row.get("app_sensitivity", 0) or 0)
    is_new_device = int(row.get("is_new_device", 0) or 0)
    is_new_ip_for_user = int(row.get("is_new_ip_for_user", 0) or 0)
    fails_5m = int(row.get("fails_5m", 0) or 0)
    fails_1h = int(row.get("fails_1h", 0) or 0)
    fails_24h = int(row.get("fails_24h", 0) or 0)
    login_1h = int(row.get("login_1h", 0) or 0)
    is_night_login = int(row.get("is_night_login", 0) or 0)
    is_business_hours = int(row.get("is_business_hours", 0) or 0)

    anomaly_count = is_new_device + is_new_ip_for_user

    # =========================================================
    # 1) CRITICAL
    # Cas franchement dangereux => blocage
    # =========================================================
    if (
        score >= 0.90
        or fails_5m >= 5
        or fails_1h >= 8
        or fails_24h >= 12
        or (app_sensitivity >= 5 and anomaly_count >= 2 and fails_1h >= 2)
        or (anomaly_count >= 2 and fails_5m >= 3)
        or (is_night_login == 1 and app_sensitivity >= 5 and anomaly_count >= 2)
    ):
        return {
            "risk_label": "critical",
            "decision": "BLOCK_REVIEW",
            "required_factor": "ADMIN_REVIEW",
            "auth_path": "TEMP_BLOCK",
            "policy_reason": "critical_conditions_met",
        }

    # =========================================================
    # 2) HIGH
    # Cas risqués => biométrie
    # =========================================================
    if (
        score >= 0.70
        or fails_5m >= 3
        or fails_1h >= 4
        or anomaly_count >= 2
        or (app_sensitivity >= 4 and anomaly_count >= 1)
        or (app_sensitivity >= 4 and fails_1h >= 2)
        or (is_night_login == 1 and app_sensitivity >= 4)
    ):
        return {
            "risk_label": "high",
            "decision": "STEP_UP_BIOMETRIC",
            "required_factor": "FACE_RECOGNITION",
            "auth_path": "BIOMETRIC_FACTOR",
            "policy_reason": "high_conditions_met",
        }

    # =========================================================
    # 3) MODERATE
    # Cas intermédiaires => TOTP
    # =========================================================
    if (
        score >= 0.35
        or fails_5m >= 2
        or fails_1h >= 2
        or (anomaly_count == 1 and app_sensitivity >= 3)
        or (app_sensitivity >= 3 and login_1h >= 3)
        or (is_night_login == 1 and app_sensitivity >= 3)
        or (is_business_hours == 0 and app_sensitivity >= 4)
    ):
        return {
            "risk_label": "moderate",
            "decision": "STEP_UP_TOTP",
            "required_factor": "TOTP_OR_WEBAUTHN",
            "auth_path": "SECOND_FACTOR",
            "policy_reason": "moderate_conditions_met",
        }

    # =========================================================
    # 4) LOW
    # Cas normaux => accès direct
    # =========================================================
    return {
        "risk_label": "low",
        "decision": "ALLOW",
        "required_factor": "NONE",
        "auth_path": "SSO_ONLY",
        "policy_reason": "low_conditions_met",
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

        risk_score = float(model.predict_proba(df)[0, 1])
        policy = compute_risk_policy(risk_score, row)

        return {
            "risk_score": round(risk_score, 4),
            "risk_label": policy["risk_label"],
            "decision": policy["decision"],
            "required_factor": policy["required_factor"],
            "auth_path": policy["auth_path"],
            "policy_reason": policy["policy_reason"],
            "features_used": feature_cols,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur scoring: {str(e)}")