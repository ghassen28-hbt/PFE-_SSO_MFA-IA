import json
import joblib
import pandas as pd
import clickhouse_connect
from pathlib import Path

from lightgbm import LGBMClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.impute import SimpleImputer


# =========================
# CONFIG
# =========================
CLICKHOUSE_HOST = "localhost"
CLICKHOUSE_PORT = 8123
CLICKHOUSE_USER = "default"
CLICKHOUSE_PASSWORD = "admin123"
CLICKHOUSE_DATABASE = "iam"

TABLE_NAME = "risk_training_dataset_v1"
MODEL_DIR = Path("artifacts")
MODEL_DIR.mkdir(exist_ok=True)

MODEL_PATH = MODEL_DIR / "risk_model_v1.joblib"
FEATURES_PATH = MODEL_DIR / "risk_model_v1_features.json"


# =========================
# 1) LOAD DATA
# =========================
def load_data() -> pd.DataFrame:
    base_dir = Path(__file__).resolve().parent
    csv_path = base_dir / "data" / "training_dataset_final.csv"

    if not csv_path.exists():
        raise FileNotFoundError(
            f"Dataset final introuvable : {csv_path}. "
            f"Lance d'abord build_training_dataset.py"
        )

    df = pd.read_csv(csv_path)
    return df



# =========================
# 2) CLEAN / PREP
# =========================
def prepare_data(df: pd.DataFrame):
    if df.empty:
        raise ValueError("Le dataset est vide. Vérifie la table ClickHouse.")

    df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce")
    df = df.dropna(subset=["event_time", "step_up_required"]).copy()

    # Colonnes catégorielles
    categorical_cols = ["client_id", "ua_browser", "ua_os", "ua_device"]

    # Colonnes numériques
    numeric_cols = [
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

    feature_cols = categorical_cols + numeric_cols
    target_col = "step_up_required"

    # Nettoyage des catégories
    for col in categorical_cols:
        df[col] = df[col].fillna("unknown").astype(str).astype("category")

    # Nettoyage des numériques
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Imputation simple pour numériques
    imputer = SimpleImputer(strategy="median")
    df[numeric_cols] = imputer.fit_transform(df[numeric_cols])

    # Cible
    df[target_col] = pd.to_numeric(df[target_col], errors="coerce").fillna(0).astype(int)

    return df, feature_cols, categorical_cols, numeric_cols, target_col, imputer


# =========================
# 3) TEMPORAL SPLIT
# =========================
def temporal_split(df: pd.DataFrame, feature_cols, target_col):
    df = df.sort_values("event_time").reset_index(drop=True)

    n = len(df)
    if n < 20:
        raise ValueError(
            f"Dataset trop petit ({n} lignes). "
            "Ajoute plus d'événements avant d'entraîner le modèle."
        )

    train_end = int(n * 0.70)
    valid_end = int(n * 0.85)

    train_df = df.iloc[:train_end].copy()
    valid_df = df.iloc[train_end:valid_end].copy()
    test_df = df.iloc[valid_end:].copy()

    X_train = train_df[feature_cols]
    y_train = train_df[target_col]

    X_valid = valid_df[feature_cols]
    y_valid = valid_df[target_col]

    X_test = test_df[feature_cols]
    y_test = test_df[target_col]

    return X_train, y_train, X_valid, y_valid, X_test, y_test


# =========================
# 4) TRAIN MODEL
# =========================
def train_model(X_train, y_train, X_valid, y_valid, categorical_cols):
    # Gestion du déséquilibre éventuel
    positives = int(y_train.sum())
    negatives = int((y_train == 0).sum())
    scale_pos_weight = negatives / positives if positives > 0 else 1.0

    model = LGBMClassifier(
        objective="binary",
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=31,
        max_depth=-1,
        min_child_samples=20,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        scale_pos_weight=scale_pos_weight,
        verbosity=-1,
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_valid, y_valid)],
        eval_metric="auc",
        categorical_feature=categorical_cols,
    )

    return model


# =========================
# 5) EVALUATE
# =========================
def evaluate_model(model, X_test, y_test, feature_cols):
    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    metrics = {
        "roc_auc": float(roc_auc_score(y_test, y_prob)) if len(set(y_test)) > 1 else None,
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
    }

    print("\n===== METRICS TEST =====")
    for k, v in metrics.items():
        print(f"{k}: {v}")

    print("\n===== CONFUSION MATRIX =====")
    print(confusion_matrix(y_test, y_pred))

    print("\n===== CLASSIFICATION REPORT =====")
    print(classification_report(y_test, y_pred, zero_division=0))

    print("\n===== FEATURE IMPORTANCE =====")
    importances = pd.DataFrame({
        "feature": feature_cols,
        "importance": model.feature_importances_,
    }).sort_values("importance", ascending=False)

    print(importances.to_string(index=False))

    return metrics, importances


# =========================
# 6) SAVE ARTIFACTS
# =========================
def save_artifacts(model, feature_cols, imputer):
    artifact = {
        "model": model,
        "imputer": imputer,
    }
    joblib.dump(artifact, MODEL_PATH)

    with open(FEATURES_PATH, "w", encoding="utf-8") as f:
        json.dump(feature_cols, f, ensure_ascii=False, indent=2)

    print(f"\nModèle sauvegardé : {MODEL_PATH}")
    print(f"Features sauvegardées : {FEATURES_PATH}")


# =========================
# MAIN
# =========================
def main():
    print("Chargement des données depuis ClickHouse...")
    df = load_data()
    print(f"Nombre de lignes chargées : {len(df)}")

    print("Préparation du dataset...")
    df, feature_cols, categorical_cols, numeric_cols, target_col, imputer = prepare_data(df)

    print("\nDistribution cible:")
    print(df[target_col].value_counts(dropna=False).sort_index())

    print("\nSplit temporel...")
    X_train, y_train, X_valid, y_valid, X_test, y_test = temporal_split(
        df, feature_cols, target_col
    )

    print(f"Train : {len(X_train)}")
    print(f"Valid : {len(X_valid)}")
    print(f"Test  : {len(X_test)}")

    print("\nEntraînement LightGBM...")
    model = train_model(X_train, y_train, X_valid, y_valid, categorical_cols)

    print("\nÉvaluation...")
    metrics, importances = evaluate_model(model, X_test, y_test, feature_cols)

    print("\nSauvegarde des artifacts...")
    save_artifacts(model, feature_cols, imputer)

    print("\nTerminé.")


if __name__ == "__main__":
    main()