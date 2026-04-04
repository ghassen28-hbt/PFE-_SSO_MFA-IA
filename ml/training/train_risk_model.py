import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from lightgbm import LGBMClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    mutual_info_score,
    roc_auc_score,
)


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "artifacts"
MODEL_DIR.mkdir(exist_ok=True)

load_dotenv(BASE_DIR / ".env")

DATASET_PATH = DATA_DIR / "training_dataset_final.csv"
MODEL_PATH = MODEL_DIR / "risk_model_v1.joblib"
FEATURES_PATH = MODEL_DIR / "risk_model_v1_features.json"

MRMR_TOP_K = int(os.getenv("MRMR_TOP_K", "10"))

RISK_CLASS_TO_LABEL = {
    0: "low",
    1: "moderate",
    2: "high",
    3: "critical",
}

CATEGORICAL_COLS = [
    "client_id",
    "ua_browser",
    "ua_os",
    "ua_device",
]

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


def load_data() -> pd.DataFrame:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Missing dataset: {DATASET_PATH}. Run build_training_dataset.py first."
        )

    return pd.read_csv(DATASET_PATH)


def prepare_data(df: pd.DataFrame):
    if df.empty:
        raise ValueError("The training dataset is empty.")

    target_col = "risk_class"
    feature_cols = CATEGORICAL_COLS + NUMERIC_COLS

    df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce")
    df = df.dropna(subset=["event_time", target_col]).copy()

    for col in CATEGORICAL_COLS:
        df[col] = df[col].fillna("unknown").astype(str).astype("category")

    for col in NUMERIC_COLS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    imputer = SimpleImputer(strategy="median")
    df[NUMERIC_COLS] = imputer.fit_transform(df[NUMERIC_COLS])

    df[target_col] = pd.to_numeric(df[target_col], errors="coerce").astype(int)
    df["risk_label"] = (
        df.get("risk_label", pd.Series(index=df.index))
        .fillna(df[target_col].map(RISK_CLASS_TO_LABEL))
        .astype(str)
        .str.lower()
    )

    missing_classes = sorted(
        set(RISK_CLASS_TO_LABEL.keys()) - set(df[target_col].unique())
    )
    if missing_classes:
        raise ValueError(
            f"Missing target classes in dataset: {missing_classes}. "
            "Regenerate synthetic data or collect more real logins."
        )

    return df, feature_cols, target_col, imputer


def discretize_numeric_feature(series: pd.Series) -> pd.Series:
    values = pd.to_numeric(series, errors="coerce")
    filled = values.fillna(values.median())

    if filled.nunique(dropna=True) <= 1:
        return pd.Series(0, index=series.index, dtype=int)

    q = int(min(10, filled.nunique(dropna=True)))
    if q < 2:
        return pd.Series(0, index=series.index, dtype=int)

    try:
        bins = pd.qcut(
            filled.rank(method="first"),
            q=q,
            labels=False,
            duplicates="drop",
        )
        return pd.Series(bins, index=series.index).fillna(0).astype(int)
    except ValueError:
        return pd.Series(0, index=series.index, dtype=int)


def encode_for_mrmr(
    df: pd.DataFrame,
    feature_cols,
    categorical_cols,
    numeric_cols,
) -> pd.DataFrame:
    encoded = pd.DataFrame(index=df.index)

    for col in feature_cols:
        if col in categorical_cols:
            encoded[col] = df[col].astype("category").cat.codes.astype(int)
        elif col in numeric_cols:
            encoded[col] = discretize_numeric_feature(df[col])
        else:
            encoded[col] = 0

    return encoded


def run_mrmr_selection(
    df: pd.DataFrame,
    feature_cols,
    categorical_cols,
    numeric_cols,
    target_col: str,
    top_k: int,
):
    encoded = encode_for_mrmr(df, feature_cols, categorical_cols, numeric_cols)
    X = encoded[feature_cols]
    y = df[target_col].astype(int)

    top_k = max(1, min(top_k, len(feature_cols)))

    relevance_scores = mutual_info_classif(
        X,
        y,
        discrete_features=True,
        random_state=42,
    )
    relevance = {
        feature: float(score)
        for feature, score in zip(feature_cols, relevance_scores)
    }

    selected = []
    ranking = []
    remaining = list(feature_cols)
    redundancy_cache = {}

    while remaining and len(selected) < top_k:
        best_feature = None
        best_score = None
        best_redundancy = 0.0

        for feature in remaining:
            if not selected:
                redundancy = 0.0
                mrmr_score = relevance[feature]
            else:
                pair_scores = []
                for selected_feature in selected:
                    key = tuple(sorted((feature, selected_feature)))
                    if key not in redundancy_cache:
                        redundancy_cache[key] = float(
                            mutual_info_score(X[feature], X[selected_feature])
                        )
                    pair_scores.append(redundancy_cache[key])

                redundancy = float(np.mean(pair_scores)) if pair_scores else 0.0
                mrmr_score = relevance[feature] - redundancy

            if best_score is None or mrmr_score > best_score:
                best_feature = feature
                best_score = mrmr_score
                best_redundancy = redundancy

        selected.append(best_feature)
        ranking.append(
            {
                "feature": best_feature,
                "relevance": round(relevance[best_feature], 6),
                "redundancy": round(best_redundancy, 6),
                "mrmr_score": round(float(best_score), 6),
            }
        )
        remaining.remove(best_feature)

    return selected, ranking


def temporal_split(df: pd.DataFrame, feature_cols, target_col: str):
    df = df.sort_values("event_time").reset_index(drop=True)

    n_rows = len(df)
    if n_rows < 40:
        raise ValueError(
            f"Dataset too small ({n_rows} rows). "
            "Collect more logins before training."
        )

    train_end = int(n_rows * 0.70)
    valid_end = int(n_rows * 0.85)

    train_df = df.iloc[:train_end].copy()
    valid_df = df.iloc[train_end:valid_end].copy()
    test_df = df.iloc[valid_end:].copy()

    return (
        train_df[feature_cols],
        train_df[target_col].astype(int),
        valid_df[feature_cols],
        valid_df[target_col].astype(int),
        test_df[feature_cols],
        test_df[target_col].astype(int),
    )


def train_model(X_train, y_train, X_valid, y_valid, categorical_cols):
    class_counts = y_train.value_counts().sort_index()
    n_samples = len(y_train)
    n_classes = len(RISK_CLASS_TO_LABEL)
    class_weight = {
        int(class_id): n_samples / (n_classes * int(count))
        for class_id, count in class_counts.items()
        if int(count) > 0
    }

    model = LGBMClassifier(
        objective="multiclass",
        num_class=n_classes,
        n_estimators=400,
        learning_rate=0.05,
        num_leaves=31,
        max_depth=-1,
        min_child_samples=20,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight=class_weight,
        random_state=42,
        verbosity=-1,
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_valid, y_valid)],
        eval_metric="multi_logloss",
        categorical_feature=categorical_cols,
    )

    return model, class_weight


def evaluate_model(model, X_test, y_test, feature_cols):
    class_order = list(RISK_CLASS_TO_LABEL.keys())
    class_names = [RISK_CLASS_TO_LABEL[class_id] for class_id in class_order]

    y_prob = model.predict_proba(X_test)
    y_pred = np.argmax(y_prob, axis=1)

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, y_pred)),
        "macro_f1": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(
            f1_score(y_test, y_pred, average="weighted", zero_division=0)
        ),
    }

    try:
        metrics["macro_roc_auc_ovr"] = float(
            roc_auc_score(
                y_test,
                y_prob,
                multi_class="ovr",
                average="macro",
                labels=class_order,
            )
        )
    except ValueError:
        metrics["macro_roc_auc_ovr"] = None

    confusion = confusion_matrix(y_test, y_pred, labels=class_order)
    report = classification_report(
        y_test,
        y_pred,
        labels=class_order,
        target_names=class_names,
        zero_division=0,
    )

    importances = pd.DataFrame(
        {
            "feature": feature_cols,
            "importance": model.feature_importances_,
        }
    ).sort_values("importance", ascending=False)

    print("\n===== TEST METRICS =====")
    for metric_name, metric_value in metrics.items():
        print(f"{metric_name}: {metric_value}")

    print("\n===== CONFUSION MATRIX =====")
    print(pd.DataFrame(confusion, index=class_names, columns=class_names))

    print("\n===== CLASSIFICATION REPORT =====")
    print(report)

    print("\n===== FEATURE IMPORTANCE =====")
    print(importances.to_string(index=False))

    return metrics, importances, report, confusion


def save_artifacts(
    model,
    imputer,
    selected_features,
    selected_categorical_cols,
    selected_numeric_cols,
    mrmr_ranking,
    metrics,
    importances,
    class_weight,
):
    artifact = {
        "model": model,
        "imputer": imputer,
        "feature_cols": selected_features,
        "selected_categorical_cols": selected_categorical_cols,
        "selected_numeric_cols": selected_numeric_cols,
        "all_categorical_cols": CATEGORICAL_COLS,
        "all_numeric_cols": NUMERIC_COLS,
        "target_col": "risk_class",
        "class_mapping": {str(k): v for k, v in RISK_CLASS_TO_LABEL.items()},
        "mrmr_ranking": mrmr_ranking,
        "metrics": metrics,
        "class_weight": class_weight,
        "feature_importance": importances.to_dict(orient="records"),
    }
    joblib.dump(artifact, MODEL_PATH)

    features_metadata = {
        "selected_features": selected_features,
        "selected_categorical_features": selected_categorical_cols,
        "selected_numeric_features": selected_numeric_cols,
        "target_col": "risk_class",
        "class_mapping": {str(k): v for k, v in RISK_CLASS_TO_LABEL.items()},
        "mrmr_top_k": len(selected_features),
        "mrmr_ranking": mrmr_ranking,
        "metrics": metrics,
    }

    with open(FEATURES_PATH, "w", encoding="utf-8") as feature_file:
        json.dump(features_metadata, feature_file, ensure_ascii=True, indent=2)

    print(f"\nModel saved: {MODEL_PATH}")
    print(f"Feature metadata saved: {FEATURES_PATH}")


def main():
    print("Loading training dataset...")
    df = load_data()
    print(f"Rows loaded: {len(df)}")

    print("\nPreparing data...")
    df, feature_cols, target_col, imputer = prepare_data(df)

    print("\nTarget distribution:")
    print(df[target_col].value_counts(dropna=False).sort_index())

    print("\nRunning mRMR feature selection...")
    selected_features, mrmr_ranking = run_mrmr_selection(
        df=df,
        feature_cols=feature_cols,
        categorical_cols=CATEGORICAL_COLS,
        numeric_cols=NUMERIC_COLS,
        target_col=target_col,
        top_k=MRMR_TOP_K,
    )
    selected_categorical_cols = [
        col for col in CATEGORICAL_COLS if col in selected_features
    ]
    selected_numeric_cols = [col for col in NUMERIC_COLS if col in selected_features]

    print("Selected features:")
    for item in mrmr_ranking:
        print(
            f"- {item['feature']}: relevance={item['relevance']}, "
            f"redundancy={item['redundancy']}, mrmr={item['mrmr_score']}"
        )

    print("\nTemporal split...")
    X_train, y_train, X_valid, y_valid, X_test, y_test = temporal_split(
        df,
        selected_features,
        target_col,
    )
    print(f"Train rows: {len(X_train)}")
    print(f"Valid rows: {len(X_valid)}")
    print(f"Test rows: {len(X_test)}")

    print("\nTraining multiclass LightGBM...")
    model, class_weight = train_model(
        X_train,
        y_train,
        X_valid,
        y_valid,
        selected_categorical_cols,
    )

    print("\nEvaluating model...")
    metrics, importances, _, _ = evaluate_model(
        model,
        X_test,
        y_test,
        selected_features,
    )

    print("\nSaving artifacts...")
    save_artifacts(
        model=model,
        imputer=imputer,
        selected_features=selected_features,
        selected_categorical_cols=selected_categorical_cols,
        selected_numeric_cols=selected_numeric_cols,
        mrmr_ranking=mrmr_ranking,
        metrics=metrics,
        importances=importances,
        class_weight=class_weight,
    )

    print("\nDone.")


if __name__ == "__main__":
    main()
