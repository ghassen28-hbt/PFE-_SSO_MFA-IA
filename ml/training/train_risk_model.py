import json
import os
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from lightgbm import LGBMClassifier
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.frozen import FrozenEstimator
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    log_loss,
    mutual_info_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from pipeline_schema import (
    ABLATION_SETS,
    ALL_FEATURES,
    CALIBRATION_HOLDOUT_RATIO,
    CALIBRATION_METRIC_TOLERANCE,
    CATEGORICAL_FEATURES,
    MRMR_CANDIDATE_TOP_KS,
    MRMR_MIN_FEATURES,
    MRMR_SCORE_FLOOR,
    NUMERIC_FEATURES,
    RISK_CLASS_TO_LABEL,
    SCHEMA_VERSION,
    SCORE_METHOD,
    normalize_dataset_schema,
)

try:
    from xgboost import XGBClassifier

    XGBOOST_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when xgboost is absent
    XGBOOST_AVAILABLE = False


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "artifacts"
MODEL_DIR.mkdir(exist_ok=True)

load_dotenv(BASE_DIR / ".env")

DATASET_PATH = DATA_DIR / "training_dataset_final.csv"
MODEL_PATH = MODEL_DIR / "risk_model_v1.joblib"
FEATURES_PATH = MODEL_DIR / "risk_model_v1_features.json"
MODEL_COMPARISON_PATH = MODEL_DIR / "risk_model_v1_model_comparison.json"
ABLATION_PATH = MODEL_DIR / "risk_model_v1_ablation.json"

REAL_DATA_WEIGHT = float(os.getenv("REAL_DATA_WEIGHT", "3.0"))
MRMR_TOP_K_CANDIDATES = sorted(
    {
        int(item.strip())
        for item in os.getenv("MRMR_TOP_K_CANDIDATES", "6,8,10,12").split(",")
        if item.strip()
    }
)


def load_data() -> pd.DataFrame:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Missing dataset: {DATASET_PATH}. Run build_training_dataset.py first."
        )

    df = pd.read_csv(DATASET_PATH)
    df = normalize_dataset_schema(df)
    if df.empty:
        raise ValueError("The training dataset is empty.")
    return df


def temporal_split(df: pd.DataFrame):
    df = df.sort_values("event_time").reset_index(drop=True)
    n_rows = len(df)
    if n_rows < 80:
        raise ValueError(
            f"Dataset too small ({n_rows} rows). Collect more logins before training."
        )

    train_end = int(n_rows * 0.70)
    valid_end = int(n_rows * 0.85)

    train_df = df.iloc[:train_end].copy()
    valid_df = df.iloc[train_end:valid_end].copy()
    test_df = df.iloc[valid_end:].copy()

    return train_df, valid_df, test_df


def validate_training_frame(df: pd.DataFrame):
    df = df.dropna(subset=["event_time", "risk_class"]).copy()
    df["risk_class"] = pd.to_numeric(df["risk_class"], errors="coerce").astype(int)

    missing_classes = sorted(set(RISK_CLASS_TO_LABEL.keys()) - set(df["risk_class"].unique()))
    if missing_classes:
        raise ValueError(
            f"Missing target classes in dataset: {missing_classes}. "
            "Regenerate synthetic data or collect more real logins."
        )
    return df


def contains_all_classes(df: pd.DataFrame) -> bool:
    return set(df["risk_class"].astype(int).unique()) == set(RISK_CLASS_TO_LABEL.keys())


def split_fit_and_calibration(df: pd.DataFrame, holdout_ratio=CALIBRATION_HOLDOUT_RATIO):
    df = df.sort_values("event_time").reset_index(drop=True)
    min_fit_rows = max(40, MRMR_MIN_FEATURES * 8)
    min_calibration_rows = max(24, len(RISK_CLASS_TO_LABEL) * 4)

    if len(df) < (min_fit_rows + min_calibration_rows):
        return df.copy(), None

    proposed_split = max(min_fit_rows, int(len(df) * (1.0 - holdout_ratio)))
    max_split = len(df) - min_calibration_rows

    for split_index in range(min(proposed_split, max_split), min_fit_rows - 1, -1):
        fit_df = df.iloc[:split_index].copy()
        calibration_df = df.iloc[split_index:].copy()
        if len(calibration_df) < min_calibration_rows:
            continue
        if contains_all_classes(calibration_df):
            return fit_df, calibration_df

    return df.copy(), None


def discretize_numeric_feature(series: pd.Series) -> pd.Series:
    numeric = pd.to_numeric(series, errors="coerce")
    median = numeric.median()
    if pd.isna(median):
        median = 0.0
    filled = numeric.fillna(median)
    if filled.nunique(dropna=True) <= 1:
        return pd.Series(0, index=series.index, dtype=int)
    bins = min(10, max(2, filled.nunique(dropna=True)))
    try:
        return (
            pd.qcut(
                filled.rank(method="first"),
                q=bins,
                labels=False,
                duplicates="drop",
            )
            .fillna(0)
            .astype(int)
        )
    except ValueError:
        return pd.Series(0, index=series.index, dtype=int)


def encode_for_mrmr(df: pd.DataFrame, feature_cols: list[str]) -> pd.DataFrame:
    encoded = pd.DataFrame(index=df.index)
    for feature in feature_cols:
        if feature in CATEGORICAL_FEATURES:
            encoded[feature] = (
                df[feature].fillna("unknown").astype(str).astype("category").cat.codes
            )
        else:
            encoded[feature] = discretize_numeric_feature(df[feature])
    return encoded


def run_mrmr_ranking(train_df: pd.DataFrame, feature_cols: list[str]) -> list[dict]:
    X = encode_for_mrmr(train_df, feature_cols)
    y = train_df["risk_class"].astype(int)

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

    ranking = []
    selected = []
    remaining = list(feature_cols)
    redundancy_cache = {}

    while remaining:
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
        remaining.remove(best_feature)
        ranking.append(
            {
                "feature": best_feature,
                "relevance": round(relevance[best_feature], 6),
                "redundancy": round(best_redundancy, 6),
                "mrmr_score": round(float(best_score), 6),
            }
        )

    return ranking


def build_feature_candidates(ranking: list[dict]) -> list[dict]:
    candidate_top_ks = sorted(set(MRMR_TOP_K_CANDIDATES + MRMR_CANDIDATE_TOP_KS))
    candidates = []
    seen = set()

    positive_features = [item["feature"] for item in ranking if item["mrmr_score"] > MRMR_SCORE_FLOOR]
    if len(positive_features) >= MRMR_MIN_FEATURES:
        key = tuple(positive_features)
        seen.add(key)
        candidates.append(
            {
                "requested_top_k": "positive_only",
                "actual_feature_count": len(positive_features),
                "features": positive_features,
            }
        )

    for requested_top_k in candidate_top_ks:
        prefix = ranking[: min(requested_top_k, len(ranking))]
        selected = [item for item in prefix]

        while (
            len(selected) > MRMR_MIN_FEATURES
            and selected[-1]["mrmr_score"] <= MRMR_SCORE_FLOOR
        ):
            selected.pop()

        features = [item["feature"] for item in selected]
        if len(features) < MRMR_MIN_FEATURES:
            continue

        key = tuple(features)
        if key in seen:
            continue
        seen.add(key)

        candidates.append(
            {
                "requested_top_k": requested_top_k,
                "actual_feature_count": len(features),
                "features": features,
            }
        )

    if not candidates:
        fallback = ranking[:MRMR_MIN_FEATURES]
        candidates.append(
            {
                "requested_top_k": len(fallback),
                "actual_feature_count": len(fallback),
                "features": [item["feature"] for item in fallback],
            }
        )

    return candidates


def build_preprocessor(feature_cols: list[str]) -> ColumnTransformer:
    selected_categorical = [col for col in CATEGORICAL_FEATURES if col in feature_cols]
    selected_numeric = [col for col in NUMERIC_FEATURES if col in feature_cols]

    transformers = []

    if selected_numeric:
        transformers.append(
            (
                "num",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="median")),
                        ("scaler", StandardScaler()),
                    ]
                ),
                selected_numeric,
            )
        )

    if selected_categorical:
        transformers.append(
            (
                "cat",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="constant", fill_value="unknown")),
                        ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
                    ]
                ),
                selected_categorical,
            )
        )

    return ColumnTransformer(transformers=transformers, remainder="drop")


def build_model_candidates():
    models = {
        "lightgbm": LGBMClassifier(
            objective="multiclass",
            num_class=len(RISK_CLASS_TO_LABEL),
            n_estimators=350,
            learning_rate=0.05,
            num_leaves=31,
            max_depth=-1,
            subsample=0.9,
            colsample_bytree=0.9,
            class_weight="balanced",
            random_state=42,
            verbosity=-1,
        ),
        "logistic_regression": LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=42,
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=400,
            class_weight="balanced_subsample",
            random_state=42,
            n_jobs=-1,
        ),
    }

    if XGBOOST_AVAILABLE:
        models["xgboost"] = XGBClassifier(
            objective="multi:softprob",
            num_class=len(RISK_CLASS_TO_LABEL),
            n_estimators=350,
            learning_rate=0.05,
            max_depth=6,
            subsample=0.9,
            colsample_bytree=0.9,
            reg_lambda=1.0,
            random_state=42,
            tree_method="hist",
            eval_metric="mlogloss",
        )

    return models


def compute_sample_weight(df: pd.DataFrame) -> np.ndarray:
    origins = df["data_origin"].astype(str).str.lower()
    return np.where(origins.eq("real"), REAL_DATA_WEIGHT, 1.0)


def fit_pipeline(estimator, feature_cols, train_df, sample_weight=None):
    pipeline = Pipeline(
        steps=[
            ("preprocessor", build_preprocessor(feature_cols)),
            ("model", clone(estimator)),
        ]
    )
    fit_kwargs = {}
    if sample_weight is not None:
        fit_kwargs["model__sample_weight"] = sample_weight
    pipeline.fit(train_df[feature_cols], train_df["risk_class"].astype(int), **fit_kwargs)
    return pipeline


def expected_calibration_error(y_true, probabilities, n_bins=10):
    confidences = probabilities.max(axis=1)
    predictions = probabilities.argmax(axis=1)
    correctness = (predictions == y_true).astype(float)

    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for start, end in zip(bin_edges[:-1], bin_edges[1:]):
        if end == 1.0:
            mask = (confidences >= start) & (confidences <= end)
        else:
            mask = (confidences >= start) & (confidences < end)
        if not np.any(mask):
            continue
        bin_confidence = confidences[mask].mean()
        bin_accuracy = correctness[mask].mean()
        ece += abs(bin_confidence - bin_accuracy) * (mask.sum() / len(y_true))
    return float(ece)


def multiclass_brier_score(y_true, probabilities):
    one_hot = np.eye(len(RISK_CLASS_TO_LABEL))[np.asarray(y_true, dtype=int)]
    return float(np.mean(np.sum((probabilities - one_hot) ** 2, axis=1)))


def normalize_probability_rows(probabilities):
    probabilities = np.asarray(probabilities, dtype=float)
    probabilities = np.clip(probabilities, 1e-12, 1.0)
    row_sums = probabilities.sum(axis=1, keepdims=True)
    row_sums[row_sums <= 0.0] = 1.0
    return probabilities / row_sums


def compute_metrics(y_true, probabilities):
    y_true = np.asarray(y_true, dtype=int)
    probabilities = normalize_probability_rows(probabilities)
    y_pred = np.argmax(probabilities, axis=1)
    labels = list(RISK_CLASS_TO_LABEL.keys())

    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "log_loss": float(log_loss(y_true, probabilities, labels=labels)),
        "expected_calibration_error": expected_calibration_error(y_true, probabilities),
        "multiclass_brier_score": multiclass_brier_score(y_true, probabilities),
    }
    try:
        metrics["macro_roc_auc_ovr"] = float(
            roc_auc_score(y_true, probabilities, multi_class="ovr", average="macro", labels=labels)
        )
    except ValueError:
        metrics["macro_roc_auc_ovr"] = None
    return metrics


def evaluate_pipeline(pipeline, df, feature_cols):
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="X does not have valid feature names, but LGBMClassifier was fitted with feature names",
            category=UserWarning,
        )
        probabilities = normalize_probability_rows(pipeline.predict_proba(df[feature_cols]))
    metrics = compute_metrics(df["risk_class"].astype(int), probabilities)
    return metrics, probabilities


def select_best_result(results: list[dict]) -> dict:
    def score_key(item: dict):
        metrics = item["validation_metrics"]
        return (
            metrics["macro_f1"],
            metrics["balanced_accuracy"],
            metrics["weighted_f1"],
            metrics.get("macro_roc_auc_ovr") or -1.0,
            -metrics["log_loss"],
            -metrics["expected_calibration_error"],
            -metrics["multiclass_brier_score"],
            -item["actual_feature_count"],
        )

    return max(results, key=score_key)


def compare_models(train_df, valid_df, feature_candidates):
    model_candidates = build_model_candidates()
    sample_weight = compute_sample_weight(train_df)
    comparison_results = []

    for candidate in feature_candidates:
        for model_name, estimator in model_candidates.items():
            pipeline = fit_pipeline(
                estimator=estimator,
                feature_cols=candidate["features"],
                train_df=train_df,
                sample_weight=sample_weight,
            )
            validation_metrics, _ = evaluate_pipeline(pipeline, valid_df, candidate["features"])
            comparison_results.append(
                {
                    "model_name": model_name,
                    "requested_top_k": candidate["requested_top_k"],
                    "actual_feature_count": candidate["actual_feature_count"],
                    "selected_features": candidate["features"],
                    "validation_metrics": validation_metrics,
                }
            )

    return comparison_results


def run_ablation_study(best_model_name, train_df, valid_df):
    estimator = build_model_candidates()[best_model_name]
    sample_weight = compute_sample_weight(train_df)
    results = {}

    for name, feature_set in ABLATION_SETS.items():
        available_features = [feature for feature in feature_set if feature in ALL_FEATURES]
        pipeline = fit_pipeline(estimator, available_features, train_df, sample_weight=sample_weight)
        metrics, _ = evaluate_pipeline(pipeline, valid_df, available_features)
        results[name] = {
            "feature_count": len(available_features),
            "features": available_features,
            "validation_metrics": metrics,
        }

    return results


def fit_holdout_calibrator(base_pipeline, calibration_df, feature_cols):
    frozen_estimator = FrozenEstimator(base_pipeline)
    calibrator = CalibratedClassifierCV(estimator=frozen_estimator, method="sigmoid")
    calibrator.fit(calibration_df[feature_cols], calibration_df["risk_class"].astype(int))
    return calibrator


def select_calibration_variant(raw_metrics: dict, calibrated_metrics: dict | None):
    if not calibrated_metrics:
        return {
            "selected_variant": "raw",
            "reason": "no_valid_calibration_holdout_with_all_classes",
            "raw_validation_metrics": raw_metrics,
            "calibrated_validation_metrics": None,
        }

    classification_drop = (
        raw_metrics["macro_f1"] - calibrated_metrics["macro_f1"] > CALIBRATION_METRIC_TOLERANCE
        or raw_metrics["balanced_accuracy"] - calibrated_metrics["balanced_accuracy"]
        > CALIBRATION_METRIC_TOLERANCE
    )
    probability_improvement = (
        raw_metrics["log_loss"] - calibrated_metrics["log_loss"] >= CALIBRATION_METRIC_TOLERANCE
        and raw_metrics["expected_calibration_error"]
        - calibrated_metrics["expected_calibration_error"]
        >= CALIBRATION_METRIC_TOLERANCE
        and raw_metrics["multiclass_brier_score"]
        - calibrated_metrics["multiclass_brier_score"]
        >= CALIBRATION_METRIC_TOLERANCE
    )

    if classification_drop:
        selected_variant = "raw"
        reason = "raw_kept_because_calibration_hurt_classification"
    elif probability_improvement:
        selected_variant = "calibrated"
        reason = "calibrated_selected_for_better_probability_quality"
    else:
        selected_variant = "raw"
        reason = "raw_kept_because_calibration_gain_was_insufficient"

    return {
        "selected_variant": selected_variant,
        "reason": reason,
        "raw_validation_metrics": raw_metrics,
        "calibrated_validation_metrics": calibrated_metrics,
    }


def summarize_confusion(y_true, probabilities):
    labels = list(RISK_CLASS_TO_LABEL.keys())
    class_names = [RISK_CLASS_TO_LABEL[label] for label in labels]
    predictions = np.argmax(probabilities, axis=1)
    matrix = confusion_matrix(y_true, predictions, labels=labels)
    report = classification_report(
        y_true,
        predictions,
        labels=labels,
        target_names=class_names,
        zero_division=0,
        output_dict=True,
    )
    return {
        "labels": class_names,
        "matrix": matrix.tolist(),
        "classification_report": report,
    }


def save_json(path: Path, payload: dict):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(payload, file, ensure_ascii=True, indent=2)


def save_artifacts(
    predictor,
    base_pipeline,
    best_result,
    full_ranking,
    comparison_results,
    ablation_results,
    raw_test_metrics,
    calibrated_test_metrics,
    final_test_metrics,
    final_probabilities,
    test_df,
    calibration_summary,
    selected_predictor_variant,
    calibration_method,
):
    feature_cols = best_result["selected_features"]
    selected_categorical = [col for col in CATEGORICAL_FEATURES if col in feature_cols]
    selected_numeric = [col for col in NUMERIC_FEATURES if col in feature_cols]

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "predictor": predictor,
        "base_pipeline": base_pipeline,
        "selected_model_name": best_result["model_name"],
        "selected_predictor_variant": selected_predictor_variant,
        "selected_features": feature_cols,
        "selected_categorical_features": selected_categorical,
        "selected_numeric_features": selected_numeric,
        "class_mapping": {str(key): value for key, value in RISK_CLASS_TO_LABEL.items()},
        "mrmr_ranking": full_ranking,
        "selected_top_k_requested": best_result["requested_top_k"],
        "selected_feature_count": best_result["actual_feature_count"],
        "validation_metrics": best_result["validation_metrics"],
        "test_metrics": final_test_metrics,
        "raw_test_metrics": raw_test_metrics,
        "calibrated_test_metrics": calibrated_test_metrics,
        "calibration_summary": calibration_summary,
        "score_method": SCORE_METHOD,
        "calibration_method": calibration_method,
        "real_data_weight": REAL_DATA_WEIGHT,
    }
    joblib.dump(artifact, MODEL_PATH)

    confusion_summary = summarize_confusion(test_df["risk_class"].astype(int), final_probabilities)
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "selected_model_name": best_result["model_name"],
        "selected_predictor_variant": selected_predictor_variant,
        "selected_features": feature_cols,
        "selected_categorical_features": selected_categorical,
        "selected_numeric_features": selected_numeric,
        "target_col": "risk_class",
        "class_mapping": {str(key): value for key, value in RISK_CLASS_TO_LABEL.items()},
        "mrmr_candidate_top_ks": MRMR_TOP_K_CANDIDATES,
        "mrmr_score_floor": MRMR_SCORE_FLOOR,
        "mrmr_ranking": full_ranking,
        "selected_top_k_requested": best_result["requested_top_k"],
        "selected_feature_count": best_result["actual_feature_count"],
        "validation_metrics": best_result["validation_metrics"],
        "test_metrics": final_test_metrics,
        "raw_test_metrics": raw_test_metrics,
        "calibrated_test_metrics": calibrated_test_metrics,
        "calibration_summary": calibration_summary,
        "score_method": SCORE_METHOD,
        "calibration_method": calibration_method,
        "available_models": list(build_model_candidates().keys()),
        "confusion_summary": confusion_summary,
    }

    save_json(FEATURES_PATH, metadata)
    save_json(MODEL_COMPARISON_PATH, {"results": comparison_results, "best_result": best_result})
    save_json(ABLATION_PATH, ablation_results)


def main():
    print("Loading dataset...")
    df = load_data()
    df = validate_training_frame(df)
    print(f"Rows loaded: {len(df)}")

    train_df, valid_df, test_df = temporal_split(df)
    print(f"Train rows: {len(train_df)}")
    print(f"Valid rows: {len(valid_df)}")
    print(f"Test rows: {len(test_df)}")

    print("\nRunning mRMR ranking on train split only...")
    full_ranking = run_mrmr_ranking(train_df, ALL_FEATURES)
    feature_candidates = build_feature_candidates(full_ranking)
    print("Feature candidates:")
    for candidate in feature_candidates:
        print(
            f"- top_k={candidate['requested_top_k']} -> {candidate['actual_feature_count']} features: "
            f"{', '.join(candidate['features'])}"
        )

    print("\nComparing candidate models on validation split...")
    comparison_results = compare_models(train_df, valid_df, feature_candidates)
    best_result = select_best_result(comparison_results)
    selected_features = best_result["selected_features"]
    estimator = build_model_candidates()[best_result["model_name"]]
    print(f"Best validation configuration: {best_result['model_name']} / {selected_features}")

    print("\nRunning ablation study...")
    ablation_results = run_ablation_study(best_result["model_name"], train_df, valid_df)

    print("\nSelecting raw vs calibrated probabilities on validation split...")
    calibration_fit_df, calibration_df = split_fit_and_calibration(train_df)
    validation_base_pipeline = fit_pipeline(
        estimator,
        selected_features,
        calibration_fit_df,
        sample_weight=compute_sample_weight(calibration_fit_df),
    )
    raw_validation_metrics, _ = evaluate_pipeline(validation_base_pipeline, valid_df, selected_features)

    calibrated_validation_metrics = None
    if calibration_df is not None:
        validation_calibrator = fit_holdout_calibrator(
            validation_base_pipeline,
            calibration_df,
            selected_features,
        )
        calibrated_validation_metrics, _ = evaluate_pipeline(
            validation_calibrator,
            valid_df,
            selected_features,
        )

    calibration_summary = select_calibration_variant(
        raw_validation_metrics,
        calibrated_validation_metrics,
    )
    print(
        "Probability variant:",
        calibration_summary["selected_variant"],
        f"({calibration_summary['reason']})",
    )

    print("\nRefitting final predictors on train+validation...")
    train_valid_df = (
        pd.concat([train_df, valid_df], axis=0)
        .sort_values("event_time")
        .reset_index(drop=True)
    )
    raw_final_pipeline = fit_pipeline(
        estimator,
        selected_features,
        train_valid_df,
        sample_weight=compute_sample_weight(train_valid_df),
    )
    raw_test_metrics, raw_probabilities = evaluate_pipeline(
        raw_final_pipeline,
        test_df,
        selected_features,
    )

    calibrated_final_predictor = None
    calibrated_base_pipeline = None
    calibrated_test_metrics = None
    calibrated_probabilities = None

    final_fit_df, final_calibration_df = split_fit_and_calibration(train_valid_df)
    if final_calibration_df is not None:
        calibrated_base_pipeline = fit_pipeline(
            estimator,
            selected_features,
            final_fit_df,
            sample_weight=compute_sample_weight(final_fit_df),
        )
        calibrated_final_predictor = fit_holdout_calibrator(
            calibrated_base_pipeline,
            final_calibration_df,
            selected_features,
        )
        calibrated_test_metrics, calibrated_probabilities = evaluate_pipeline(
            calibrated_final_predictor,
            test_df,
            selected_features,
        )

    if (
        calibration_summary["selected_variant"] == "calibrated"
        and calibrated_final_predictor is not None
    ):
        predictor = calibrated_final_predictor
        base_pipeline = calibrated_base_pipeline
        final_test_metrics = calibrated_test_metrics
        final_probabilities = calibrated_probabilities
        selected_predictor_variant = "calibrated"
        calibration_method = "sigmoid_holdout_frozen_estimator"
    else:
        predictor = raw_final_pipeline
        base_pipeline = raw_final_pipeline
        final_test_metrics = raw_test_metrics
        final_probabilities = raw_probabilities
        selected_predictor_variant = "raw"
        calibration_method = "none_raw_probabilities"

    print("\n===== FINAL TEST METRICS =====")
    for key, value in final_test_metrics.items():
        print(f"{key}: {value}")

    print("\nSaving artifacts...")
    save_artifacts(
        predictor=predictor,
        base_pipeline=base_pipeline,
        best_result=best_result,
        full_ranking=full_ranking,
        comparison_results=comparison_results,
        ablation_results=ablation_results,
        raw_test_metrics=raw_test_metrics,
        calibrated_test_metrics=calibrated_test_metrics,
        final_test_metrics=final_test_metrics,
        final_probabilities=final_probabilities,
        test_df=test_df,
        calibration_summary=calibration_summary,
        selected_predictor_variant=selected_predictor_variant,
        calibration_method=calibration_method,
    )

    print(f"Model saved: {MODEL_PATH}")
    print(f"Feature metadata saved: {FEATURES_PATH}")
    print(f"Model comparison saved: {MODEL_COMPARISON_PATH}")
    print(f"Ablation study saved: {ABLATION_PATH}")


if __name__ == "__main__":
    main()
