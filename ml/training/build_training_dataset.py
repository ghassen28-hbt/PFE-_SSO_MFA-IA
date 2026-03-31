import os
from pathlib import Path

import pandas as pd
import clickhouse_connect
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

load_dotenv(BASE_DIR / ".env")

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DATABASE = os.getenv("CLICKHOUSE_DATABASE", "iam")

REAL_OUTPUT_PATH = DATA_DIR / "real_export.csv"
SYNTHETIC_INPUT_PATH = DATA_DIR / "synthetic_risk_dataset.csv"
FINAL_OUTPUT_PATH = DATA_DIR / "training_dataset_final.csv"


def export_real_data() -> pd.DataFrame:
    client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE,
    )

    query = f"""
    SELECT
        event_time,
        client_id,
        app_sensitivity,
        ua_browser,
        ua_os,
        ua_device,
        hour,
        day_of_week,
        is_weekend,
        is_night_login,
        is_business_hours,
        is_new_device,
        is_new_ip_for_user,
        fails_5m,
        fails_1h,
        fails_24h,
        login_1h,
        step_up_required
    FROM {CLICKHOUSE_DATABASE}.risk_training_dataset_v1
    ORDER BY event_time ASC
    """

    df = client.query_df(query)

    if not df.empty:
        df["data_origin"] = "real"

    return df


def load_synthetic_data() -> pd.DataFrame:
    if not SYNTHETIC_INPUT_PATH.exists():
        raise FileNotFoundError(
            f"Fichier introuvable : {SYNTHETIC_INPUT_PATH}"
        )

    df = pd.read_csv(SYNTHETIC_INPUT_PATH)

    if "data_origin" not in df.columns:
        df["data_origin"] = "synthetic"

    return df


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    expected_cols = [
        "event_time",
        "client_id",
        "app_sensitivity",
        "ua_browser",
        "ua_os",
        "ua_device",
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
        "step_up_required",
        "data_origin",
    ]

    for col in expected_cols:
        if col not in df.columns:
            df[col] = None

    df = df[expected_cols].copy()
    return df


def main():
    print("Export des données réelles depuis ClickHouse...")
    real_df = export_real_data()
    real_df = normalize_columns(real_df)
    real_df.to_csv(REAL_OUTPUT_PATH, index=False)
    print(f"Export réel sauvegardé : {REAL_OUTPUT_PATH}")
    print(f"Nombre de lignes réelles : {len(real_df)}")

    print("\nChargement du dataset synthétique...")
    synthetic_df = load_synthetic_data()
    synthetic_df = normalize_columns(synthetic_df)
    print(f"Nombre de lignes synthétiques : {len(synthetic_df)}")

    print("\nFusion des datasets...")
    final_df = pd.concat([real_df, synthetic_df], ignore_index=True)

    final_df["event_time"] = pd.to_datetime(final_df["event_time"], errors="coerce")
    final_df = final_df.sort_values("event_time", na_position="last").reset_index(drop=True)

    final_df.to_csv(FINAL_OUTPUT_PATH, index=False)

    print(f"Dataset final sauvegardé : {FINAL_OUTPUT_PATH}")
    print(f"Nombre total de lignes : {len(final_df)}")

    print("\nDistribution globale de la cible :")
    print(final_df["step_up_required"].value_counts(dropna=False).sort_index())

    print("\nRépartition par origine :")
    print(final_df["data_origin"].value_counts(dropna=False))

    print("\nCrosstab origine / cible :")
    print(pd.crosstab(final_df["data_origin"], final_df["step_up_required"]))


if __name__ == "__main__":
    main()