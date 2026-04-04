import os
from pathlib import Path

import clickhouse_connect
import pandas as pd
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
HISTORY_RESET_AT = os.getenv("HISTORY_RESET_AT", "").strip()

REAL_OUTPUT_PATH = DATA_DIR / "real_export.csv"
SYNTHETIC_INPUT_PATH = DATA_DIR / "synthetic_risk_dataset.csv"
FINAL_OUTPUT_PATH = DATA_DIR / "training_dataset_final.csv"

RISK_CLASS_MAP = {
    "low": 0,
    "moderate": 1,
    "high": 2,
    "critical": 3,
}

EXPECTED_COLS = [
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
    "risk_label",
    "risk_class",
    "data_origin",
]


def export_real_data() -> pd.DataFrame:
    client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE,
    )

    where_clauses = [
        "event_type = 'LOGIN'",
        "event_success = 1",
        "scoring_status = 'ok'",
        "lower(risk_label) IN ('low', 'moderate', 'high', 'critical')",
    ]

    if HISTORY_RESET_AT:
        where_clauses.append(
            f"event_time >= toDateTime('{HISTORY_RESET_AT}')"
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
        lower(risk_label) AS risk_label
    FROM {CLICKHOUSE_DATABASE}.login_events
    WHERE {" AND ".join(where_clauses)}
    ORDER BY event_time ASC
    """

    df = client.query_df(query)

    if df.empty:
        return df

    df["risk_class"] = df["risk_label"].map(RISK_CLASS_MAP).astype("Int64")
    df["data_origin"] = "real"
    return df


def load_synthetic_data() -> pd.DataFrame:
    if not SYNTHETIC_INPUT_PATH.exists():
        raise FileNotFoundError(
            f"Missing file: {SYNTHETIC_INPUT_PATH}. "
            "Run generate_synthetic_dataset.py first."
        )

    df = pd.read_csv(SYNTHETIC_INPUT_PATH)

    if "risk_label" not in df.columns and "risk_class" in df.columns:
        reverse_map = {value: key for key, value in RISK_CLASS_MAP.items()}
        df["risk_label"] = pd.to_numeric(
            df["risk_class"], errors="coerce"
        ).map(reverse_map)

    if "risk_class" not in df.columns and "risk_label" in df.columns:
        df["risk_class"] = (
            df["risk_label"].astype(str).str.lower().map(RISK_CLASS_MAP)
        )

    if "data_origin" not in df.columns:
        df["data_origin"] = "synthetic"

    return df


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    for col in EXPECTED_COLS:
        if col not in df.columns:
            df[col] = None

    df = df[EXPECTED_COLS].copy()

    df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce")
    df["risk_label"] = df["risk_label"].astype(str).str.lower()
    df["risk_class"] = pd.to_numeric(df["risk_class"], errors="coerce").astype("Int64")

    return df


def print_distribution(df: pd.DataFrame, prefix: str):
    print(f"\n{prefix} - distribution by risk_class:")
    print(df["risk_class"].value_counts(dropna=False).sort_index())
    print(f"\n{prefix} - distribution by risk_label:")
    print(df["risk_label"].value_counts(dropna=False).sort_index())


def main():
    print("Exporting real login events from ClickHouse...")
    real_df = export_real_data()
    real_df = normalize_columns(real_df)
    real_df.to_csv(REAL_OUTPUT_PATH, index=False)
    print(f"Real export saved: {REAL_OUTPUT_PATH}")
    print(f"Real rows: {len(real_df)}")
    if not real_df.empty:
        print_distribution(real_df, "Real")

    print("\nLoading synthetic dataset...")
    synthetic_df = load_synthetic_data()
    synthetic_df = normalize_columns(synthetic_df)
    print(f"Synthetic rows: {len(synthetic_df)}")
    print_distribution(synthetic_df, "Synthetic")

    print("\nMerging datasets...")
    final_df = pd.concat([real_df, synthetic_df], ignore_index=True)
    final_df = final_df.dropna(subset=["event_time", "risk_class"]).copy()
    final_df["risk_class"] = final_df["risk_class"].astype(int)
    final_df = final_df.sort_values("event_time", na_position="last").reset_index(drop=True)

    final_df.to_csv(FINAL_OUTPUT_PATH, index=False)

    print(f"Final dataset saved: {FINAL_OUTPUT_PATH}")
    print(f"Total rows: {len(final_df)}")
    print_distribution(final_df, "Final")

    print("\nDistribution by origin:")
    print(final_df["data_origin"].value_counts(dropna=False))

    print("\nOrigin / risk_class cross-tab:")
    print(pd.crosstab(final_df["data_origin"], final_df["risk_class"]))


if __name__ == "__main__":
    main()
