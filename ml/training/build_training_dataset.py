import os
from pathlib import Path

import clickhouse_connect
import pandas as pd
from dotenv import load_dotenv

from pipeline_schema import (
    DATASET_COLUMNS,
    RISK_LABEL_TO_CLASS,
    normalize_dataset_schema,
)


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
STEP_UP_CLIENT_IDS_RAW = os.getenv("STEP_UP_CLIENT_IDS", "portal-stepup-totp-client")

REAL_OUTPUT_PATH = DATA_DIR / "real_export.csv"
SYNTHETIC_INPUT_PATH = DATA_DIR / "synthetic_risk_dataset.csv"
FINAL_OUTPUT_PATH = DATA_DIR / "training_dataset_final.csv"


def parse_csv_set(raw: str) -> set:
    return {
        item.strip()
        for item in str(raw or "").split(",")
        if item and item.strip()
    }


def sql_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


STEP_UP_CLIENT_IDS = parse_csv_set(STEP_UP_CLIENT_IDS_RAW)


def step_up_client_exclusion_sql(column: str = "client_id") -> str:
    if not STEP_UP_CLIENT_IDS:
        return "1 = 1"

    values = ", ".join(
        f"'{sql_escape(client_id)}'"
        for client_id in sorted(STEP_UP_CLIENT_IDS)
    )
    return f"{column} NOT IN ({values})"


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
        step_up_client_exclusion_sql(),
    ]

    if HISTORY_RESET_AT:
        where_clauses.append(f"event_time >= toDateTime('{HISTORY_RESET_AT}')")

    query = f"""
    SELECT
        event_time,
        client_id,
        app_sensitivity,
        ua_browser,
        ua_os,
        ua_device,
        geo_country_code,
        asn_org,
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
        is_vpn_detected,
        is_proxy_detected,
        is_tor,
        distance_from_last_location_km,
        is_impossible_travel,
        abuse_confidence_score,
        risk_score AS source_risk_score,
        lower(risk_label) AS source_risk_label,
        decision AS source_decision,
        policy_reason AS source_policy_reason
    FROM {CLICKHOUSE_DATABASE}.login_events
    WHERE {" AND ".join(where_clauses)}
    ORDER BY event_time ASC
    """

    df = client.query_df(query)
    if df.empty:
        return df

    df["risk_label"] = df["source_risk_label"].astype(str).str.lower()
    df["risk_class"] = df["risk_label"].map(RISK_LABEL_TO_CLASS).astype("Int64")
    df["synthetic_rule_score"] = None
    df["data_origin"] = "real"
    return df


def load_synthetic_data() -> pd.DataFrame:
    if not SYNTHETIC_INPUT_PATH.exists():
        raise FileNotFoundError(
            f"Missing file: {SYNTHETIC_INPUT_PATH}. "
            "Run generate_synthetic_dataset.py first."
        )

    df = pd.read_csv(SYNTHETIC_INPUT_PATH)
    if "data_origin" not in df.columns:
        df["data_origin"] = "synthetic"
    return df


def validate_target_classes(df: pd.DataFrame, dataset_name: str):
    invalid_rows = df[~df["risk_label"].isin(RISK_LABEL_TO_CLASS.keys())]
    if not invalid_rows.empty:
        raise ValueError(
            f"{dataset_name} contains unknown labels: "
            f"{sorted(invalid_rows['risk_label'].dropna().unique().tolist())}"
        )


def print_distribution(df: pd.DataFrame, prefix: str):
    print(f"\n{prefix} - distribution by risk_class:")
    print(df["risk_class"].value_counts(dropna=False).sort_index())
    print(f"\n{prefix} - distribution by risk_label:")
    print(df["risk_label"].value_counts(dropna=False).sort_index())


def main():
    print("Exporting real login events from ClickHouse...")
    real_df = export_real_data()
    real_df = normalize_dataset_schema(real_df)
    validate_target_classes(real_df[real_df["risk_class"].notna()], "Real export")
    real_df.to_csv(REAL_OUTPUT_PATH, index=False)
    print(f"Real export saved: {REAL_OUTPUT_PATH}")
    print(f"Real rows: {len(real_df)}")
    if not real_df.empty:
        print_distribution(real_df, "Real")

    print("\nLoading synthetic dataset...")
    synthetic_df = load_synthetic_data()
    synthetic_df = normalize_dataset_schema(synthetic_df)
    validate_target_classes(synthetic_df[synthetic_df["risk_class"].notna()], "Synthetic dataset")
    print(f"Synthetic rows: {len(synthetic_df)}")
    print_distribution(synthetic_df, "Synthetic")

    print("\nMerging datasets...")
    final_df = pd.concat([real_df, synthetic_df], ignore_index=True)
    final_df = normalize_dataset_schema(final_df)
    final_df = final_df.dropna(subset=["event_time", "risk_class"]).copy()
    final_df["risk_class"] = final_df["risk_class"].astype(int)
    final_df = final_df.sort_values("event_time", na_position="last").reset_index(drop=True)
    final_df = final_df[DATASET_COLUMNS].copy()

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
