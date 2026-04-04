import random
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

OUTPUT_PATH = DATA_DIR / "synthetic_risk_dataset.csv"

RISK_CLASS_MAP = {
    "low": 0,
    "moderate": 1,
    "high": 2,
    "critical": 3,
}

CLASS_TARGETS = {
    "low": 260,
    "moderate": 130,
    "high": 70,
    "critical": 40,
}

BROWSERS = ["Chrome", "Brave", "Firefox", "Edge"]
OPERATING_SYSTEMS = ["Windows 11", "Windows 10", "Ubuntu", "macOS"]
DEVICES = ["pc", "laptop"]

CLIENTS = [
    ("portal-main-client", 1),
    ("crm-client-2", 2),
    ("hr-client-4", 3),
    ("finance-client-3", 4),
    ("admin-console-client-1", 5),
]


def random_datetime(start_days_ago: int = 45) -> datetime:
    now = datetime.now()
    start = now - timedelta(days=start_days_ago)
    delta = now - start
    random_seconds = random.randint(0, int(delta.total_seconds()))
    return start + timedelta(seconds=random_seconds)


def assign_risk_label(row: dict) -> str:
    app_sensitivity = int(row["app_sensitivity"])
    is_new_device = int(row["is_new_device"])
    is_new_ip_for_user = int(row["is_new_ip_for_user"])
    fails_5m = int(row["fails_5m"])
    fails_1h = int(row["fails_1h"])
    fails_24h = int(row["fails_24h"])
    login_1h = int(row["login_1h"])
    is_night_login = int(row["is_night_login"])
    is_business_hours = int(row["is_business_hours"])

    anomaly_count = is_new_device + is_new_ip_for_user

    if (
        fails_5m >= 5
        or fails_1h >= 8
        or fails_24h >= 12
        or (app_sensitivity >= 5 and anomaly_count >= 2 and fails_1h >= 2)
        or (anomaly_count >= 2 and fails_5m >= 3)
        or (is_night_login == 1 and app_sensitivity >= 5 and anomaly_count >= 2)
    ):
        return "critical"

    if (
        fails_5m >= 3
        or fails_1h >= 4
        or anomaly_count >= 2
        or (app_sensitivity >= 4 and anomaly_count >= 1)
        or (app_sensitivity >= 4 and fails_1h >= 2)
        or (is_night_login == 1 and app_sensitivity >= 4)
    ):
        return "high"

    if (
        fails_5m >= 2
        or fails_1h >= 2
        or (anomaly_count == 1 and app_sensitivity >= 3)
        or (app_sensitivity >= 3 and login_1h >= 3)
        or (is_night_login == 1 and app_sensitivity >= 3)
        or (is_business_hours == 0 and app_sensitivity >= 4)
    ):
        return "moderate"

    return "low"


def sample_hour(profile: str) -> int:
    if profile == "low":
        weights = [
            1, 1, 1, 1, 1, 1,
            2, 4, 8, 10, 10, 10,
            10, 10, 9, 8, 7, 6,
            4, 3, 2, 1, 1, 1,
        ]
    elif profile == "moderate":
        weights = [
            3, 3, 3, 3, 2, 2,
            3, 4, 6, 8, 8, 8,
            8, 8, 7, 7, 6, 5,
            5, 4, 4, 3, 3, 3,
        ]
    elif profile == "high":
        weights = [
            5, 5, 5, 5, 4, 4,
            3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3,
            4, 4, 5, 5, 5, 5,
        ]
    else:
        weights = [
            8, 8, 8, 8, 7, 6,
            4, 3, 2, 1, 1, 1,
            1, 1, 1, 1, 1, 2,
            3, 4, 5, 6, 7, 8,
        ]

    return random.choices(list(range(24)), weights=weights, k=1)[0]


def sample_client(profile: str):
    if profile == "low":
        weights = [40, 24, 16, 12, 8]
    elif profile == "moderate":
        weights = [18, 24, 24, 20, 14]
    elif profile == "high":
        weights = [10, 16, 20, 28, 26]
    else:
        weights = [6, 10, 14, 30, 40]
    return random.choices(CLIENTS, weights=weights, k=1)[0]


def sample_anomalies(profile: str):
    if profile == "low":
        return (
            random.choices([0, 1], weights=[92, 8], k=1)[0],
            random.choices([0, 1], weights=[92, 8], k=1)[0],
        )
    if profile == "moderate":
        return (
            random.choices([0, 1], weights=[55, 45], k=1)[0],
            random.choices([0, 1], weights=[65, 35], k=1)[0],
        )
    if profile == "high":
        return (
            random.choices([0, 1], weights=[30, 70], k=1)[0],
            random.choices([0, 1], weights=[35, 65], k=1)[0],
        )
    return (
        random.choices([0, 1], weights=[10, 90], k=1)[0],
        random.choices([0, 1], weights=[10, 90], k=1)[0],
    )


def build_candidate_row(profile: str) -> dict:
    client_id, app_sensitivity = sample_client(profile)
    hour = sample_hour(profile)
    day_of_week = random.randint(1, 7)
    is_weekend = 1 if day_of_week in [6, 7] else 0
    is_night_login = 1 if hour >= 22 or hour < 6 else 0
    is_business_hours = 1 if 8 <= hour <= 18 else 0
    is_new_device, is_new_ip_for_user = sample_anomalies(profile)

    if profile == "low":
        fails_5m = random.choices([0, 1, 2], weights=[76, 21, 3], k=1)[0]
        fails_1h = random.choices([0, 1, 2], weights=[60, 30, 10], k=1)[0]
        fails_24h = random.randint(fails_1h, fails_1h + 2)
        login_1h = random.randint(0, 3)
    elif profile == "moderate":
        fails_5m = random.choices([0, 1, 2, 3], weights=[18, 35, 37, 10], k=1)[0]
        fails_1h = random.randint(max(1, fails_5m), max(3, fails_5m + 2))
        fails_24h = random.randint(fails_1h, fails_1h + 4)
        login_1h = random.randint(1, 5)
    elif profile == "high":
        fails_5m = random.randint(1, 4)
        fails_1h = random.randint(max(2, fails_5m), max(5, fails_5m + 3))
        fails_24h = random.randint(fails_1h + 1, fails_1h + 6)
        login_1h = random.randint(0, 3)
    else:
        fails_5m = random.randint(3, 6)
        fails_1h = random.randint(max(5, fails_5m), max(8, fails_5m + 5))
        fails_24h = random.randint(max(10, fails_1h), fails_1h + 10)
        login_1h = random.randint(0, 2)

    row = {
        "event_time": random_datetime(),
        "client_id": client_id,
        "app_sensitivity": app_sensitivity,
        "ua_browser": random.choice(BROWSERS),
        "ua_os": random.choice(OPERATING_SYSTEMS),
        "ua_device": random.choice(DEVICES),
        "hour": hour,
        "day_of_week": day_of_week,
        "is_weekend": is_weekend,
        "is_night_login": is_night_login,
        "is_business_hours": is_business_hours,
        "is_new_device": is_new_device,
        "is_new_ip_for_user": is_new_ip_for_user,
        "fails_5m": fails_5m,
        "fails_1h": fails_1h,
        "fails_24h": fails_24h,
        "login_1h": login_1h,
    }

    risk_label = assign_risk_label(row)
    row["risk_label"] = risk_label
    row["risk_class"] = RISK_CLASS_MAP[risk_label]
    row["data_origin"] = "synthetic"
    return row


def generate_rows_for_class(target_label: str, target_count: int):
    rows = []
    attempts = 0
    max_attempts = target_count * 500

    while len(rows) < target_count and attempts < max_attempts:
        row = build_candidate_row(target_label)
        if row["risk_label"] == target_label:
            rows.append(row)
        attempts += 1

    if len(rows) != target_count:
        raise RuntimeError(
            f"Unable to generate enough rows for class '{target_label}'. "
            f"Expected {target_count}, got {len(rows)}."
        )

    return rows


def main():
    random.seed(42)

    rows = []
    for risk_label, target_count in CLASS_TARGETS.items():
        rows.extend(generate_rows_for_class(risk_label, target_count))

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(OUTPUT_PATH, index=False)

    print(f"Synthetic dataset generated: {OUTPUT_PATH}")
    print(f"Total rows: {len(df)}")
    print("\nDistribution by risk_class:")
    print(df["risk_class"].value_counts().sort_index())
    print("\nDistribution by risk_label:")
    print(df["risk_label"].value_counts().sort_index())


if __name__ == "__main__":
    main()
