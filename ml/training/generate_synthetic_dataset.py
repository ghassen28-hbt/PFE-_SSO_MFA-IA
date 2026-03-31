import random
from pathlib import Path
from datetime import datetime, timedelta

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

OUTPUT_PATH = DATA_DIR / "synthetic_risk_dataset.csv"

N_NORMAL = 300
N_RISKY = 200

BROWSERS = ["Chrome", "Brave", "Firefox", "Edge"]
OPERATING_SYSTEMS = ["Windows 11", "Windows 10", "Ubuntu", "macOS"]
DEVICES = ["pc", "laptop"]

CLIENTS = [
    ("portal-client-5", 1),
    ("crm-client-2", 2),
    ("hr-client-4", 3),
    ("finance-client-3", 4),
    ("admin-console-client-1", 5),
]


def random_datetime(start_days_ago=30):
    now = datetime.now()
    start = now - timedelta(days=start_days_ago)
    delta = now - start
    random_seconds = random.randint(0, int(delta.total_seconds()))
    return start + timedelta(seconds=random_seconds)


def build_normal_row():
    client_id, app_sensitivity = random.choices(
        CLIENTS,
        weights=[35, 25, 15, 15, 10],
        k=1
    )[0]

    hour = random.choices(
        population=list(range(24)),
        weights=[
            1, 1, 1, 1, 1, 1,
            2, 4, 8, 10, 10, 10,
            10, 10, 9, 8, 7, 6,
            4, 3, 2, 1, 1, 1
        ],
        k=1
    )[0]

    day_of_week = random.randint(1, 7)
    is_weekend = 1 if day_of_week in [6, 7] else 0
    is_night_login = 1 if hour >= 22 or hour < 6 else 0
    is_business_hours = 1 if 8 <= hour <= 18 else 0

    fails_5m = random.choices([0, 1], weights=[90, 10], k=1)[0]
    fails_1h = random.choices([0, 1, 2], weights=[70, 20, 10], k=1)[0]
    fails_24h = random.randint(fails_1h, fails_1h + 2)
    login_1h = random.randint(0, 3)

    is_new_device = random.choices([0, 1], weights=[85, 15], k=1)[0]
    is_new_ip_for_user = random.choices([0, 1], weights=[85, 15], k=1)[0]

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
        "step_up_required": 0,
        "data_origin": "synthetic"
    }

    if (
        is_new_device == 1
        or is_new_ip_for_user == 1
        or fails_1h >= 3
        or (is_night_login == 1 and app_sensitivity >= 4)
    ):
        row["step_up_required"] = 1 if random.random() < 0.35 else 0

    return row


def build_risky_row():
    client_id, app_sensitivity = random.choices(
        CLIENTS,
        weights=[10, 15, 15, 30, 30],
        k=1
    )[0]

    hour = random.choices(
        population=list(range(24)),
        weights=[
            8, 8, 8, 8, 7, 6,
            3, 2, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 2,
            3, 4, 5, 6, 7, 8
        ],
        k=1
    )[0]

    day_of_week = random.randint(1, 7)
    is_weekend = 1 if day_of_week in [6, 7] else 0
    is_night_login = 1 if hour >= 22 or hour < 6 else 0
    is_business_hours = 1 if 8 <= hour <= 18 else 0

    fails_5m = random.randint(1, 5)
    fails_1h = random.randint(max(2, fails_5m), 8)
    fails_24h = random.randint(fails_1h, fails_1h + 8)
    login_1h = random.randint(0, 2)

    is_new_device = random.choices([0, 1], weights=[20, 80], k=1)[0]
    is_new_ip_for_user = random.choices([0, 1], weights=[20, 80], k=1)[0]

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
        "step_up_required": 1,
        "data_origin": "synthetic"
    }

    return row


def main():
    random.seed(42)

    rows = []

    for _ in range(N_NORMAL):
        rows.append(build_normal_row())

    for _ in range(N_RISKY):
        rows.append(build_risky_row())

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(OUTPUT_PATH, index=False)

    print(f"Dataset synthétique généré : {OUTPUT_PATH}")
    print(f"Nombre total de lignes : {len(df)}")
    print("\nDistribution cible :")
    print(df["step_up_required"].value_counts().sort_index())


if __name__ == "__main__":
    main()