from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_auto_train_command() -> list[str]:
    command = [sys.executable, "scripts/auto_train.py"]

    if bool_env("AUTO_TRAIN_SKIP_SYNTHETIC", False):
        command.append("--skip-synthetic")
    if bool_env("AUTO_TRAIN_SKIP_REAL_EXPORT", False):
        command.append("--skip-real-export")
    if bool_env("AUTO_TRAIN_SKIP_TESTS", False):
        command.append("--skip-tests")
    if bool_env("AUTO_TRAIN_DISABLE_PROMOTION_GATE", False):
        command.append("--disable-promotion-gate")
    if bool_env("AUTO_TRAIN_BIOMETRIC_CHECK", True):
        command.extend(
            [
                "--biometric-check",
                "--biometric-url",
                os.getenv("AUTO_TRAIN_BIOMETRIC_URL", "http://biometric-service:8091/health"),
            ]
        )

    command.extend(
        [
            "--min-macro-f1",
            os.getenv("AUTO_TRAIN_MIN_MACRO_F1", "0.80"),
            "--min-balanced-accuracy",
            os.getenv("AUTO_TRAIN_MIN_BALANCED_ACCURACY", "0.75"),
        ]
    )

    extra_args = os.getenv("AUTO_TRAIN_EXTRA_ARGS", "").strip()
    if extra_args:
        command.extend(extra_args.split())

    return command


def run_once() -> int:
    command = build_auto_train_command()
    print(f"[{now()}] auto-training command: {' '.join(command)}", flush=True)
    process = subprocess.run(command, cwd=ROOT)
    print(f"[{now()}] auto-training finished with return code {process.returncode}", flush=True)
    return process.returncode


def main() -> int:
    enabled = bool_env("AUTO_TRAIN_ENABLED", True)
    interval_seconds = max(300, int_env("AUTO_TRAIN_INTERVAL_SECONDS", 86400))
    initial_delay_seconds = max(0, int_env("AUTO_TRAIN_INITIAL_DELAY_SECONDS", 300))
    run_once_on_start = bool_env("AUTO_TRAIN_RUN_ON_START", False)

    print(
        (
            f"[{now()}] training scheduler started "
            f"enabled={enabled} interval={interval_seconds}s "
            f"initial_delay={initial_delay_seconds}s run_once_on_start={run_once_on_start}"
        ),
        flush=True,
    )

    if not enabled:
        while True:
            time.sleep(interval_seconds)

    if run_once_on_start:
        run_once()

    if initial_delay_seconds:
        time.sleep(initial_delay_seconds)

    while True:
        run_once()
        time.sleep(interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
