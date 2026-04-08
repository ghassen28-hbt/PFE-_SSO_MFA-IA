from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
TRAINING_DIR = ROOT / "ml" / "training"
ARTIFACTS_DIR = TRAINING_DIR / "artifacts"
REPORTS_DIR = TRAINING_DIR / "reports"
FEATURES_PATH = ARTIFACTS_DIR / "risk_model_v1_features.json"
MODEL_COMPARISON_PATH = ARTIFACTS_DIR / "risk_model_v1_model_comparison.json"
ABLATION_PATH = ARTIFACTS_DIR / "risk_model_v1_ablation.json"
MODEL_PATH = ARTIFACTS_DIR / "risk_model_v1.joblib"
PROMOTED_ARTIFACT_PATHS = [
    MODEL_PATH,
    FEATURES_PATH,
    MODEL_COMPARISON_PATH,
    ABLATION_PATH,
]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_command(command: list[str], step_name: str, timeout: int | None = None) -> dict[str, Any]:
    started_at = time.time()
    print(f"\n[{step_name}] {' '.join(command)}")
    process = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    duration_seconds = round(time.time() - started_at, 2)

    if process.stdout:
        print(process.stdout)
    if process.stderr:
        print(process.stderr, file=sys.stderr)

    result = {
        "step": step_name,
        "command": command,
        "returncode": process.returncode,
        "duration_seconds": duration_seconds,
        "stdout_tail": process.stdout[-4000:],
        "stderr_tail": process.stderr[-4000:],
        "status": "ok" if process.returncode == 0 else "failed",
    }

    if process.returncode != 0:
        raise RuntimeError(f"Step failed: {step_name}")

    return result


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def summarize_training_artifacts() -> dict[str, Any]:
    metadata = read_json(FEATURES_PATH)
    comparison = read_json(MODEL_COMPARISON_PATH)
    ablation = read_json(ABLATION_PATH)

    return {
        "schema_version": metadata.get("schema_version"),
        "selected_model_name": metadata.get("selected_model_name"),
        "selected_predictor_variant": metadata.get("selected_predictor_variant"),
        "selected_features": metadata.get("selected_features", []),
        "selected_feature_count": metadata.get("selected_feature_count"),
        "test_metrics": metadata.get("test_metrics", {}),
        "validation_metrics": metadata.get("validation_metrics", {}),
        "calibration_method": metadata.get("calibration_method"),
        "calibration_summary": metadata.get("calibration_summary", {}),
        "best_result": comparison.get("best_result", {}),
        "ablation_summary": {
            name: {
                "feature_count": payload.get("feature_count"),
                "validation_metrics": payload.get("validation_metrics", {}),
            }
            for name, payload in ablation.items()
        },
    }


def snapshot_artifacts() -> dict[Path, bytes]:
    snapshot = {}
    for path in PROMOTED_ARTIFACT_PATHS:
        if path.exists():
            snapshot[path] = path.read_bytes()
    return snapshot


def restore_artifacts(snapshot: dict[Path, bytes]):
    for path, payload in snapshot.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def promotion_gate_passed(artifacts: dict[str, Any], min_macro_f1: float, min_balanced_accuracy: float) -> tuple[bool, str]:
    metrics = artifacts.get("test_metrics", {})
    macro_f1 = float(metrics.get("macro_f1", 0.0) or 0.0)
    balanced_accuracy = float(metrics.get("balanced_accuracy", 0.0) or 0.0)

    if macro_f1 < min_macro_f1:
        return False, f"macro_f1={macro_f1:.4f} is below minimum {min_macro_f1:.4f}"
    if balanced_accuracy < min_balanced_accuracy:
        return False, (
            f"balanced_accuracy={balanced_accuracy:.4f} is below minimum "
            f"{min_balanced_accuracy:.4f}"
        )
    return True, "passed"


def check_http_json(url: str, timeout: int = 20) -> dict[str, Any]:
    with urlopen(url, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
    return json.loads(raw)


def biometric_health_check(url: str) -> dict[str, Any]:
    try:
        payload = check_http_json(url)
        return {
            "status": "ok",
            "url": url,
            "payload": payload,
            "note": (
                "buffalo_l is an InsightFace pretrained model. This project validates "
                "availability/warm-up; it does not retrain buffalo_l."
            ),
        }
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return {
            "status": "skipped",
            "url": url,
            "error": str(exc),
            "note": (
                "Biometric service is not reachable. buffalo_l is pretrained; start "
                "biometric-service and call this check again if you want a warm-up validation."
            ),
        }


def write_reports(summary: dict[str, Any]) -> tuple[Path, Path]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = REPORTS_DIR / f"auto_training_report_{timestamp}.json"
    md_path = REPORTS_DIR / f"auto_training_report_{timestamp}.md"

    json_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")

    metrics = summary.get("artifacts", {}).get("test_metrics", {})
    selected_features = summary.get("artifacts", {}).get("selected_features", [])
    biometric = summary.get("biometric_check", {})

    md_lines = [
        "# Auto Training Report",
        "",
        f"- Started at: `{summary.get('started_at')}`",
        f"- Finished at: `{summary.get('finished_at')}`",
        f"- Overall status: `{summary.get('status')}`",
        f"- Selected model: `{summary.get('artifacts', {}).get('selected_model_name')}`",
        f"- Predictor variant: `{summary.get('artifacts', {}).get('selected_predictor_variant')}`",
        f"- Selected features: `{', '.join(selected_features)}`",
        "",
        "## Test Metrics",
        "",
    ]
    for key in [
        "accuracy",
        "balanced_accuracy",
        "macro_f1",
        "weighted_f1",
        "log_loss",
        "expected_calibration_error",
        "multiclass_brier_score",
        "macro_roc_auc_ovr",
    ]:
        if key in metrics:
            md_lines.append(f"- `{key}`: `{metrics[key]}`")

    md_lines.extend(
        [
            "",
            "## Biometric Model",
            "",
            f"- Check status: `{biometric.get('status', 'not_requested')}`",
            f"- Note: {biometric.get('note', 'not requested')}",
            "",
            "## Steps",
            "",
        ]
    )
    for step in summary.get("steps", []):
        md_lines.append(
            f"- `{step['step']}`: `{step['status']}` in `{step['duration_seconds']}s`"
        )

    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    return json_path, md_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Automate risk ML + mRMR retraining and optional biometric pretrained model checks."
    )
    parser.add_argument("--skip-synthetic", action="store_true", help="Do not regenerate synthetic data.")
    parser.add_argument("--skip-real-export", action="store_true", help="Do not rebuild final dataset from ClickHouse.")
    parser.add_argument("--skip-tests", action="store_true", help="Do not run unittest validation.")
    parser.add_argument(
        "--restart-services",
        action="store_true",
        help="Rebuild/restart scoring-service and event-collector after a successful training.",
    )
    parser.add_argument(
        "--biometric-check",
        action="store_true",
        help="Check biometric-service health/warm-up. This validates buffalo_l availability; it does not retrain it.",
    )
    parser.add_argument(
        "--biometric-url",
        default="http://localhost:8091/health",
        help="Biometric health URL used when --biometric-check is enabled.",
    )
    parser.add_argument(
        "--docker-timeout",
        type=int,
        default=600,
        help="Timeout in seconds for Docker restart step.",
    )
    parser.add_argument(
        "--disable-promotion-gate",
        action="store_true",
        help="Do not restore previous artifacts if the new model misses minimum metrics.",
    )
    parser.add_argument(
        "--min-macro-f1",
        type=float,
        default=0.80,
        help="Minimum test macro_f1 required to keep newly trained artifacts.",
    )
    parser.add_argument(
        "--min-balanced-accuracy",
        type=float,
        default=0.75,
        help="Minimum test balanced_accuracy required to keep newly trained artifacts.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    summary: dict[str, Any] = {
        "started_at": utc_now(),
        "status": "running",
        "steps": [],
        "options": vars(args),
    }
    artifact_snapshot = snapshot_artifacts()

    try:
        if not args.skip_synthetic:
            summary["steps"].append(
                run_command(
                    [sys.executable, "ml/training/generate_synthetic_dataset.py"],
                    "generate_synthetic_dataset",
                    timeout=180,
                )
            )

        if not args.skip_real_export:
            summary["steps"].append(
                run_command(
                    [sys.executable, "ml/training/build_training_dataset.py"],
                    "build_training_dataset",
                    timeout=180,
                )
            )

        summary["steps"].append(
            run_command(
                [sys.executable, "ml/training/train_risk_model.py"],
                "train_risk_model_mrmr",
                timeout=300,
            )
        )

        if not args.skip_tests:
            summary["steps"].append(
                run_command(
                    [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                    "unit_and_endpoint_tests",
                    timeout=180,
                )
            )

        summary["artifacts"] = summarize_training_artifacts()
        if args.disable_promotion_gate:
            summary["promotion_gate"] = {
                "status": "disabled",
                "reason": "disabled_by_cli",
            }
        else:
            promoted, reason = promotion_gate_passed(
                summary["artifacts"],
                min_macro_f1=args.min_macro_f1,
                min_balanced_accuracy=args.min_balanced_accuracy,
            )
            summary["promotion_gate"] = {
                "status": "passed" if promoted else "failed",
                "reason": reason,
                "min_macro_f1": args.min_macro_f1,
                "min_balanced_accuracy": args.min_balanced_accuracy,
            }
            if not promoted:
                restore_artifacts(artifact_snapshot)
                summary["artifacts_restored"] = True
                raise RuntimeError(f"Promotion gate failed: {reason}")

        if args.restart_services:
            summary["steps"].append(
                run_command(
                    ["docker", "compose", "up", "-d", "--build", "scoring-service", "event-collector"],
                    "restart_scoring_runtime",
                    timeout=args.docker_timeout,
                )
            )

        if args.biometric_check:
            summary["biometric_check"] = biometric_health_check(args.biometric_url)
        else:
            summary["biometric_check"] = {
                "status": "not_requested",
                "note": "Use --biometric-check to validate buffalo_l service availability.",
            }

        summary["status"] = "ok"
        return_code = 0
    except Exception as exc:
        summary["status"] = "failed"
        summary["error"] = str(exc)
        return_code = 1
    finally:
        summary["finished_at"] = utc_now()
        json_path, md_path = write_reports(summary)
        print(f"\nAuto-training JSON report: {json_path}")
        print(f"Auto-training Markdown report: {md_path}")

    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
