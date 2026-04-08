import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TRAINING_DIR = ROOT / "ml" / "training"
if str(TRAINING_DIR) not in sys.path:
    sys.path.insert(0, str(TRAINING_DIR))

from train_risk_model import build_feature_candidates, select_calibration_variant  # noqa: E402


class TrainingSelectionTests(unittest.TestCase):
    def test_build_feature_candidates_trims_zero_score_fillers(self):
        ranking = [
            {"feature": "fails_24h", "mrmr_score": 0.8},
            {"feature": "fails_1h", "mrmr_score": 0.4},
            {"feature": "client_id", "mrmr_score": 0.2},
            {"feature": "geo_country_code", "mrmr_score": 0.1},
            {"feature": "hour", "mrmr_score": 0.0},
            {"feature": "ua_os", "mrmr_score": -0.05},
        ]

        candidates = build_feature_candidates(ranking)
        flattened = [tuple(candidate["features"]) for candidate in candidates]

        self.assertIn(
            ("fails_24h", "fails_1h", "client_id", "geo_country_code"),
            flattened,
        )
        self.assertNotIn(
            ("fails_24h", "fails_1h", "client_id", "geo_country_code", "hour"),
            flattened,
        )

    def test_select_calibration_variant_keeps_raw_when_calibration_is_worse(self):
        raw_metrics = {
            "macro_f1": 0.95,
            "balanced_accuracy": 0.94,
            "log_loss": 0.10,
            "expected_calibration_error": 0.02,
            "multiclass_brier_score": 0.03,
        }
        calibrated_metrics = {
            "macro_f1": 0.90,
            "balanced_accuracy": 0.89,
            "log_loss": 0.14,
            "expected_calibration_error": 0.04,
            "multiclass_brier_score": 0.05,
        }

        decision = select_calibration_variant(raw_metrics, calibrated_metrics)

        self.assertEqual(decision["selected_variant"], "raw")

    def test_select_calibration_variant_keeps_calibrated_when_probability_quality_improves(self):
        raw_metrics = {
            "macro_f1": 0.95,
            "balanced_accuracy": 0.94,
            "log_loss": 0.12,
            "expected_calibration_error": 0.05,
            "multiclass_brier_score": 0.06,
        }
        calibrated_metrics = {
            "macro_f1": 0.95,
            "balanced_accuracy": 0.94,
            "log_loss": 0.08,
            "expected_calibration_error": 0.03,
            "multiclass_brier_score": 0.04,
        }

        decision = select_calibration_variant(raw_metrics, calibrated_metrics)

        self.assertEqual(decision["selected_variant"], "calibrated")


if __name__ == "__main__":
    unittest.main()
