import json
import sys
import unittest
from pathlib import Path

import joblib


ROOT = Path(__file__).resolve().parents[1]
TRAINING_DIR = ROOT / "ml" / "training"
if str(TRAINING_DIR) not in sys.path:
    sys.path.insert(0, str(TRAINING_DIR))

from pipeline_schema import SCHEMA_VERSION  # noqa: E402


class TrainingArtifactsTests(unittest.TestCase):
    def test_saved_artifacts_are_consistent(self):
        model_path = ROOT / "ml" / "training" / "artifacts" / "risk_model_v1.joblib"
        features_path = ROOT / "ml" / "training" / "artifacts" / "risk_model_v1_features.json"

        artifact = joblib.load(model_path)
        metadata = json.loads(features_path.read_text(encoding="utf-8"))

        self.assertEqual(artifact["schema_version"], SCHEMA_VERSION)
        self.assertEqual(metadata["schema_version"], SCHEMA_VERSION)
        self.assertEqual(artifact["selected_features"], metadata["selected_features"])
        self.assertIn("predictor", artifact)
        self.assertIn("selected_predictor_variant", metadata)


if __name__ == "__main__":
    unittest.main()
