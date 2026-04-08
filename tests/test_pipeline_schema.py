import sys
import unittest
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
TRAINING_DIR = ROOT / "ml" / "training"
if str(TRAINING_DIR) not in sys.path:
    sys.path.insert(0, str(TRAINING_DIR))

from pipeline_schema import DATASET_COLUMNS, normalize_dataset_schema  # noqa: E402


class PipelineSchemaTests(unittest.TestCase):
    def test_normalize_dataset_schema_adds_missing_columns_and_coerces_types(self):
        raw = pd.DataFrame(
            [
                {
                    "event_time": "2026-04-06T10:00:00",
                    "client_id": "portal-main-client",
                    "fails_5m": "3",
                    "synthetic_rule_score": "0.61",
                    "risk_label": "HIGH",
                    "risk_class": "2",
                    "data_origin": "synthetic",
                }
            ]
        )

        normalized = normalize_dataset_schema(raw)

        self.assertEqual(list(normalized.columns), DATASET_COLUMNS)
        self.assertEqual(normalized.loc[0, "risk_label"], "high")
        self.assertEqual(int(normalized.loc[0, "risk_class"]), 2)
        self.assertEqual(float(normalized.loc[0, "fails_5m"]), 3.0)
        self.assertEqual(float(normalized.loc[0, "synthetic_rule_score"]), 0.61)
        self.assertEqual(normalized.loc[0, "ua_browser"], "unknown")


if __name__ == "__main__":
    unittest.main()
