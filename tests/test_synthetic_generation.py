import importlib.util
import unittest
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = ROOT / "ml" / "training" / "generate_synthetic_dataset.py"


def load_generator_module():
    spec = importlib.util.spec_from_file_location("synthetic_generator", GENERATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SyntheticGenerationTests(unittest.TestCase):
    def test_project_training_columns_keeps_advanced_features_and_synthetic_rule_score(self):
        module = load_generator_module()
        df = pd.DataFrame(
            [
                {
                    "event_time": "2026-04-06T10:00:00",
                    "client_id": "portal-main-client",
                    "app_sensitivity": 1,
                    "ua_browser": "Brave 146.0.0.0",
                    "ua_os": "Windows 11",
                    "ua_device": "pc",
                    "geo_country_code": "TN",
                    "asn_org": "Orange Tunisie",
                    "hour": 10,
                    "day_of_week": 5,
                    "is_weekend": 0,
                    "is_night_login": 0,
                    "is_business_hours": 1,
                    "is_new_device": 0,
                    "is_new_ip_for_user": 0,
                    "fails_5m": 0,
                    "fails_1h": 0,
                    "fails_24h": 0,
                    "login_1h": 1,
                    "is_vpn_detected": 0,
                    "is_proxy_detected": 0,
                    "is_tor": 0,
                    "distance_from_last_location_km": 0.0,
                    "is_impossible_travel": 0,
                    "abuse_confidence_score": 0,
                    "synthetic_rule_score": 0.12,
                    "source_risk_score": None,
                    "source_risk_label": "low",
                    "source_decision": "ALLOW",
                    "source_policy_reason": "synthetic_rule_low",
                    "risk_label": "low",
                    "risk_class": 0,
                    "data_origin": "synthetic",
                }
            ]
        )

        projected = module.project_training_columns(df)

        self.assertIn("synthetic_rule_score", projected.columns)
        self.assertIn("is_vpn_detected", projected.columns)
        self.assertIn("distance_from_last_location_km", projected.columns)
        self.assertNotIn("risk_score", projected.columns)


if __name__ == "__main__":
    unittest.main()
