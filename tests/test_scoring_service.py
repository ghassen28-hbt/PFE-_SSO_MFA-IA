import importlib.util
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "ml" / "scoring-service" / "app.py"


def load_scoring_app():
    spec = importlib.util.spec_from_file_location("risk_scoring_app", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


class ScoringServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(load_scoring_app())

    def test_health_endpoint_reports_loaded_model(self):
        response = self.client.get("/")
        payload = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["model_loaded"])
        self.assertIn("schema_version", payload)
        self.assertIn("artifact_fingerprint", payload)

    def test_score_endpoint_handles_sparse_payload(self):
        response = self.client.post("/score", json={"client_id": "portal-main-client"})
        payload = response.json()

        self.assertEqual(response.status_code, 200)
        for key in [
            "risk_class",
            "risk_label",
            "risk_score",
            "decision",
            "required_factor",
            "auth_path",
            "policy_reason",
            "class_probabilities",
            "features_used",
        ]:
            self.assertIn(key, payload)

        self.assertGreaterEqual(payload["risk_score"], 0.0)
        self.assertLessEqual(payload["risk_score"], 1.0)
        self.assertAlmostEqual(sum(payload["class_probabilities"].values()), 1.0, places=3)

    def test_impossible_travel_with_vpn_forces_high_risk(self):
        response = self.client.post(
            "/score",
            json={
                "client_id": "portal-main-client",
                "app_sensitivity": 1,
                "ua_browser": "Brave 146.0.0.0",
                "ua_os": "Windows 11",
                "ua_device": "pc",
                "geo_country_code": "NL",
                "asn_org": "JSC Ukrtelecom",
                "hour": 11,
                "day_of_week": 5,
                "is_weekend": 0,
                "is_night_login": 0,
                "is_business_hours": 1,
                "is_new_device": 0,
                "is_new_ip_for_user": 1,
                "fails_5m": 0,
                "fails_1h": 0,
                "fails_24h": 0,
                "login_1h": 1,
                "is_vpn_detected": 1,
                "is_proxy_detected": 0,
                "is_tor": 0,
                "distance_from_last_location_km": 1800,
                "is_impossible_travel": 1,
                "abuse_confidence_score": 0,
            },
        )
        payload = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["prediction_source"], "hard_rule_override")
        self.assertEqual(payload["risk_class"], 2)
        self.assertEqual(payload["risk_label"], "high")
        self.assertEqual(payload["policy_reason"], "high_hard_rule_impossible_travel")
        self.assertGreaterEqual(payload["risk_score"], 0.70)

    def test_vpn_geo_shift_without_impossible_travel_forces_moderate_risk(self):
        response = self.client.post(
            "/score",
            json={
                "client_id": "portal-main-client",
                "app_sensitivity": 1,
                "ua_browser": "Brave 146.0.0.0",
                "ua_os": "Windows 11",
                "ua_device": "pc",
                "geo_country_code": "NL",
                "asn_org": "WorldStream B.V.",
                "hour": 10,
                "day_of_week": 2,
                "is_weekend": 0,
                "is_night_login": 0,
                "is_business_hours": 1,
                "is_new_device": 0,
                "is_new_ip_for_user": 1,
                "fails_5m": 0,
                "fails_1h": 0,
                "fails_24h": 0,
                "login_1h": 1,
                "is_vpn_detected": 1,
                "is_proxy_detected": 0,
                "is_tor": 0,
                "distance_from_last_location_km": 1751.48,
                "is_impossible_travel": 0,
                "abuse_confidence_score": 9,
            },
        )
        payload = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["prediction_source"], "hard_rule_override")
        self.assertEqual(payload["risk_class"], 1)
        self.assertEqual(payload["risk_label"], "moderate")
        self.assertEqual(payload["policy_reason"], "moderate_hard_rule_vpn_geo_shift")
        self.assertGreaterEqual(payload["risk_score"], 0.35)


if __name__ == "__main__":
    unittest.main()
