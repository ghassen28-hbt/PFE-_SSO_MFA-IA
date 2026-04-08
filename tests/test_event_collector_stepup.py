import importlib.util
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVENT_COLLECTOR_DIR = ROOT / "services" / "event-collector"
EVENT_COLLECTOR_PATH = EVENT_COLLECTOR_DIR / "main.py"

if str(EVENT_COLLECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(EVENT_COLLECTOR_DIR))


def load_event_collector_module():
    user_agents_stub = types.ModuleType("user_agents")
    user_agents_stub.parse = lambda raw: None
    sys.modules.setdefault("user_agents", user_agents_stub)

    enrichment_stub = types.ModuleType("enrichment")
    enrichment_stub.enrich_ip = lambda ip: {}
    enrichment_stub.is_password_pwned = lambda password: 0
    enrichment_stub.initialize = lambda: None
    sys.modules.setdefault("enrichment", enrichment_stub)

    spec = importlib.util.spec_from_file_location("event_collector_main", EVENT_COLLECTOR_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EventCollectorStepUpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_event_collector_module()

    def test_default_step_up_client_is_recognized(self):
        self.assertTrue(self.module.is_step_up_client("portal-stepup-totp-client"))
        self.assertFalse(self.module.is_step_up_client("portal-main-client"))

    def test_completed_totp_inherits_risk_but_allows_session(self):
        inherited = {
            "risk_score": 0.35,
            "risk_label": "moderate",
            "decision": "STEP_UP_TOTP",
            "required_factor": "TOTP_OR_WEBAUTHN",
            "auth_path": "SECOND_FACTOR",
            "policy_reason": "moderate_hard_rule_vpn_geo_shift",
            "scoring_status": "ok",
        }

        result = self.module.as_completed_step_up_scoring(inherited)

        self.assertEqual(result["risk_score"], 0.35)
        self.assertEqual(result["risk_label"], "moderate")
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["required_factor"], "NONE")
        self.assertEqual(result["auth_path"], "MFA_COMPLETED")
        self.assertEqual(result["scoring_status"], "mfa_step_inherited_recent_login")
        self.assertIn("moderate_hard_rule_vpn_geo_shift", result["policy_reason"])

    def test_completed_totp_does_not_downgrade_biometric_or_admin_decisions(self):
        inherited = {
            "risk_score": 0.70,
            "risk_label": "high",
            "decision": "STEP_UP_BIOMETRIC",
            "required_factor": "FACE_RECOGNITION",
            "auth_path": "BIOMETRIC_FACTOR",
            "policy_reason": "high_hard_rule_impossible_travel",
            "scoring_status": "ok",
        }

        result = self.module.as_completed_step_up_scoring(inherited)

        self.assertEqual(result["decision"], "STEP_UP_BIOMETRIC")
        self.assertEqual(result["required_factor"], "FACE_RECOGNITION")
        self.assertEqual(result["auth_path"], "BIOMETRIC_FACTOR")
        self.assertEqual(result["scoring_status"], "mfa_step_inherited_recent_login")
        self.assertIn("without_downgrade", result["policy_reason"])


if __name__ == "__main__":
    unittest.main()
