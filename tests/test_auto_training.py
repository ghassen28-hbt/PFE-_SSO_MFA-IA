import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUTO_TRAIN_PATH = ROOT / "scripts" / "auto_train.py"


def load_auto_train_module():
    spec = importlib.util.spec_from_file_location("auto_train", AUTO_TRAIN_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AutoTrainingTests(unittest.TestCase):
    def test_parser_defaults_are_safe_for_runtime(self):
        module = load_auto_train_module()
        args = module.build_parser().parse_args([])

        self.assertFalse(args.restart_services)
        self.assertFalse(args.biometric_check)
        self.assertFalse(args.skip_tests)
        self.assertFalse(args.disable_promotion_gate)
        self.assertEqual(args.min_macro_f1, 0.80)

    def test_parser_can_enable_biometric_check_and_restart(self):
        module = load_auto_train_module()
        args = module.build_parser().parse_args(["--biometric-check", "--restart-services"])

        self.assertTrue(args.biometric_check)
        self.assertTrue(args.restart_services)

    def test_promotion_gate_rejects_low_metrics(self):
        module = load_auto_train_module()
        passed, reason = module.promotion_gate_passed(
            {"test_metrics": {"macro_f1": 0.20, "balanced_accuracy": 0.90}},
            min_macro_f1=0.80,
            min_balanced_accuracy=0.75,
        )

        self.assertFalse(passed)
        self.assertIn("macro_f1", reason)

    def test_promotion_gate_accepts_good_metrics(self):
        module = load_auto_train_module()
        passed, reason = module.promotion_gate_passed(
            {"test_metrics": {"macro_f1": 0.88, "balanced_accuracy": 0.86}},
            min_macro_f1=0.80,
            min_balanced_accuracy=0.75,
        )

        self.assertTrue(passed)
        self.assertEqual(reason, "passed")

    def test_scheduler_command_builder_can_be_imported(self):
        scheduler_path = ROOT / "scripts" / "auto_train_scheduler.py"
        spec = importlib.util.spec_from_file_location("auto_train_scheduler", scheduler_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        command = module.build_auto_train_command()

        self.assertIn("scripts/auto_train.py", command)
        self.assertIn("--min-macro-f1", command)


if __name__ == "__main__":
    unittest.main()
