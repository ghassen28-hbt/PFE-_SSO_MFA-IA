import importlib.util
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIOMETRIC_DIR = ROOT / "services" / "biometric-service"
BIOMETRIC_PATH = BIOMETRIC_DIR / "main.py"

if str(BIOMETRIC_DIR) not in sys.path:
    sys.path.insert(0, str(BIOMETRIC_DIR))


def load_biometric_module():
    storage_stub = types.ModuleType("storage")
    storage_stub.load_profile = lambda user_id: None
    storage_stub.save_profile = lambda **kwargs: kwargs
    sys.modules.setdefault("storage", storage_stub)

    try:
        import cv2  # noqa: F401
    except Exception:
        cv2_stub = types.ModuleType("cv2")
        cv2_stub.IMREAD_COLOR = 1
        cv2_stub.COLOR_BGR2GRAY = 6
        cv2_stub.CV_64F = 6
        cv2_stub.imdecode = lambda *args, **kwargs: None
        cv2_stub.cvtColor = lambda image, code: image
        cv2_stub.Laplacian = lambda image, code: image
        sys.modules.setdefault("cv2", cv2_stub)

    spec = importlib.util.spec_from_file_location("biometric_service_main", BIOMETRIC_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BiometricServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_biometric_module()

    def test_multiple_faces_are_rejected(self):
        with self.assertRaises(self.module.HTTPException) as ctx:
            self.module.ensure_single_face([object(), object()])

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Plusieurs visages", ctx.exception.detail)

    def test_enrollment_pose_must_be_frontal(self):
        with self.assertRaises(self.module.HTTPException) as ctx:
            self.module.validate_enrollment_pose({"yaw_proxy": 0.2, "roll_proxy": 0.0})

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("frontal", ctx.exception.detail)

    def test_liveness_rejects_roll_based_photo_tilt(self):
        result = self.module.evaluate_liveness(
            {
                "yaw_proxy": 0.0,
                "roll_proxy": 0.0,
                "bbox_center_x_ratio": 0.5,
                "bbox_center_y_ratio": 0.5,
                "bbox_area_ratio": 0.18,
            },
            {
                "yaw_proxy": -0.18,
                "roll_proxy": 0.22,
                "bbox_center_x_ratio": 0.51,
                "bbox_center_y_ratio": 0.5,
                "bbox_area_ratio": 0.19,
            },
            "turn_left",
        )

        self.assertFalse(result["liveness_passed"])
        self.assertEqual(result["liveness_reason"], "roll_delta_too_large")

    def test_liveness_rejects_large_framing_shift(self):
        result = self.module.evaluate_liveness(
            {
                "yaw_proxy": 0.0,
                "roll_proxy": 0.0,
                "bbox_center_x_ratio": 0.5,
                "bbox_center_y_ratio": 0.5,
                "bbox_area_ratio": 0.18,
            },
            {
                "yaw_proxy": -0.18,
                "roll_proxy": 0.01,
                "bbox_center_x_ratio": 0.82,
                "bbox_center_y_ratio": 0.5,
                "bbox_area_ratio": 0.18,
            },
            "turn_left",
        )

        self.assertFalse(result["liveness_passed"])
        self.assertEqual(result["liveness_reason"], "framing_shift_too_large")

    def test_liveness_accepts_consistent_head_turn(self):
        result = self.module.evaluate_liveness(
            {
                "yaw_proxy": 0.0,
                "roll_proxy": 0.0,
                "bbox_center_x_ratio": 0.5,
                "bbox_center_y_ratio": 0.5,
                "bbox_area_ratio": 0.18,
            },
            {
                "yaw_proxy": -0.16,
                "roll_proxy": -0.02,
                "bbox_center_x_ratio": 0.53,
                "bbox_center_y_ratio": 0.5,
                "bbox_area_ratio": 0.2,
            },
            "turn_left",
        )

        self.assertTrue(result["liveness_passed"])
        self.assertEqual(result["liveness_reason"], "active_liveness_passed")


if __name__ == "__main__":
    unittest.main()
