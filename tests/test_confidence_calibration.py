import os
import tempfile
import unittest

from src.config import reload_config
from src.ml.calibration import (
    apply_confidence_calibration,
    clear_calibrator_cache,
    load_calibrator,
    train_confidence_calibrator,
)


class ConfidenceCalibrationTests(unittest.TestCase):
    def setUp(self):
        self._old_env = os.environ.get("TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH")

    def tearDown(self):
        clear_calibrator_cache()
        if self._old_env is None:
            os.environ.pop("TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH", None)
        else:
            os.environ["TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH"] = self._old_env
        reload_config()

    def test_training_persists_calibrator(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH"] = os.path.join(tmpdir, "confidence.pkl")
            reload_config()
            sessions = [
                {"hybrid_rca": {"confidence_pct": 92}, "confidence_label": 1},
                {"hybrid_rca": {"confidence_pct": 85}, "confidence_label": 1},
                {"hybrid_rca": {"confidence_pct": 35}, "confidence_label": 0},
                {"hybrid_rca": {"confidence_pct": 28}, "confidence_label": 0},
            ]
            result = train_confidence_calibrator(sessions)
            self.assertTrue(result["trained"])
            payload = load_calibrator()
            self.assertIsNotNone(payload)
            self.assertEqual(payload["model_type"], "isotonic")

    def test_apply_confidence_calibration_preserves_raw_and_sets_band(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH"] = os.path.join(tmpdir, "confidence.pkl")
            reload_config()
            train_confidence_calibrator(
                [
                    {"hybrid_rca": {"confidence_pct": 91}, "confidence_label": 1},
                    {"hybrid_rca": {"confidence_pct": 82}, "confidence_label": 1},
                    {"hybrid_rca": {"confidence_pct": 42}, "confidence_label": 0},
                    {"hybrid_rca": {"confidence_pct": 22}, "confidence_label": 0},
                ]
            )
            hybrid = {
                "rca_label": "SUBSCRIBER_BARRED",
                "confidence_pct": 88,
                "confidence_model": {"confidence_score": 0.88, "confidence_pct": 88, "uncertainty": 0.12},
            }
            calibrated = apply_confidence_calibration(hybrid, use_model=True)
            self.assertEqual(calibrated["raw_confidence_pct"], 88.0)
            self.assertIn(calibrated["confidence_band"], {"high", "medium", "guarded", "low"})
            self.assertEqual(calibrated["confidence_model"]["raw_confidence_pct"], 88)
            self.assertEqual(calibrated["confidence_model"]["calibration_source"], "isotonic")


if __name__ == "__main__":
    unittest.main()
