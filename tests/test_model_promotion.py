import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.config import reload_config
from src.ml.promotion import (
    candidate_artifact_paths,
    compare_candidate_to_current,
    promote_candidate_artifacts,
)
from src.ml.retrain import retrain_from_feedback


class ModelPromotionTests(unittest.TestCase):
    def setUp(self):
        self.old_env = {
            "TC_RCA__LEARNING__FEEDBACK_CANDIDATE_DIR": os.environ.get("TC_RCA__LEARNING__FEEDBACK_CANDIDATE_DIR"),
            "TC_RCA__LEARNING__FEEDBACK_PROMOTION_ENABLED": os.environ.get("TC_RCA__LEARNING__FEEDBACK_PROMOTION_ENABLED"),
            "TC_RCA__MODEL__RANKING_PATH": os.environ.get("TC_RCA__MODEL__RANKING_PATH"),
            "TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH": os.environ.get("TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH"),
        }

    def tearDown(self):
        for key, value in self.old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reload_config()

    def test_compare_candidate_to_current_accepts_non_regressing_candidate(self):
        passed, reasons = compare_candidate_to_current(
            {
                "pass_rate": 1.0,
                "failed_cases": 0,
                "avg_abnormal_priority_score": 82.0,
            },
            {
                "pass_rate": 1.0,
                "failed_cases": 0,
                "avg_abnormal_priority_score": 83.5,
            },
        )
        self.assertTrue(passed)
        self.assertEqual(reasons, [])

    def test_compare_candidate_to_current_rejects_priority_drop(self):
        passed, reasons = compare_candidate_to_current(
            {
                "pass_rate": 1.0,
                "failed_cases": 0,
                "avg_abnormal_priority_score": 82.0,
            },
            {
                "pass_rate": 1.0,
                "failed_cases": 0,
                "avg_abnormal_priority_score": 70.0,
            },
        )
        self.assertFalse(passed)
        self.assertTrue(any("avg_abnormal_priority_score" in reason for reason in reasons))

    def test_promote_candidate_artifacts_copies_into_live_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            ranking_live = tmp / "live-ranking.pkl"
            calibration_live = tmp / "live-calibration.pkl"
            ranking_candidate = tmp / "cand-ranking.pkl"
            calibration_candidate = tmp / "cand-calibration.pkl"
            ranking_candidate.write_text("ranking", encoding="utf-8")
            calibration_candidate.write_text("calibration", encoding="utf-8")
            os.environ["TC_RCA__MODEL__RANKING_PATH"] = str(ranking_live)
            os.environ["TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH"] = str(calibration_live)
            reload_config()

            promoted = promote_candidate_artifacts(
                ranking_candidate_path=ranking_candidate,
                calibration_candidate_path=calibration_candidate,
            )
            self.assertEqual(ranking_live.read_text(encoding="utf-8"), "ranking")
            self.assertEqual(calibration_live.read_text(encoding="utf-8"), "calibration")
            self.assertIn("ranking", promoted)
            self.assertIn("calibration", promoted)

    def test_retrain_from_feedback_promotes_when_candidate_clears_gate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            dataset = tmp / "feedback_dataset.jsonl"
            dataset.write_text(
                "\n".join(
                    [
                        '{"session_snapshot":{"protocols":["GTP"],"technologies":["LTE/4G"],"duration_ms":1000,"rca_label":"NORMAL_CALL","confidence_pct":84,"raw_confidence_pct":84,"priority_score":22,"priority_band":"low","priority_reason":"baseline","pattern_match":{"similarity":0.95},"anomaly":{"score":0.1},"confidence_model":{"confidence_score":0.84},"features":{"cross_protocol_hops":1,"timer_anomaly_count":0,"dia_failure_count":0,"has_retransmission":0},"trace_intelligence":{"cross_protocol_hops":1}},"review_action":"approve","resolved_root_cause":"NORMAL_CALL","confidence_label":true,"priority_label":22}',
                        '{"session_snapshot":{"protocols":["DIAMETER","GTP"],"technologies":["IMS","LTE/4G"],"duration_ms":2100,"rca_label":"CHARGING_FAILURE","confidence_pct":93,"raw_confidence_pct":93,"priority_score":90,"priority_band":"critical","priority_reason":"charging","pattern_match":{"similarity":0.96},"anomaly":{"score":0.81},"confidence_model":{"confidence_score":0.93},"features":{"cross_protocol_hops":3,"timer_anomaly_count":2,"dia_failure_count":2,"has_retransmission":1},"trace_intelligence":{"cross_protocol_hops":3}},"review_action":"approve","resolved_root_cause":"CHARGING_FAILURE","confidence_label":true,"priority_label":90}',
                        '{"session_snapshot":{"protocols":["S1AP","NAS_EPS"],"technologies":["LTE/4G"],"duration_ms":1900,"rca_label":"UNKNOWN","confidence_pct":38,"raw_confidence_pct":38,"priority_score":86,"priority_band":"high","priority_reason":"review","pattern_match":{"similarity":0.75},"anomaly":{"score":0.62},"confidence_model":{"confidence_score":0.38},"features":{"cross_protocol_hops":2,"timer_anomaly_count":1,"dia_failure_count":0,"has_retransmission":1},"trace_intelligence":{"cross_protocol_hops":2}},"review_action":"reject","resolved_root_cause":"UNKNOWN","confidence_label":false,"priority_label":86}'
                    ]
                ),
                encoding="utf-8",
            )

            os.environ["TC_RCA__LEARNING__FEEDBACK_CANDIDATE_DIR"] = str(tmp / "candidates")
            os.environ["TC_RCA__LEARNING__FEEDBACK_PROMOTION_ENABLED"] = "true"
            os.environ["TC_RCA__MODEL__RANKING_PATH"] = str(tmp / "live-ranking.pkl")
            os.environ["TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH"] = str(tmp / "live-calibration.pkl")
            reload_config()

            with patch("src.ml.retrain.evaluate_artifact_set") as mock_eval:
                mock_eval.side_effect = [
                    {"pass_rate": 1.0, "failed_cases": 0, "avg_abnormal_priority_score": 82.0},
                    {"pass_rate": 1.0, "failed_cases": 0, "avg_abnormal_priority_score": 84.0},
                ]
                result = retrain_from_feedback(dataset_path=str(dataset), min_samples=3)

            self.assertTrue(result["retrained"])
            self.assertTrue(result["promotion"]["promoted"])
            self.assertTrue(Path(os.environ["TC_RCA__MODEL__RANKING_PATH"]).exists())
            self.assertTrue(Path(os.environ["TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH"]).exists())


if __name__ == "__main__":
    unittest.main()
