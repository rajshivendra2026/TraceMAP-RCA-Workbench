import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.config import reload_config
from src.eval.drift import build_session_profile, evaluate_feedback_drift
from src.ml.retrain import retrain_from_feedback


def _session(label: str, protocols: list[str], technologies: list[str], duration_ms: float) -> dict:
    return {
        "protocols": protocols,
        "technologies": technologies,
        "duration_ms": duration_ms,
        "hybrid_rca": {"rca_label": label, "confidence_pct": 80},
        "priority_score": 60 if label != "NORMAL_CALL" else 20,
    }


class ModelDriftTests(unittest.TestCase):
    def setUp(self):
        self.old_env = {
            "TC_RCA__LEARNING__FEEDBACK_DRIFT_DETECTION_ENABLED": os.environ.get("TC_RCA__LEARNING__FEEDBACK_DRIFT_DETECTION_ENABLED"),
            "TC_RCA__LEARNING__FEEDBACK_PROMOTION_ENABLED": os.environ.get("TC_RCA__LEARNING__FEEDBACK_PROMOTION_ENABLED"),
        }

    def tearDown(self):
        for key, value in self.old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reload_config()

    def test_build_session_profile_tracks_distributions(self):
        profile = build_session_profile(
            [
                _session("NORMAL_CALL", ["GTP"], ["LTE/4G"], 1000),
                _session("UNKNOWN", ["S1AP", "NAS_EPS"], ["LTE/4G", "Transport"], 2200),
            ]
        )
        self.assertEqual(profile["sample_count"], 2)
        self.assertIn("NORMAL_CALL", profile["label_distribution"])
        self.assertIn("GTP", profile["protocol_distribution"])
        self.assertGreater(profile["avg_duration_ms"], 0)

    def test_evaluate_feedback_drift_passes_when_close_to_baseline(self):
        baseline = build_session_profile(
            [
                _session("NORMAL_CALL", ["GTP"], ["LTE/4G"], 1000),
                _session("CHARGING_FAILURE", ["DIAMETER", "GTP"], ["IMS", "LTE/4G"], 2000),
            ]
        )
        report = evaluate_feedback_drift(
            [
                _session("NORMAL_CALL", ["GTP"], ["LTE/4G"], 1100),
                _session("CHARGING_FAILURE", ["DIAMETER", "GTP"], ["IMS", "LTE/4G"], 2100),
            ],
            baseline_profile=baseline,
        )
        self.assertTrue(report["passed"])

    def test_evaluate_feedback_drift_fails_on_large_shift(self):
        baseline = build_session_profile(
            [
                _session("NORMAL_CALL", ["GTP"], ["LTE/4G"], 1000),
                _session("NORMAL_CALL", ["GTP"], ["LTE/4G"], 1200),
            ]
        )
        report = evaluate_feedback_drift(
            [
                _session("UNKNOWN", ["DNS", "UDP"], ["CORE"], 15000),
                _session("UNKNOWN", ["DNS", "UDP"], ["CORE"], 18000),
            ],
            baseline_profile=baseline,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(any(not check["passed"] for check in report["checks"]))

    def test_retrain_from_feedback_blocks_when_drift_exceeds_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dataset = Path(tmpdir) / "feedback_dataset.jsonl"
            dataset.write_text(
                "\n".join(
                    [
                        '{"session_snapshot":{"protocols":["DNS","UDP"],"technologies":["CORE"],"duration_ms":15000,"rca_label":"UNKNOWN","confidence_pct":32,"raw_confidence_pct":32,"priority_score":88,"priority_band":"high","priority_reason":"review","pattern_match":{"similarity":0.7},"anomaly":{"score":0.8},"confidence_model":{"confidence_score":0.32},"features":{"cross_protocol_hops":2,"timer_anomaly_count":1,"dia_failure_count":0,"has_retransmission":1},"trace_intelligence":{"cross_protocol_hops":2}},"review_action":"reject","resolved_root_cause":"UNKNOWN","confidence_label":false,"priority_label":88}',
                        '{"session_snapshot":{"protocols":["DNS","UDP"],"technologies":["CORE"],"duration_ms":17000,"rca_label":"UNKNOWN","confidence_pct":28,"raw_confidence_pct":28,"priority_score":92,"priority_band":"critical","priority_reason":"review","pattern_match":{"similarity":0.72},"anomaly":{"score":0.85},"confidence_model":{"confidence_score":0.28},"features":{"cross_protocol_hops":2,"timer_anomaly_count":1,"dia_failure_count":0,"has_retransmission":1},"trace_intelligence":{"cross_protocol_hops":2}},"review_action":"reject","resolved_root_cause":"UNKNOWN","confidence_label":false,"priority_label":92}',
                        '{"session_snapshot":{"protocols":["DNS","UDP"],"technologies":["CORE"],"duration_ms":16000,"rca_label":"UNKNOWN","confidence_pct":30,"raw_confidence_pct":30,"priority_score":90,"priority_band":"critical","priority_reason":"review","pattern_match":{"similarity":0.71},"anomaly":{"score":0.83},"confidence_model":{"confidence_score":0.30},"features":{"cross_protocol_hops":2,"timer_anomaly_count":1,"dia_failure_count":0,"has_retransmission":1},"trace_intelligence":{"cross_protocol_hops":2}},"review_action":"reject","resolved_root_cause":"UNKNOWN","confidence_label":false,"priority_label":90}'
                    ]
                ),
                encoding="utf-8",
            )

            os.environ["TC_RCA__LEARNING__FEEDBACK_DRIFT_DETECTION_ENABLED"] = "true"
            os.environ["TC_RCA__LEARNING__FEEDBACK_PROMOTION_ENABLED"] = "false"
            reload_config()

            baseline = build_session_profile(
                [
                    _session("NORMAL_CALL", ["GTP"], ["LTE/4G"], 1000),
                    _session("CHARGING_FAILURE", ["DIAMETER", "GTP"], ["IMS", "LTE/4G"], 1800),
                    _session("NORMAL_CALL", ["S1AP", "NAS_EPS"], ["LTE/4G", "Transport"], 2400),
                ]
            )

            with patch("src.ml.retrain.evaluate_feedback_drift") as mock_drift:
                mock_drift.return_value = {
                    "passed": False,
                    "checks": [{"name": "label_drift_within_limit", "passed": False, "detail": "label_drift=1.0"}],
                    "baseline": baseline,
                    "candidate": build_session_profile([]),
                    "label_drift": 1.0,
                    "protocol_drift": 1.0,
                    "technology_drift": 1.0,
                    "avg_duration_ratio_delta": 10.0,
                }
                result = retrain_from_feedback(dataset_path=str(dataset), min_samples=3)

            self.assertFalse(result["retrained"])
            self.assertEqual(result["reason"], "feedback_drift_exceeds_limit")
            self.assertIn("drift", result)


if __name__ == "__main__":
    unittest.main()
