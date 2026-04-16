import json
import os
import tempfile
import unittest
from pathlib import Path

from src.config import reload_config
from src.eval.feedback_dataset import build_feedback_training_sessions, load_feedback_records
from src.intelligence.knowledge_engine import KnowledgeEngine
from src.ml.retrain import retrain_from_feedback


def _snapshot(idx: int, label: str, priority: float, confidence: float, approved: bool) -> dict:
    return {
        "session_id": f"sess-{idx}",
        "protocols": ["DIAMETER", "GTP"] if label != "NORMAL_CALL" else ["GTP"],
        "technologies": ["IMS", "LTE/4G", "Transport"],
        "duration_ms": 2400 + idx * 100,
        "rca_label": label,
        "confidence_pct": confidence,
        "raw_confidence_pct": confidence,
        "priority_score": priority,
        "priority_band": "high" if priority >= 60 else "low",
        "priority_reason": "feedback training",
        "pattern_match": {"root_cause": label, "similarity": 0.95 if approved else 0.81, "historical_success": 0.9},
        "anomaly": {
            "score": 0.74 if label != "NORMAL_CALL" else 0.12,
            "is_anomalous": label != "NORMAL_CALL",
            "suggested_root_cause": label,
            "dominant_signal": "charging" if label == "CHARGING_FAILURE" else "transport",
            "component_scores": {"charging": 0.8, "transport": 0.4, "signaling": 0.3, "mobility": 0.2},
        },
        "confidence_model": {"confidence_score": confidence / 100.0, "uncertainty": max(0.0, 1.0 - (confidence / 100.0)), "consensus": 0.82},
        "features": {
            "duration_ms": 2400 + idx * 100,
            "time_to_failure_ms": 18000 if label != "NORMAL_CALL" else 0,
            "dia_failure_count": 2 if label == "CHARGING_FAILURE" else 0,
            "charging_failed": 1 if label == "CHARGING_FAILURE" else 0,
            "auth_failed_dia": 0,
            "cross_protocol_hops": 3 if label != "NORMAL_CALL" else 1,
            "timer_anomaly_count": 2 if label != "NORMAL_CALL" else 0,
            "has_retransmission": 1 if label != "NORMAL_CALL" else 0,
            "sip_4xx": 0,
            "sip_5xx": 0,
            "q850_network_fail": 0,
            "protocol_count": 2 if label != "NORMAL_CALL" else 1,
            "technology_count": 3,
        },
        "trace_intelligence": {
            "sequence_length": 9,
            "timer_anomaly_count": 2 if label != "NORMAL_CALL" else 0,
            "cross_protocol_hops": 3 if label != "NORMAL_CALL" else 1,
            "failure_signature": f"{label}|sig",
        },
    }


class FeedbackRetrainingTests(unittest.TestCase):
    def setUp(self):
        self.old_paths = {
            "TC_RCA__MODEL__RANKING_PATH": os.environ.get("TC_RCA__MODEL__RANKING_PATH"),
            "TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH": os.environ.get("TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH"),
            "TC_RCA__LEARNING__FEEDBACK_PROMOTION_ENABLED": os.environ.get("TC_RCA__LEARNING__FEEDBACK_PROMOTION_ENABLED"),
        }

    def tearDown(self):
        for key, value in self.old_paths.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reload_config()

    def test_resolve_validation_writes_feedback_dataset(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            knowledge = KnowledgeEngine(base_dir=tmpdir)
            knowledge.queue_validation(
                {
                    "session_id": "sess-1",
                    "rule_root_cause": "CHARGING_FAILURE",
                    "hybrid_root_cause": "CHARGING_FAILURE",
                    "knowledge_root_cause": "UNKNOWN",
                    "session_snapshot": _snapshot(1, "CHARGING_FAILURE", 88.0, 91.0, True),
                }
            )
            validation_id = knowledge.validation_queue[0]["validation_id"]
            result = knowledge.resolve_validation(validation_id, "approve", reviewer="tester")
            self.assertEqual(result["validation_status"], "approved")

            dataset = Path(tmpdir) / "feedback_dataset.jsonl"
            self.assertTrue(dataset.exists())
            records = load_feedback_records(dataset)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["review_action"], "approve")
            self.assertEqual(records[0]["resolved_root_cause"], "CHARGING_FAILURE")

    def test_retrain_from_feedback_trains_models(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["TC_RCA__MODEL__RANKING_PATH"] = os.path.join(tmpdir, "ranking.pkl")
            os.environ["TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH"] = os.path.join(tmpdir, "confidence.pkl")
            os.environ["TC_RCA__LEARNING__FEEDBACK_PROMOTION_ENABLED"] = "false"
            reload_config()

            knowledge = KnowledgeEngine(base_dir=tmpdir)
            payloads = [
                ("approve", _snapshot(1, "CHARGING_FAILURE", 92.0, 94.0, True)),
                ("reject", _snapshot(2, "UNKNOWN", 87.0, 38.0, False)),
                ("approve", _snapshot(3, "NORMAL_CALL", 24.0, 82.0, True)),
            ]
            for idx, (action, snapshot) in enumerate(payloads, start=1):
                knowledge.queue_validation(
                    {
                        "session_id": f"sess-{idx}",
                        "rule_root_cause": snapshot["rca_label"],
                        "hybrid_root_cause": snapshot["rca_label"],
                        "knowledge_root_cause": "UNKNOWN",
                        "session_snapshot": snapshot,
                    }
                )
                validation_id = knowledge.validation_queue[-1]["validation_id"]
                knowledge.resolve_validation(validation_id, action, reviewer="tester")

            result = retrain_from_feedback(dataset_path=str(Path(tmpdir) / "feedback_dataset.jsonl"), min_samples=3)
            self.assertTrue(result["retrained"])
            self.assertTrue(result["ranking"]["trained"])
            self.assertTrue(result["calibration"]["trained"])
            self.assertIsNone(result["promotion"])
            sessions = build_feedback_training_sessions(Path(tmpdir) / "feedback_dataset.jsonl")
            self.assertEqual(len(sessions), 3)


if __name__ == "__main__":
    unittest.main()
