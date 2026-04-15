import os
import tempfile
import unittest

from src.config import reload_config
from src.ml.ranking import clear_ranker_cache, load_ranker, score_session_priority
from src.ml.train_ranking import train_ranking_model


def _session(label: str, *, confidence: int, anomaly: float, retransmission: int = 0, dia_failures: int = 0):
    return {
        "session_id": f"s-{label}-{confidence}",
        "protocols": ["DIAMETER", "GTP"] if label != "NORMAL_CALL" else ["GTP"],
        "technologies": ["LTE/4G", "Transport"],
        "duration_ms": 4800,
        "flow": [{"protocol": "GTP", "message": "Create Session Request"} for _ in range(3)],
        "features": {
            "cross_protocol_hops": 3 if label != "NORMAL_CALL" else 1,
            "timer_anomaly_count": 2 if label != "NORMAL_CALL" else 0,
            "dia_failure_count": dia_failures,
            "has_retransmission": retransmission,
        },
        "hybrid_rca": {
            "rca_label": label,
            "confidence_pct": confidence,
            "severity": "HIGH" if label != "NORMAL_CALL" else "LOW",
            "anomaly": {"score": anomaly},
            "confidence_model": {"confidence_score": confidence / 100.0, "uncertainty": max(0.0, 1.0 - (confidence / 100.0))},
        },
    }


class RankingModelTests(unittest.TestCase):
    def setUp(self):
        self._old_env = os.environ.get("TC_RCA__MODEL__RANKING_PATH")

    def tearDown(self):
        clear_ranker_cache()
        if self._old_env is None:
            os.environ.pop("TC_RCA__MODEL__RANKING_PATH", None)
        else:
            os.environ["TC_RCA__MODEL__RANKING_PATH"] = self._old_env
        reload_config()

    def test_training_persists_ranker_with_sklearn_fallback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["TC_RCA__MODEL__RANKING_PATH"] = os.path.join(tmpdir, "ranking.pkl")
            reload_config()
            sessions = [
                {**_session("SUBSCRIBER_BARRED", confidence=92, anomaly=0.71, dia_failures=1), "priority_label": 92.0},
                {**_session("UNKNOWN", confidence=41, anomaly=0.83, retransmission=1), "priority_label": 88.0},
                {**_session("NORMAL_CALL", confidence=82, anomaly=0.09), "priority_label": 21.0},
            ]
            result = train_ranking_model(sessions)
            self.assertTrue(result["trained"])
            self.assertIn(result["model_type"], {"lightgbm", "hist_gradient_boosting"})
            payload = load_ranker()
            self.assertIsNotNone(payload)
            self.assertIn("model", payload)

    def test_score_session_priority_uses_learned_model_when_available(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["TC_RCA__MODEL__RANKING_PATH"] = os.path.join(tmpdir, "ranking.pkl")
            reload_config()
            train_ranking_model(
                [
                    {**_session("SUBSCRIBER_BARRED", confidence=94, anomaly=0.76, dia_failures=2), "priority_label": 95.0},
                    {**_session("NETWORK_CONGESTION", confidence=86, anomaly=0.62, retransmission=1), "priority_label": 84.0},
                    {**_session("NORMAL_CALL", confidence=88, anomaly=0.04), "priority_label": 18.0},
                ]
            )
            scored = score_session_priority(
                _session("SUBSCRIBER_BARRED", confidence=90, anomaly=0.69, dia_failures=1),
                use_model=True,
            )
            self.assertIn(scored["priority_model_source"], {"lightgbm", "hist_gradient_boosting"})
            self.assertGreaterEqual(scored["priority_score"], 60.0)
            self.assertIn("learned triage support", scored["priority_reason"])


if __name__ == "__main__":
    unittest.main()
